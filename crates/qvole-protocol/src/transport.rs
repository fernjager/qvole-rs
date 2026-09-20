//! QUIC transport configuration (Go `internal/engine/transport.go`).
//!
//! TLS 1.3 with pinned SHA-256 certificate fingerprints (no trust anchor),
//! fixed ALPN `qvole-v0.1`, and a transport profile tuned for bulk transfer.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use webpki::EndEntityCert;

use crate::cert::{SelfSignedCert, constant_time_eq};
use crate::exchange::PeerConfig;

pub const PROTOCOL_VERSION: &str = "0.1";
/// ALPN identifier (Go: `"qvole-v" + ProtocolVersion`).
pub const ALPN: &[u8] = b"qvole-v0.1";
pub const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(5);
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_INCOMING_STREAMS: u32 = 100;
pub const DEFAULT_FORWARD_MAX_STREAMS: i64 = 200;
pub const DEFAULT_INITIAL_STREAM_WINDOW: i64 = 1024 * 1024;
pub const DEFAULT_INITIAL_CONNECTION_WINDOW: i64 = 4 * 1024 * 1024;
/// Go `cancelErrorCode`: application close code sent on local cancellation.
pub const CANCEL_ERROR_CODE: u32 = 1;
/// Go `streamCloseDelay`: pause between FIN and connection close.
pub const STREAM_CLOSE_DELAY: Duration = Duration::from_millis(500);
/// Go `helperTimeout`: how long the post-punch keep-alive helper runs.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(3);
/// Go `helperTickerInterval`.
pub const HELPER_TICKER_INTERVAL: Duration = Duration::from_millis(50);
/// Go `keepalivePayload`: tiny UDP probe sent while the NAT mapping is
/// being established.
pub const KEEPALIVE_PAYLOAD: &[u8] = &[0x01];

const ENV_INITIAL_STREAM_WINDOW: &str = "QVOLE_INITIAL_STREAM_WINDOW";
const ENV_INITIAL_CONNECTION_WINDOW: &str = "QVOLE_INITIAL_CONNECTION_WINDOW";
const ENV_FORWARD_MAX_STREAMS: &str = "QVOLE_FORWARD_MAX_STREAMS";

/// Errors building QUIC/TLS configuration (effectively unreachable in
/// practice: certificates are freshly generated and the provider is fixed).
#[derive(Debug, thiserror::Error)]
pub enum QuicConfigError {
    /// `tls config: {0}`
    #[error("tls config: {0}")]
    Tls(#[from] TlsError),
    /// `quic crypto config: {0}`
    #[error("quic crypto config: {0}")]
    QuicCrypto(String),
}

/// Port of `QUICConfigWithOverrides`.
///
/// Maps Go's `quic.Config` onto a quinn `TransportConfig`:
/// `MaxIncomingStreams` -> `max_concurrent_bidi_streams`;
/// `MaxIncomingUniStreams = -1` (forbidden) -> `max_concurrent_uni_streams(0)`;
/// `KeepAlivePeriod`/`MaxIdleTimeout`/windows map directly. Go's
/// `HandshakeIdleTimeout` has no quinn equivalent and is applied in
/// [`crate::connect`] with an explicit timeout instead.
#[must_use]
pub fn quic_transport_config(cfg: &PeerConfig) -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(cfg.max_streams()))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .keep_alive_interval(Some(cfg.keep_alive_period()))
        .max_idle_timeout(Some(IdleTimeout::from(millis_varint(cfg.idle_timeout()))))
        .stream_receive_window(byte_varint(initial_stream_window()))
        .receive_window(byte_varint(initial_connection_window()));
    Arc::new(config)
}

/// Encodes a duration in milliseconds as a QUIC varint (the unit QUIC uses
/// for idle timeouts), capped at the varint maximum like quic-go's uint64
/// cast.
fn millis_varint(d: Duration) -> VarInt {
    VarInt::from_u32(d.as_millis().min(u32::MAX as u128) as u32)
}

/// Encodes a byte count as a QUIC varint, capped at the varint maximum like
/// quic-go's uint64 cast.
fn byte_varint(b: u64) -> VarInt {
    VarInt::from_u32(b.min(u32::MAX as u64) as u32)
}

/// Go `InitialStreamReceiveWindow` (env-only, no PeerConfig override).
#[must_use]
pub fn initial_stream_window() -> u64 {
    crate::env::env_int(ENV_INITIAL_STREAM_WINDOW, DEFAULT_INITIAL_STREAM_WINDOW) as u64
}

/// Go `InitialConnectionReceiveWindow` (env-only, no PeerConfig override).
#[must_use]
pub fn initial_connection_window() -> u64 {
    crate::env::env_int(
        ENV_INITIAL_CONNECTION_WINDOW,
        DEFAULT_INITIAL_CONNECTION_WINDOW,
    ) as u64
}

/// Port of `GetForwardMaxStreams`.
///
/// `override_val` is Go's optional variadic argument: a non-zero value wins,
/// otherwise `QVOLE_FORWARD_MAX_STREAMS` or 200.
#[must_use]
pub fn get_forward_max_streams(override_val: Option<u32>) -> i64 {
    match override_val {
        Some(v) if v > 0 => v as i64,
        _ => crate::env::env_int(ENV_FORWARD_MAX_STREAMS, DEFAULT_FORWARD_MAX_STREAMS),
    }
}

/// Server certificate verifier that pins the SHA-256 fingerprint of the
/// peer's end-entity certificate (Go `VerifyPeerCertificate` with
/// `InsecureSkipVerify`).
#[derive(Debug, Clone)]
pub struct PinnedServerVerifier {
    fingerprint: [u8; 32],
}

impl PinnedServerVerifier {
    #[must_use]
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        check_fingerprint(self.fingerprint, end_entity.as_ref())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_pinned_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_pinned_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// Client certificate verifier pinning the SHA-256 fingerprint (Go
/// `RequireAnyClientCert` + `VerifyPeerCertificate`: a client certificate is
/// required, any certificate is accepted subject to the fingerprint check).
#[derive(Debug, Clone)]
pub struct PinnedClientVerifier {
    fingerprint: [u8; 32],
}

impl PinnedClientVerifier {
    #[must_use]
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    /// Empty hints: "present any certificate you have", exactly what Go's
    /// `RequireAnyClientCert` conveys.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        check_fingerprint(self.fingerprint, end_entity.as_ref())?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_pinned_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_pinned_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// Go `VerifyPeerCertificate` core: SHA-256 of the first DER certificate must
/// match the pinned fingerprint.
fn check_fingerprint(fingerprint: [u8; 32], end_entity: &[u8]) -> Result<(), TlsError> {
    let h = Sha256::digest(end_entity);
    if !constant_time_eq(&h, &fingerprint) {
        return Err(TlsError::General(
            "peer certificate fingerprint mismatch".into(),
        ));
    }
    Ok(())
}

/// Verifies an ECDSA P-256 SHA-256 signature made by the pinned certificate
/// (the only key type qvole generates; Go peers sign `ECDSA_SHA256`).
fn verify_pinned_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    if dss.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Err(TlsError::General("unsupported signature scheme".into()));
    }
    let end_entity = EndEntityCert::try_from(cert)
        .map_err(|_| TlsError::General("invalid peer certificate encoding".into()))?;
    end_entity
        .verify_signature(webpki::ring::ECDSA_P256_SHA256, message, dss.signature())
        .map_err(|e| TlsError::General(format!("peer certificate signature invalid: {e}")))?;
    Ok(HandshakeSignatureValid::assertion())
}

/// Port of `ClientTLSConfig` (Go `NoClientCert`: the client never requests a
/// certificate from the server, but presents its own when the server asks).
pub fn client_tls_config(
    cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
) -> Result<rustls::ClientConfig, TlsError> {
    let fp: [u8; 32] = peer_fingerprint
        .try_into()
        .map_err(|_| TlsError::General("bad peer fingerprint length".into()))?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(fp)))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert.der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key.clone())),
        )?;
    // Go: `NextProtos: []string{alpn}` - fixed ALPN, wire-compatible with
    // quic-go peers.
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Port of `ServerTLSConfig` (Go `RequireAnyClientCert`: a client certificate
/// is required and pinned by fingerprint).
pub fn server_tls_config(
    cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
) -> Result<rustls::ServerConfig, TlsError> {
    let fp: [u8; 32] = peer_fingerprint
        .try_into()
        .map_err(|_| TlsError::General("bad peer fingerprint length".into()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PinnedClientVerifier::new(fp)))
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key.clone())),
        )?;
    // Go: `NextProtos: []string{alpn}`.
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Build the quinn `ServerConfig` (transport + TLS) for the QUIC listener.
pub fn quic_server_config(
    cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
    cfg: &PeerConfig,
) -> Result<ServerConfig, QuicConfigError> {
    let tls = server_tls_config(cert, peer_fingerprint)?;
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|e| QuicConfigError::QuicCrypto(e.to_string()))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(quic_transport_config(cfg));
    Ok(server_config)
}

/// Build the quinn `ClientConfig` (transport + TLS) for the QUIC dial.
pub fn quic_client_config(
    cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
    cfg: &PeerConfig,
) -> Result<ClientConfig, QuicConfigError> {
    let tls = client_tls_config(cert, peer_fingerprint)?;
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|e| QuicConfigError::QuicCrypto(e.to_string()))?;
    let mut client_config = ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(quic_transport_config(cfg));
    Ok(client_config)
}

/// Port of `closeOnCancel`: closes the connection with the cancel error code
/// when the parent context is canceled.
pub fn close_on_cancel(cancel: &CancellationToken, conn: &Connection) {
    let cancel = cancel.clone();
    let conn = conn.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = cancel.cancelled() => {
                conn.close(VarInt::from_u32(CANCEL_ERROR_CODE), b"canceled");
            }
            _ = conn.closed() => {}
        }
    });
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
