//! SPAKE2 key agreement.
//!
//! Port of `spake2/spake2.go` from the Go reference
//! (commit `8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`).
//!
//! Go uses `crypto/elliptic` (big.Int, not fully constant-time scalar
//! multiplication); this port uses `p256` with the `arithmetic` feature,
//! which is designed for constant-time secret-dependent operations (an
//! improvement over Go's variable-time big.Int path).
//!
//! `p256`'s `FieldElement::sqrt` computes `beta^((p+1)/4) mod p` via the
//! addition chain `(((2^32-1)*2^32+1)*2^96+1)*2^94` - verified to be exactly
//! the same root (same sign) as Go's `big.Int.Exp(rhs, (p+1)/4, p)`, which
//! `ComputeWeierstrassY` relies on for byte parity.

use std::sync::OnceLock;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    AffinePoint, EncodedPoint, FieldElement, NistP256, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        FieldBytes,
        bigint::Encoding,
        ff::{Field, PrimeField},
        group::Group,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};

/// 32-byte big-endian representation shared by P-256 field elements and
/// scalars. Named via the `elliptic_curve` type alias rather than
/// `generic_array::GenericArray` directly: the latter is deprecated in the
/// pinned dependency tree (feature `ga_is_deprecated`) and would trip
/// `-D warnings`.
type Bytes32 = FieldBytes<NistP256>;

/// Centralized byte conversions for the `generic-array`-backed P-256 types.
/// The pinned RustCrypto 0.13 tree marks `generic_array` items deprecated
/// (cargo feature `ga_is_deprecated`), so every deprecated call site lives
/// in this module and carries the single scoped `allow`.
pub(crate) mod bytes32 {
    use super::*;

    /// Field element from a 32-byte big-endian value (panics if >= p).
    #[allow(deprecated)]
    pub(crate) fn to_fe(b: &[u8]) -> FieldElement {
        FieldElement::from_repr_vartime(Bytes32::clone_from_slice(b))
            .expect("field element in range")
    }

    /// Scalar from a 32-byte big-endian value (panics if >= N).
    #[allow(deprecated)]
    pub(crate) fn to_scalar(b: &[u8]) -> Scalar {
        Scalar::from_repr_vartime(Bytes32::clone_from_slice(b)).expect("scalar in range")
    }

    /// 32-byte big-endian bytes of a field element.
    #[allow(deprecated)]
    pub(crate) fn fe_to_bytes(f: &FieldElement) -> [u8; 32] {
        f.to_repr().into()
    }
}
use primeorder::PrimeCurveParams;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::Error;

/// P-256 prime `p` (Go: `curve.Params().P`).
pub(crate) const MOD_P: U256 =
    U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

/// P-256 group order `N` (Go: `curve.Params().N`).
pub(crate) const ORDER_N: U256 =
    U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/// P-256 Weierstrass `B` coefficient, taken from `p256`'s own curve params
/// (so it cannot drift from the crate's validated constant).
const COEFF_B: FieldElement = <NistP256 as PrimeCurveParams>::EQUATION_B;

/// Hash-to-curve seed for the client-side generator `M`.
const M_SEED: &[u8] = b"qvole-spake2-M-v1";
/// Hash-to-curve seed for the server-side generator `N`.
const N_SEED: &[u8] = b"qvole-spake2-N-v1";

/// Default PBKDF2-SHA256 iterations (Go: `kdfIterations`).
const DEFAULT_KDF_ITERATIONS: u32 = 600_000;
/// Minimum accepted iterations (Go: `minKdfIterations`).
const MIN_KDF_ITERATIONS: u32 = 100_000;

/// HKDF info string for session key derivation.
const SESSION_INFO: &[u8] = b"qvole-spake2-session";
/// Domain separation prefix for the password-to-scalar KDF.
const PW_PREFIX: &[u8] = b"qvole-spake2-pw:";
/// Domain separation suffix for the confirm HMAC.
const CONFIRM_INFO: &[u8] = b"qvole-spake2-confirm";

/// PBKDF2 iteration count.
///
/// Go reads `QVOLE_KDF_ITERATIONS` once in `init()`; this mirrors that with a
/// once-lock. Invalid values and values below `MIN_KDF_ITERATIONS` fall back
/// to the default silently, exactly like Go. (Values above `u32::MAX` are
/// impossible in Go's 64-bit `Atoi` world in practice; the cast saturates.)
fn kdf_iterations() -> u32 {
    static ITERATIONS: OnceLock<u32> = OnceLock::new();
    *ITERATIONS.get_or_init(|| {
        if let Ok(v) = std::env::var("QVOLE_KDF_ITERATIONS")
            && let Ok(n) = v.parse::<i64>()
            && n >= MIN_KDF_ITERATIONS as i64
        {
            return n as u32;
        }
        DEFAULT_KDF_ITERATIONS
    })
}

/// Maps a byte seed to a point on P-256 using hash-and-increment.
///
/// Port of `HashToCurve`: `SHA256(SHA256(seed) || BE64(counter))` candidate,
/// `x = candidate mod p`, retry on `x == 0` or no square root.
pub fn hash_to_curve(seed: &[u8]) -> AffinePoint {
    let h = Sha256::digest(seed);
    let mut counter: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(h);
        hasher.update(counter.to_be_bytes());
        let candidate = hasher.finalize();

        let x = reduce_mod_p(&candidate);
        if x.is_zero_vartime() {
            counter += 1;
            continue;
        }

        if let Some(y) = compute_weierstrass_y(&x) {
            return point_from_xy(&x, &y);
        }
        counter += 1;
    }
}

/// Computes the y-coordinate for P-256 given x, using
/// `y = sqrt(x^3 - 3x + B)`. Returns `None` if the point is not on the curve.
///
/// Port of `ComputeWeierstrassY`. The square root is `rhs^((p+1)/4) mod p`
/// (same exponent, same root, as Go).
pub fn compute_weierstrass_y(x: &FieldElement) -> Option<FieldElement> {
    let x3 = x * x * x;
    let three_x = FieldElement::from_u64(3) * x;
    let rhs = x3 - three_x + COEFF_B;

    if rhs.is_zero_vartime() {
        return Some(FieldElement::ZERO);
    }

    // `sqrt` returns Some iff y^2 == rhs (verified inside), matching Go's
    // explicit `y2.Cmp(rhs) == 0` check.
    rhs.sqrt().into()
}

/// The M generator: `HashToCurve("qvole-spake2-M-v1")` (Go package `init`).
fn m_generator() -> &'static AffinePoint {
    static M: OnceLock<AffinePoint> = OnceLock::new();
    M.get_or_init(|| hash_to_curve(M_SEED))
}

/// The N generator: `HashToCurve("qvole-spake2-N-v1")` (Go package `init`).
fn n_generator() -> &'static AffinePoint {
    static N: OnceLock<AffinePoint> = OnceLock::new();
    N.get_or_init(|| hash_to_curve(N_SEED))
}

/// Maps a password to a scalar in [1, N-1] via PBKDF2-HMAC-SHA256 with domain
/// separation and tunable iterations. Never returns zero. If the initial
/// derivation maps to zero, it retries with a counter appended to the input
/// (deterministic, both peers iterate identically).
///
/// Port of `PasswordToScalar`.
pub fn password_to_scalar(password: &str) -> Scalar {
    let mut pw_bytes = PW_PREFIX.to_vec();
    pw_bytes.extend_from_slice(password.as_bytes());
    let salt = PW_PREFIX;
    let mut counter: u64 = 0;
    loop {
        let mut input = if counter == 0 {
            pw_bytes.clone()
        } else {
            let mut v = pw_bytes.clone();
            v.extend_from_slice(&counter.to_be_bytes());
            v
        };
        let mut h = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&input, salt, kdf_iterations(), &mut h);
        input.zeroize();
        let s = reduce_mod_n(&h);
        h.zeroize();
        if !s.is_zero_vartime() {
            pw_bytes.zeroize();
            return s;
        }
        counter += 1;
    }
}

/// `g * scalar` for an affine generator point. Port of `generatorScalar`.
///
/// Go serializes the scalar to fixed-length 32 bytes first because
/// `crypto/elliptic`'s scalar multiplication is not constant-time; `p256`
/// multiplies constant-time directly from the scalar type, so the round trip
/// is omitted.
fn generator_scalar(g: &AffinePoint, scalar: &Scalar) -> AffinePoint {
    (ProjectivePoint::from(*g) * *scalar).to_affine()
}

/// Ephemeral key material for one side of a SPAKE2 PAKE exchange.
///
/// Port of `State`. Two independent ephemeral scalars (`scalar_m`, `scalar_n`)
/// are used so that subtracting the two blinded points does NOT cancel the
/// ephemeral contribution. If a single scalar were reused for both blinded
/// points, an observer could compute `blindedM - blindedN = pw*(M-N)` and
/// verify candidate passwords offline, defeating the core PAKE property.
#[derive(Debug)]
pub struct State {
    pub(crate) pw_scalar: Scalar,
    pub(crate) scalar_m: Scalar,
    pub(crate) scalar_n: Scalar,
    pub(crate) blinded_m: (FieldElement, FieldElement),
    pub(crate) blinded_n: (FieldElement, FieldElement),
}

/// Creates a new SPAKE2 state, generating two independent ephemeral scalars
/// and computing M-based and N-based blinded points (`rM*G + w*M` and
/// `rN*G + w*N`). The caller determines the protocol role after seeing the
/// peer's points and uses the appropriate point via [`State::compute_shared`].
///
/// Port of `NewState`.
pub fn new_state(password: &str) -> Result<State, Error> {
    let mut priv_m = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut priv_m);
    let mut priv_n = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut priv_n);

    let scalar_m = reduce_mod_n(&priv_m);
    let scalar_n = reduce_mod_n(&priv_n);

    let state = state_from_scalars(password, &scalar_m, &scalar_n);
    priv_m.zeroize();
    priv_n.zeroize();
    Ok(state)
}

/// Core state construction from reduced ephemeral scalars.
fn state_from_scalars(password: &str, scalar_m: &Scalar, scalar_n: &Scalar) -> State {
    let pw_scalar = password_to_scalar(password);

    let pub_m = generator_scalar(base_generator(), scalar_m);
    let pub_n = generator_scalar(base_generator(), scalar_n);

    let bm = generator_scalar(m_generator(), &pw_scalar);
    let (blinded_mx, blinded_my) = add_affine(&pub_m, &bm);

    let bn = generator_scalar(n_generator(), &pw_scalar);
    let (blinded_nx, blinded_ny) = add_affine(&pub_n, &bn);

    State {
        pw_scalar,
        scalar_m: *scalar_m,
        scalar_n: *scalar_n,
        blinded_m: (blinded_mx, blinded_my),
        blinded_n: (blinded_nx, blinded_ny),
    }
}

/// State constructor with fixed (raw, un-reduced) ephemeral scalars, for
/// golden-vector tests. Not part of the production API (Go has no equivalent;
/// the Go vector generator reads the ephemeral scalars back out of the state
/// instead).
#[cfg(any(test, feature = "test-util"))]
pub fn new_state_with_scalars(
    password: &str,
    r_m: &[u8; 32],
    r_n: &[u8; 32],
) -> Result<State, Error> {
    let scalar_m = reduce_mod_n(r_m);
    let scalar_n = reduce_mod_n(r_n);
    Ok(state_from_scalars(password, &scalar_m, &scalar_n))
}

/// P-256 base point `G` (Go: `curve.ScalarBaseMult` over the standard
/// generator). Uncompressed SEC1 encoding of the standard P-256 base point.
fn base_generator() -> &'static AffinePoint {
    static G: OnceLock<AffinePoint> = OnceLock::new();
    G.get_or_init(|| {
        let bytes: [u8; 65] = [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let enc = EncodedPoint::from_bytes(bytes).expect("valid base point encoding");
        AffinePoint::from_encoded_point(&enc)
            .into_option()
            .expect("base point is on curve")
    })
}

/// Adds two affine points. Port of `curve.Add`.
fn add_affine(a: &AffinePoint, b: &AffinePoint) -> (FieldElement, FieldElement) {
    let sum = ProjectivePoint::from(*a) + ProjectivePoint::from(*b);
    let (x, y) = affine_xy(&sum.to_affine());
    (x, y)
}

/// Extracts the coordinates of an affine point via its SEC1 encoding
/// (avoids private fields of `p256::AffinePoint`).
fn affine_xy(p: &AffinePoint) -> (FieldElement, FieldElement) {
    let enc = p.to_encoded_point(false);
    let bytes = enc.as_bytes();
    let x = bytes32::to_fe(&bytes[1..33]);
    let y = bytes32::to_fe(&bytes[33..65]);
    (x, y)
}

impl State {
    /// Marshalled M-based blinded public point (65-byte uncompressed SEC1).
    /// Port of `BlindedBytesM`.
    pub fn blinded_bytes_m(&self) -> Vec<u8> {
        marshal_point(&self.blinded_m)
    }

    /// Marshalled N-based blinded public point (65-byte uncompressed SEC1).
    /// Port of `BlindedBytesN`.
    pub fn blinded_bytes_n(&self) -> Vec<u8> {
        marshal_point(&self.blinded_n)
    }

    /// Attempts to zero sensitive fields (Go `Destroy`).
    pub fn destroy(&mut self) {
        self.pw_scalar.zeroize();
        self.scalar_m.zeroize();
        self.scalar_n.zeroize();
        let (zx, zy) = (FieldElement::ZERO, FieldElement::ZERO);
        self.blinded_m = (zx, zy);
        self.blinded_n = (zx, zy);
    }

    /// Completes the SPAKE2 exchange using the correct generator.
    /// `peer_used_m` indicates whether the peer blinded with generator `M`
    /// (true) or `N` (false). Returns a 32-byte shared secret from the
    /// x-coordinate.
    ///
    /// Port of `ComputeShared`.
    pub fn compute_shared(
        &self,
        peer_blinded_bytes: &[u8],
        peer_used_m: bool,
    ) -> Result<[u8; 32], Error> {
        let peer = parse_peer_point(peer_blinded_bytes)?;

        let generator = if peer_used_m {
            m_generator()
        } else {
            n_generator()
        };
        let pw_point = generator_scalar(generator, &self.pw_scalar);
        let (pwx, pwy) = affine_xy(&pw_point);

        // Go: `pwyNeg = p - pwy` (field negation; identical when pwy == 0).
        let pwy_neg = -pwy;
        let unblinded =
            ProjectivePoint::from(peer) + ProjectivePoint::from(point_from_xy(&pwx, &pwy_neg));

        if unblinded.is_identity().into() {
            return Err(Error::UnblindedIdentity);
        }

        // If the peer blinded with M, I am the server using my N path
        // (scalar_n). If the peer blinded with N, I am the client using my M
        // path (scalar_m).
        let my_scalar = if !peer_used_m {
            self.scalar_m
        } else {
            self.scalar_n
        };
        let shared = (unblinded * my_scalar).to_affine();

        let enc = shared.to_encoded_point(false);
        let bytes = enc.as_bytes();
        let shared_x = bytes32::to_fe(&bytes[1..33]);
        if shared_x.is_zero_vartime() {
            return Err(Error::SharedXZero);
        }
        Ok(bytes32::fe_to_bytes(&shared_x))
    }
}

/// Parses and validates a peer's 65-byte uncompressed point.
///
/// `from_encoded_point` rejects malformed encodings and points not on the
/// curve (it verifies the curve equation), matching Go's separate
/// `elliptic.Unmarshal` + `IsOnCurve` checks.
fn parse_peer_point(bytes: &[u8]) -> Result<AffinePoint, Error> {
    let enc = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPeerPoint)?;
    AffinePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or(Error::PeerPointOffCurve)
}

/// 65-byte uncompressed SEC1 marshalling (Go: `elliptic.Marshal`).
fn marshal_point((x, y): &(FieldElement, FieldElement)) -> Vec<u8> {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&bytes32::fe_to_bytes(x));
    out[33..65].copy_from_slice(&bytes32::fe_to_bytes(y));
    out.to_vec()
}

/// Builds an [`AffinePoint`] from raw field coordinates. The point is
/// re-validated against the curve equation by `from_encoded_point`.
pub(crate) fn point_from_xy(x: &FieldElement, y: &FieldElement) -> AffinePoint {
    let mut bytes = [0u8; 65];
    bytes[0] = 0x04;
    bytes[1..33].copy_from_slice(&bytes32::fe_to_bytes(x));
    bytes[33..65].copy_from_slice(&bytes32::fe_to_bytes(y));
    let enc = EncodedPoint::from_bytes(bytes).expect("valid uncompressed encoding");
    AffinePoint::from_encoded_point(&enc)
        .into_option()
        .expect("point is on curve by construction")
}

/// Reduces a 32-byte big-endian integer modulo the P-256 prime `p`.
/// One subtraction suffices because `2^256 < 2p`.
fn reduce_mod_p(bytes: &[u8]) -> FieldElement {
    assert_eq!(bytes.len(), 32, "reduce_mod_p requires 32 bytes");
    // `from_be_slice` panics on overflow; 32 bytes always fits U256.
    let v = U256::from_be_slice(bytes);
    let r = if v >= MOD_P {
        v.wrapping_sub(&MOD_P)
    } else {
        v
    };
    bytes32::to_fe(&r.to_be_bytes())
}

/// Reduces a 32-byte big-endian integer modulo the P-256 order `N`.
/// One subtraction suffices because `2^256 < 2N`.
fn reduce_mod_n(bytes: &[u8]) -> Scalar {
    assert_eq!(bytes.len(), 32, "reduce_mod_n requires 32 bytes");
    let v = U256::from_be_slice(bytes);
    let r = if v >= ORDER_N {
        v.wrapping_sub(&ORDER_N)
    } else {
        v
    };
    bytes32::to_scalar(&r.to_be_bytes())
}

/// The lexicographically-ordered concatenation of two public points.
/// Operates on public data; variable-time comparison is safe. Returns a fresh
/// allocation so callers' slices are not mutated.
///
/// Port of `SessionAAD`.
pub fn session_aad(my_point: &[u8], peer_point: &[u8]) -> Vec<u8> {
    let (a, b) = if my_point > peer_point {
        (peer_point, my_point)
    } else {
        (my_point, peer_point)
    };
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// AAD for session-key derivation: ordered points plus the N generator.
/// Port of `aadWithGenerators`.
fn aad_with_generators(my_point: &[u8], peer_point: &[u8]) -> Vec<u8> {
    let mut aad = session_aad(my_point, peer_point);
    aad.extend_from_slice(&marshal_point(&affine_xy(n_generator())));
    aad
}

/// Derives a 32-byte confirm HMAC key and a 32-byte AES-256-GCM encryption
/// key from the SPAKE2 shared secret using HKDF.
///
/// Port of `DeriveSessionKey`.
pub fn derive_session_key(
    shared_secret: &[u8],
    my_point: &[u8],
    peer_point: &[u8],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let aad = aad_with_generators(my_point, peer_point);
    let salt = Sha256::digest(&aad);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), shared_secret);
    let mut key = [0u8; 64]; // 32 for confirm HMAC, 32 for AES-256-GCM
    hk.expand(SESSION_INFO, &mut key)
        .map_err(|e| Error::Hkdf(e.to_string()))?;
    Ok((key[..32].try_into().unwrap(), key[32..].try_into().unwrap()))
}

fn new_gcm(key: &[u8]) -> Result<Aes256Gcm, Error> {
    Aes256Gcm::new_from_slice(key).map_err(|e| Error::Gcm(format!("new cipher: {e}")))
}

/// Encrypts data with AES-256-GCM using `key` and `aad` for authentication.
/// Output is `nonce (12) || ciphertext || tag (16)`.
///
/// Port of `EncryptMetadata` (Go `gcm.Seal` appends to the nonce buffer).
pub fn encrypt_metadata(key: &[u8], aad: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let gcm = new_gcm(key)?;
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ct = gcm
        .encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|e| Error::Gcm(format!("cipher: {e}")))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts data with AES-256-GCM. Input is `nonce (12) || ciphertext || tag`.
///
/// Port of `DecryptMetadata`.
pub fn decrypt_metadata(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let gcm = new_gcm(key)?;
    const NS: usize = 12;
    if ciphertext.len() < NS {
        return Err(Error::CiphertextTooShort);
    }
    let nonce_bytes: [u8; 12] = ciphertext[..NS].try_into().expect("12-byte nonce");
    let nonce = Nonce::from(nonce_bytes);
    gcm.decrypt(
        &nonce,
        Payload {
            msg: &ciphertext[NS..],
            aad,
        },
    )
    .map_err(|_| Error::GcmAuth)
}

/// Computes an HMAC-SHA-256 over the ordered public points, the N generator,
/// the peer's certificate fingerprint, a nonce, and a domain separation
/// string. Returns an error if the nonce is empty.
///
/// Port of `ComputeConfirm`.
pub fn compute_confirm(
    session_key: &[u8],
    my_point: &[u8],
    peer_point: &[u8],
    nonce: &[u8],
    peer_fingerprint: &[u8],
) -> Result<[u8; 32], Error> {
    if nonce.is_empty() {
        return Err(Error::EmptyNonce);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key)
        .map_err(|e| Error::Hmac(e.to_string()))?;
    let (a, b) = if my_point > peer_point {
        (peer_point, my_point) // public data; variable-time is safe
    } else {
        (my_point, peer_point)
    };
    mac.update(a);
    mac.update(b);
    let g = n_generator();
    let (gx, gy) = affine_xy(g);
    mac.update(&marshal_point(&(gx, gy))[..]);
    mac.update(peer_fingerprint);
    mac.update(nonce);
    mac.update(CONFIRM_INFO);
    Ok(mac.finalize().into_bytes().into())
}

/// Checks that `peer_confirm` matches the expected HMAC computed with
/// [`compute_confirm`], using constant-time comparison.
/// `my_fingerprint` is the local certificate fingerprint (the one the peer
/// used when computing their confirm).
///
/// Port of `VerifyConfirm`.
pub fn verify_confirm(
    session_key: &[u8],
    my_point: &[u8],
    peer_point: &[u8],
    nonce: &[u8],
    my_fingerprint: &[u8],
    peer_confirm: &[u8],
) -> bool {
    let expected = match compute_confirm(session_key, my_point, peer_point, nonce, my_fingerprint) {
        Ok(c) => c,
        Err(_) => return false,
    };
    constant_time_eq(&expected, peer_confirm)
}

/// Constant-time byte-slice comparison (Go: `subtle.ConstantTimeCompare`).
///
/// Deliberately local rather than a dependency: the comparison is over
/// 32-byte HMAC outputs, and the loop folds differences into a mask.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Zeroes every byte in `b` (Go `ZeroBytes`).
pub fn zero_bytes(b: &mut [u8]) {
    b.zeroize();
}

/// Test-only access to the M/N generator points (Go exports `Mx, My, Nx, Ny`
/// within the package).
#[cfg(any(test, feature = "test-util"))]
pub fn generator_points() -> (AffinePoint, AffinePoint) {
    (*m_generator(), *n_generator())
}

/// Affine coordinates of a point (test-only helper mirroring Go's exported
/// `Mx, My, Nx, Ny` big.Ints).
#[cfg(any(test, feature = "test-util"))]
pub fn affine_coords(p: &AffinePoint) -> (FieldElement, FieldElement) {
    affine_xy(p)
}
