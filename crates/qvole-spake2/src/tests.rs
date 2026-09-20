//! In-crate unit tests: these need access to private fields of `State` or
//! crate-private helpers, so they live inside the crate (Go equivalents are
//! package tests in `spake2/spake2_test.go` and `internal/util/code_test.go`).

use crate::code::{generate_code, is_generated_code, nameplate, rand_int};
use crate::spake2::bytes32;
use crate::spake2::{
    MOD_P, ORDER_N, affine_coords, compute_weierstrass_y, generator_points, new_state,
    password_to_scalar, point_from_xy, zero_bytes,
};
use crate::words::code_words;
use p256::elliptic_curve::bigint::Encoding;
use p256::elliptic_curve::ff::Field;
use p256::{AffinePoint, ProjectivePoint, Scalar, U256};

/// Port of `TestSPAKE2_Destroy_ZerosFields`.
#[test]
fn test_spake2_destroy_zeros_fields() {
    let mut s = new_state("test-password").unwrap();
    s.destroy();
    assert!(s.pw_scalar.is_zero_vartime(), "pwScalar not zeroed");
    assert!(s.scalar_m.is_zero_vartime(), "scalarM not zeroed");
    assert!(s.scalar_n.is_zero_vartime(), "scalarN not zeroed");
    assert!(
        s.blinded_m.0.is_zero_vartime() && s.blinded_m.1.is_zero_vartime(),
        "blindedXM/YM not zeroed"
    );
    assert!(
        s.blinded_n.0.is_zero_vartime() && s.blinded_n.1.is_zero_vartime(),
        "blindedXN/YN not zeroed"
    );
}

/// Port of `TestSPAKE2_IndependentScalars`.
#[test]
fn test_spake2_independent_scalars() {
    for i in 0..100 {
        let s = new_state("test-password").unwrap();
        assert_ne!(
            s.scalar_m, s.scalar_n,
            "iteration {i}: scalarM == scalarN (scalars not independent)"
        );
    }
}

/// Port of `TestSPAKE2_NoOfflineOracle` (the key regression test for the
/// independent-ephemeral-scalar fix).
#[test]
fn test_spake2_no_offline_oracle() {
    let correct_password = "correct-horse-battery-staple";
    let wrong_candidates = [
        "wrong-password-1",
        "wrong-password-2",
        "password",
        "12345678",
        "",
        "correct-horse-battery-stapl",
        "Correct-Horse-Battery-Staple",
        "correct-horse-battery-staple!",
    ];

    let state = new_state(correct_password).unwrap();

    let (mx, my) = affine_coords(&generator_points().0);
    let (nx, ny) = affine_coords(&generator_points().1);

    let bm = point_from_xy(&state.blinded_m.0, &state.blinded_m.1);
    let bn = point_from_xy(&state.blinded_n.0, &state.blinded_n.1);

    // captured delta = blindedM - blindedN
    let delta = (ProjectivePoint::from(bm) - ProjectivePoint::from(bn)).to_affine();

    // Public constant T = M - N (computed once, like an attacker would).
    let neg_ny = -ny;
    let t = (ProjectivePoint::from(point_from_xy(&mx, &my))
        - ProjectivePoint::from(point_from_xy(&nx, &neg_ny)))
    .to_affine();

    fn mult(p: &AffinePoint, s: &Scalar) -> AffinePoint {
        (ProjectivePoint::from(*p) * *s).to_affine()
    }

    for candidate in wrong_candidates {
        let pw_scalar = password_to_scalar(candidate);
        let cand = mult(&t, &pw_scalar);
        assert_ne!(
            cand, delta,
            "offline oracle matched for wrong candidate {candidate:?}: scalar reuse regression?"
        );
    }

    // With independent scalars, blindedM - blindedN = (rM - rN)*G + pw*(M-N),
    // so even the correct password does NOT match delta.
    let correct_scalar = password_to_scalar(correct_password);
    let correct = mult(&t, &correct_scalar);
    assert_ne!(
        correct, delta,
        "correct password matched delta; single-scalar regression?"
    );
}

/// Port of `TestSPAKE2_NewState_EmptyPassword` (the on-curve parts need the
/// private blinded coordinates).
#[test]
fn test_spake2_new_state_empty_password() {
    let s = new_state("").unwrap();
    let bm = s.blinded_bytes_m();
    assert_eq!(bm.len(), 65);
    assert_eq!(bm[0], 0x04);
    assert_on_curve(&s.blinded_m.0, &s.blinded_m.1);
    let bn = s.blinded_bytes_n();
    assert_eq!(bn.len(), 65);
    assert_eq!(bn[0], 0x04);
    assert_on_curve(&s.blinded_n.0, &s.blinded_n.1);
}

fn assert_on_curve(x: &p256::FieldElement, y: &p256::FieldElement) {
    // Panics if the point is not on the curve (from_encoded_point validates).
    let _ = point_from_xy(x, y);
}

/// Port of `TestSPAKE2_WeierstrassY_RhsZero`.
#[test]
fn test_spake2_compute_weierstrass_y_rhs_zero() {
    use p256::FieldElement;
    // x=0 and x=1: P-256's rhs may or may not be a square; Go only logs.
    let _ = compute_weierstrass_y(&FieldElement::from_u64(0));
    let _ = compute_weierstrass_y(&FieldElement::from_u64(1));

    // Known valid seed point: ComputeWeierstrassY reproduces HashToCurve's y.
    let (mx, my) = affine_coords(&generator_points().0);
    let y2 = compute_weierstrass_y(&mx).expect("M x has a square root");
    assert_eq!(
        y2, my,
        "ComputeWeierstrassY did not match HashToCurve y for M"
    );
}

/// Port of `TestSPAKE2_WeierstrassY_NilReturn`.
#[test]
fn test_spake2_compute_weierstrass_y_nil_return() {
    use p256::FieldElement;
    // About half of x values have no quadratic residue. Find one.
    for x_val in 2u64..10_000 {
        if compute_weierstrass_y(&FieldElement::from_u64(x_val)).is_none() {
            return;
        }
    }
    panic!("could not find x that produces nil y; test may be flaky");
}

/// Port of `TestSPAKE2_HashToCurve_RetryOnZeroX`.
#[test]
fn test_spake2_hash_to_curve_retry_on_zero_x() {
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use rand_core::RngCore;

    let mut seed = [0u8; 32];
    for _ in 0..100 {
        rand_core::OsRng.fill_bytes(&mut seed);
        let pt = crate::hash_to_curve(&seed);
        let (x, _y) = affine_coords(&pt);
        assert!(
            !x.is_zero_vartime(),
            "HashToCurve returned x=0 for seed {}; loop may have terminated early",
            hex::encode(seed)
        );
        let enc = pt.to_encoded_point(false);
        assert!(
            p256::AffinePoint::from_encoded_point(&enc)
                .into_option()
                .is_some(),
            "HashToCurve returned point not on curve for seed {}",
            hex::encode(seed)
        );
    }
}

/// Port of `TestSPAKE2_ZeroBytes` (+ `_Empty`).
#[test]
fn test_spake2_zero_bytes() {
    let mut b = [0x01, 0x02, 0x03, 0x04];
    zero_bytes(&mut b);
    assert_eq!(b, [0u8; 4]);
    zero_bytes(&mut []);
}

// ---------------------------------------------------------------------------
// internal/util/code_test.go ports
// ---------------------------------------------------------------------------

/// Port of `TestRandInt_ValidRange`.
#[test]
fn test_rand_int_valid_range() {
    for max in 1..=256usize {
        let v = rand_int(max).unwrap_or_else(|e| panic!("randInt({max}): {e}"));
        assert!(v < max, "randInt({max}) = {v}, want [0, {max})");
    }
}

/// Port of `TestRandInt_MaxBoundary`.
#[test]
fn test_rand_int_max_boundary() {
    let v = rand_int(65536).unwrap();
    assert!(v < 65536);
}

/// Port of `TestRandInt_AlwaysZero`.
#[test]
fn test_rand_int_always_zero() {
    assert_eq!(rand_int(1).unwrap(), 0);
}

/// Port of `TestRandInt_Uniformity`.
#[test]
fn test_rand_int_uniformity() {
    const N: usize = 10_000;
    const BUCKETS: usize = 10;
    let mut counts = [0usize; BUCKETS];
    for _ in 0..N {
        counts[rand_int(BUCKETS).unwrap()] += 1;
    }
    let expected = N / BUCKETS;
    for (i, &c) in counts.iter().enumerate() {
        assert!(
            c >= expected / 2 && c <= expected * 2,
            "bucket {i} got {c} samples (expected ~{expected})"
        );
    }
}

/// Port of `TestRandInt_OutOfRange`.
#[test]
fn test_rand_int_out_of_range() {
    // Go's int allows negatives; Rust's usize cannot. The Go test's negative
    // cases map to the same "out of range" contract via the public API's
    // range check.
    assert!(rand_int(0).is_err());
    assert!(rand_int(65537).is_err());
    assert!(rand_int(100_000).is_err());
}

/// Port of `TestNameplate_ExtractsPrefix`.
#[test]
fn test_nameplate_extracts_prefix() {
    assert_eq!(nameplate("9908-ability-subway-unicorn"), "9908");
}

/// Port of `TestNameplate_LeadingZeros`.
#[test]
fn test_nameplate_leading_zeros() {
    assert_eq!(nameplate("0000-ability-subway-unicorn"), "0000");
}

/// Port of `TestNameplate_FiveDigitPrefix`.
#[test]
fn test_nameplate_five_digit_prefix() {
    let np = nameplate("12345-test");
    assert_ne!(np, "12345");
    assert_eq!(np.len(), 8);
}

/// Port of `TestNameplate_NoDash`.
#[test]
fn test_nameplate_no_dash() {
    assert_eq!(nameplate("hello"), "870dcb1f");
}

/// Port of `TestNameplate_Empty`.
#[test]
fn test_nameplate_empty() {
    assert_eq!(nameplate(""), "72786c0e");
}

/// Port of `TestNameplate_GeneratedCodeRe`.
#[test]
fn test_nameplate_generated_code_re() {
    for c in ["0000-", "9999-", "1234-abc"] {
        assert!(is_generated_code(c), "expected regex to match {c:?}");
    }
    for c in ["123-", "12345-", "abcd-", "1234", "", "0000"] {
        assert!(!is_generated_code(c), "expected regex to not match {c:?}");
    }
}

/// Port of `TestGenerateCode_Format` (internal/util variant).
#[test]
fn test_generate_code_format_util() {
    for _ in 0..100 {
        let code = generate_code().unwrap();
        let first = code.split_once('-').unwrap().0;
        assert_eq!(first.len(), 4, "expected 4-digit number in {code}");
    }
}

/// Port of `TestGenerateCode_WordsInList` (internal/util variant).
#[test]
fn test_generate_code_words_in_list() {
    let words = code_words();
    for _ in 0..100 {
        let code = generate_code().unwrap();
        let np = nameplate(&code);
        let mut rest = &code[np.len() + 1..];
        while !rest.is_empty() {
            let mut found = false;
            for w in words {
                if rest.starts_with(w.as_str())
                    && (rest.len() == w.len() || rest.as_bytes()[w.len()] == b'-')
                {
                    rest = &rest[w.len()..];
                    if !rest.is_empty() {
                        rest = &rest[1..]; // skip hyphen
                    }
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "could not parse words in {code:?} (remaining: {rest:?})"
            );
        }
    }
}

/// Port of `TestGenerateCode_DeterministicNot` (internal/util variant).
#[test]
fn test_generate_code_deterministic_not() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let code = generate_code().unwrap();
        assert!(
            seen.insert(code.clone()),
            "duplicate code generated: {code}"
        );
    }
}

/// Top-level `TestGenerateCode_Format` (package qvole variant).
#[test]
fn test_generate_code_format_top() {
    let code = generate_code().unwrap();
    assert!(!code.is_empty());
    let parts: Vec<&str> = code.split('-').collect();
    assert_eq!(
        parts.len(),
        4,
        "expected 4 parts, got {}: {code:?}",
        parts.len()
    );
    assert_eq!(parts[0].len(), 4);
    assert!(
        parts[0].chars().all(|c| c.is_ascii_digit()),
        "first part should be all digits, got {:?}",
        parts[0]
    );
}

/// Top-level `TestNameplate_Generated`.
#[test]
fn test_nameplate_generated() {
    let code = generate_code().unwrap();
    let np = nameplate(&code);
    assert_eq!(
        np.len(),
        4,
        "nameplate for generated code should be 4 chars, got {np:?}"
    );
    assert_eq!(&code[..4], np);
}

/// Top-level `TestNameplate_Arbitrary`.
#[test]
fn test_nameplate_arbitrary() {
    let np = nameplate("my-secret-code");
    assert_eq!(np.len(), 8);
    assert!(np.chars().all(|c| c.is_ascii_hexdigit()));
}

/// Top-level `TestNameplate_Deterministic`.
#[test]
fn test_nameplate_deterministic() {
    let a = nameplate("my-secret-code");
    let b = nameplate("my-secret-code");
    assert_eq!(a, b);
    assert_eq!(a.len(), 8);
}

/// Top-level `TestNameplate_DifferentCodes`.
#[test]
fn test_nameplate_different_codes() {
    assert_ne!(nameplate("code-a"), nameplate("code-b"));
}

/// Check that `MOD_P` / `ORDER_N` match the `p256` crate's own arithmetic.
/// The `p256` 0.13 tree does not export the raw modulus/order constants, so
/// instead verify that reduction by our constants agrees with p256's native
/// modular addition on values chosen to force the wrap: (p-2) + 3 == 1 (mod p)
/// and (N-2) + 3 == 1 (mod N).
#[test]
fn test_curve_constants_match_p256() {
    let two = U256::from(2u32);
    let three = U256::from(3u32);

    // Field prime: p256's own field addition must equal reduction by MOD_P.
    let pm2 = MOD_P.wrapping_sub(&two);
    let a = bytes32::to_fe(&pm2.to_be_bytes());
    let b = bytes32::to_fe(&three.to_be_bytes());
    let c = a + b;
    let sum = pm2.wrapping_add(&three); // p + 1, no 256-bit overflow
    let expected = if sum >= MOD_P {
        sum.wrapping_sub(&MOD_P)
    } else {
        sum
    };
    assert_eq!(
        c,
        bytes32::to_fe(&expected.to_be_bytes()),
        "MOD_P does not match p256's field prime"
    );

    // Group order: p256's own scalar addition must equal reduction by ORDER_N.
    let nm2 = ORDER_N.wrapping_sub(&two);
    let a = bytes32::to_scalar(&nm2.to_be_bytes());
    let b = bytes32::to_scalar(&three.to_be_bytes());
    let c = a + b;
    let sum = nm2.wrapping_add(&three); // N + 1, no 256-bit overflow
    let expected = if sum >= ORDER_N {
        sum.wrapping_sub(&ORDER_N)
    } else {
        sum
    };
    assert_eq!(
        c,
        bytes32::to_scalar(&expected.to_be_bytes()),
        "ORDER_N does not match p256's group order"
    );
}
