//! sworn-verify: pure Ed25519 signature verification for SWORN attestations.
//!
//! This crate is the correctness reference for SWORN's signing scheme (spec §3).
//! It has no DB dependency, no HTTP dependency, and no `unsafe`. It is safe to
//! embed inside a Postgres server, a browser via WASM, a Node service via NAPI,
//! or a CLI. If this crate and the spec disagree, the spec wins and this crate
//! is a bug.
//!
//! Scope for v0.1:
//!
//! - Ed25519 keygen (RFC 8032, PureEdDSA)
//! - `canonical_bytes` construction (spec §3.1, 216 bytes)
//! - Sign and verify against `canonical_bytes`
//! - SHA-256 helper for `data_hash` / `activity_hash` (spec §2.4)
//!
//! Out of scope (deliberately):
//!
//! - JSON canonicalization (RFC 8785 lives in a higher layer that owns payloads)
//! - Postgres storage (see `store/`)
//! - HTTP transport (see `api/`)
//! - Any Extol-specific derivation (HMAC-KMS nonces, invisible wallets, etc.)

use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey,
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Length of the canonical byte sequence signed under Ed25519, per spec §3.1.
///
/// Layout arithmetic: 32 (signer) + 32 (subject) + 32 (activity_hash) +
/// 32 (data_hash) + 32 (witness_for) + 8 (created_at) + 8 (retention_hint) +
/// 32 (nonce) = **208 bytes**.
///
/// The SPEC.md prose at the time of this crate's initial commit said "216
/// bytes" in one place, contradicting its own field-by-field layout. The
/// field-by-field layout is normative; the summary line was a spec bug
/// caught by this crate's byte-offset test. Spec fix tracked in the SWORN
/// repo history.
pub const CANONICAL_BYTES_LEN: usize = 208;

/// Length of a hash (SHA-256, and the field width used for pubkeys and nonces).
pub const HASH_LEN: usize = 32;

/// A 32-byte value: pubkey, hash, or nonce. All 32-byte fields in SWORN share
/// this type to make byte-layout construction obvious.
pub type Bytes32 = [u8; HASH_LEN];

/// All fields required to construct `canonical_bytes` and to sign or verify
/// an attestation per spec §3.1.
///
/// This struct does NOT capture the semantic payload, the `activity_type` URI,
/// or the `signature` itself. Those live at higher layers; `AttestationFields`
/// is only the input the signing scheme consumes.
///
/// `witness_for` is `[0u8; 32]` when the attestation is not a corroboration
/// (spec §2.5: the field is always present in the byte sequence; 32 zero bytes
/// means "no endorsement").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationFields {
    pub signer: Bytes32,
    pub subject: Bytes32,
    pub activity_hash: Bytes32,
    pub data_hash: Bytes32,
    pub witness_for: Bytes32,
    pub created_at: i64,
    pub retention_hint: i64,
    pub nonce: Bytes32,
}

impl AttestationFields {
    /// Construct the 216-byte canonical byte sequence per spec §3.1.
    ///
    /// Field order and widths are normative. Implementations MUST NOT include
    /// additional fields, framing, or version markers.
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_BYTES_LEN] {
        let mut out = [0u8; CANONICAL_BYTES_LEN];
        let mut off = 0;

        write32(&mut out, &mut off, &self.signer);
        write32(&mut out, &mut off, &self.subject);
        write32(&mut out, &mut off, &self.activity_hash);
        write32(&mut out, &mut off, &self.data_hash);
        write32(&mut out, &mut off, &self.witness_for);
        out[off..off + 8].copy_from_slice(&self.created_at.to_le_bytes());
        off += 8;
        out[off..off + 8].copy_from_slice(&self.retention_hint.to_le_bytes());
        off += 8;
        write32(&mut out, &mut off, &self.nonce);

        debug_assert_eq!(off, CANONICAL_BYTES_LEN);
        out
    }
}

#[inline]
fn write32(dst: &mut [u8; CANONICAL_BYTES_LEN], off: &mut usize, src: &Bytes32) {
    dst[*off..*off + HASH_LEN].copy_from_slice(src);
    *off += HASH_LEN;
}

/// Errors returned by the verify crate.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("signature verification failed: {0}")]
    BadSignature(#[from] SignatureError),

    #[error("signer pubkey length must be {PUBLIC_KEY_LENGTH} bytes, got {0}")]
    BadPubkeyLen(usize),

    #[error("signature length must be {SIGNATURE_LENGTH} bytes, got {0}")]
    BadSignatureLen(usize),

    #[error("signer_from_fields does not match provided pubkey")]
    SignerMismatch,
}

/// Generate a fresh Ed25519 keypair using the operating system's CSPRNG.
///
/// Returns `(signing_key, verifying_key_bytes)`. Callers that want the
/// verifying key as a `VerifyingKey` can call `.verifying_key()` on the
/// signing key.
pub fn keygen() -> (SigningKey, Bytes32) {
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = sk.verifying_key().to_bytes();
    (sk, pk_bytes)
}

/// Sign a set of attestation fields per spec §3.2.
///
/// The signer's public key MUST match `fields.signer`. If it does not, the
/// caller has a bug: the canonical byte sequence embeds the signer pubkey, so
/// signing a `canonical_bytes` whose embedded signer differs from the actual
/// signing key produces a signature that verifies against neither. We reject
/// with `SignerMismatch` rather than produce that footgun.
pub fn sign(
    signing_key: &SigningKey,
    fields: &AttestationFields,
) -> Result<[u8; SIGNATURE_LENGTH], VerifyError> {
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = signing_key.verifying_key().to_bytes();
    if pk_bytes != fields.signer {
        return Err(VerifyError::SignerMismatch);
    }
    let bytes = fields.canonical_bytes();
    let sig: Signature = signing_key.sign(&bytes);
    Ok(sig.to_bytes())
}

/// Verify a signature against an attestation's fields per spec §3.1 verification
/// procedure.
///
/// This function establishes ONLY that the holder of `fields.signer`'s private
/// key produced `signature` over the exact 216-byte sequence in
/// `fields.canonical_bytes()`. It does NOT verify that any payload matches
/// `data_hash`. Payload verification is the caller's responsibility, per spec
/// §3.1 step 3.
pub fn verify(fields: &AttestationFields, signature: &[u8]) -> Result<(), VerifyError> {
    if signature.len() != SIGNATURE_LENGTH {
        return Err(VerifyError::BadSignatureLen(signature.len()));
    }
    let sig_arr: [u8; SIGNATURE_LENGTH] = signature.try_into().expect("checked");
    let sig = Signature::from_bytes(&sig_arr);

    let vk = VerifyingKey::from_bytes(&fields.signer)?;
    let bytes = fields.canonical_bytes();
    vk.verify(&bytes, &sig)?;
    Ok(())
}

/// SHA-256 helper. Convenience for callers computing `activity_hash` per
/// spec §2.4 or `data_hash` per spec §2.4 from already-canonicalized bytes.
///
/// This crate deliberately does not canonicalize JSON; that lives at Layer 1
/// and belongs to whichever crate owns payload handling.
pub fn sha256(input: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test `AttestationFields` value where every field is filled with
    /// a distinct known pattern, so byte-layout regressions surface as failed
    /// offset assertions rather than cryptographic ones.
    fn fixture(signer: Bytes32) -> AttestationFields {
        AttestationFields {
            signer,
            subject: [0x02; HASH_LEN],
            activity_hash: [0x03; HASH_LEN],
            data_hash: [0x04; HASH_LEN],
            witness_for: [0x05; HASH_LEN],
            created_at: 1_753_910_400, // Aug 1 2026 UTC, arbitrary but stable
            retention_hint: 30 * 24 * 60 * 60, // 30 days in seconds, arbitrary
            nonce: [0x08; HASH_LEN],
        }
    }

    #[test]
    fn canonical_bytes_is_208_bytes_exactly() {
        let (_sk, pk) = keygen();
        let f = fixture(pk);
        let bytes = f.canonical_bytes();
        assert_eq!(bytes.len(), CANONICAL_BYTES_LEN);
        assert_eq!(bytes.len(), 208);
    }

    #[test]
    fn canonical_bytes_layout_matches_spec_offsets() {
        // Distinct byte patterns per field so a wrong offset produces a
        // visibly wrong slice.
        let f = AttestationFields {
            signer: [0xA1; HASH_LEN],
            subject: [0xA2; HASH_LEN],
            activity_hash: [0xA3; HASH_LEN],
            data_hash: [0xA4; HASH_LEN],
            witness_for: [0xA5; HASH_LEN],
            created_at: 0x0102030405060708_i64,
            retention_hint: 0x1112131415161718_i64,
            nonce: [0xA8; HASH_LEN],
        };
        let b = f.canonical_bytes();

        // Byte-for-byte offset check against spec §3.1 field-by-field layout:
        //   0..32     signer
        //   32..64    subject
        //   64..96    activity_hash
        //   96..128   data_hash
        //   128..160  witness_for
        //   160..168  created_at   (i64 little-endian)
        //   168..176  retention_hint (i64 little-endian)
        //   176..208  nonce
        // Total 208 bytes exactly. No trailing padding.
        assert_eq!(&b[0..32], &[0xA1u8; 32]);
        assert_eq!(&b[32..64], &[0xA2u8; 32]);
        assert_eq!(&b[64..96], &[0xA3u8; 32]);
        assert_eq!(&b[96..128], &[0xA4u8; 32]);
        assert_eq!(&b[128..160], &[0xA5u8; 32]);
        assert_eq!(
            &b[160..168],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            &b[168..176],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(&b[176..208], &[0xA8u8; 32]);

        // Guardrail: constant must equal field-by-field arithmetic. If a
        // future field-width change makes these disagree, this test fires
        // before any real signature is produced against a wrong-length buffer.
        let expected: usize =
            32 + 32 + 32 + 32 + 32 + 8 + 8 + 32;
        assert_eq!(expected, CANONICAL_BYTES_LEN, "layout arithmetic vs constant");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = keygen();
        let f = fixture(pk);
        let sig = sign(&sk, &f).expect("sign ok");
        verify(&f, &sig).expect("verify ok");
    }

    #[test]
    fn verify_rejects_tampered_field() {
        let (sk, pk) = keygen();
        let f = fixture(pk);
        let sig = sign(&sk, &f).expect("sign ok");

        // Change subject after signing; signature MUST NOT verify.
        let mut tampered = f;
        tampered.subject = [0xFF; HASH_LEN];
        assert!(verify(&tampered, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer_pubkey() {
        let (sk, pk_a) = keygen();
        let (_sk_b, pk_b) = keygen();
        let f = fixture(pk_a);
        let sig = sign(&sk, &f).expect("sign ok");

        // Change signer after signing; verification uses the pubkey in fields.
        let mut swapped = f;
        swapped.signer = pk_b;
        assert!(verify(&swapped, &sig).is_err());
    }

    #[test]
    fn sign_rejects_pubkey_mismatch() {
        // Fields claim signer B, but we try to sign with A's private key.
        // Must error rather than produce an unverifiable signature.
        let (sk_a, _pk_a) = keygen();
        let (_sk_b, pk_b) = keygen();
        let f = fixture(pk_b);
        let err = sign(&sk_a, &f).unwrap_err();
        assert!(matches!(err, VerifyError::SignerMismatch));
    }

    #[test]
    fn verify_rejects_bad_signature_length() {
        let (_sk, pk) = keygen();
        let f = fixture(pk);
        let too_short = [0u8; 32];
        let err = verify(&f, &too_short).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignatureLen(32)));
    }

    #[test]
    fn nonce_change_produces_different_signature() {
        // Per spec §3.4: two attestations by the same signer about the same
        // subject with the same activity_hash MUST NOT share a nonce, and MUST
        // produce distinct signatures. This is the replay-protection property.
        let (sk, pk) = keygen();
        let mut f1 = fixture(pk);
        let mut f2 = fixture(pk);
        f1.nonce = [0x01; HASH_LEN];
        f2.nonce = [0x02; HASH_LEN];
        let s1 = sign(&sk, &f1).unwrap();
        let s2 = sign(&sk, &f2).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn sha256_matches_known_vector() {
        // Empty string SHA-256 is the standard test vector.
        let want = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
            0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
            0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
            0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(sha256(b""), want);
    }
}
