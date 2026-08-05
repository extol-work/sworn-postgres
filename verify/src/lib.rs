//! sworn-verify: pure Ed25519 signature verification for SWORN attestations.
//!
//! This crate is the correctness reference for SWORN's signing scheme (spec §3).
//! It has no DB dependency, no HTTP dependency, and no `unsafe`. It is safe to
//! embed inside a Postgres server, a browser via WASM, a Node service via NAPI,
//! or a CLI. If this crate and the spec disagree, the spec wins and this crate
//! is a bug.
//!
//! Scope for v0.1-final:
//!
//! - Ed25519 keygen (RFC 8032, PureEdDSA)
//! - `canonical_bytes` construction for spec_version = 2 (spec §3.1, 248 bytes)
//! - Legacy `canonical_bytes` construction for spec_version = 1 (208 bytes,
//!   read-only, no new signing)
//! - Sign and verify against `canonical_bytes`
//! - SHA-256 helper for `data_hash`, `activity_hash`, `source_hash` (spec §2.4)
//! - Enum types for source_type / witnessing_depth / attestor_relationship
//!   with locked integer positions per spec §9.2–§9.4
//!
//! Out of scope (deliberately):
//!
//! - JSON canonicalization (RFC 8785 lives in a higher layer that owns payloads)
//! - source_hash canonicalization per source_type (higher layers; see spec §9.2)
//! - Postgres storage (see `store/`)
//! - HTTP transport (see `api/`)
//! - Any Extol-specific derivation (HMAC-KMS nonces, invisible wallets, etc.)

use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey,
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Length of the v0.1-final canonical byte sequence signed under Ed25519, per
/// spec §3.1.
///
/// Layout arithmetic (spec_version = 2):
/// `2 (spec_version) + 32 (signer) + 32 (subject) + 32 (activity_hash) +
/// 32 (data_hash) + 32 (witness_for) + 32 (source_hash) + 2 (source_type) +
/// 2 (confidence) + 1 (witnessing_depth) + 1 (attestor_relationship) +
/// 8 (created_at) + 8 (retention_hint) + 32 (nonce) = 248 bytes`.
pub const CANONICAL_BYTES_LEN_V2: usize = 248;

/// Length of the legacy v0.1-preview canonical byte sequence (208 bytes).
///
/// Retained ONLY for verifying historical rows written before the v0.1-final
/// restructure. No signing path in this crate produces v0.1-preview bytes.
/// New attestations MUST use v0.1-final (spec_version = 2).
pub const CANONICAL_BYTES_LEN_V1: usize = 208;

/// Length of a hash (SHA-256, and the field width used for pubkeys and nonces).
pub const HASH_LEN: usize = 32;

/// A 32-byte value: pubkey, hash, or nonce. All 32-byte fields in SWORN share
/// this type to make byte-layout construction obvious.
pub type Bytes32 = [u8; HASH_LEN];

// ── SPEC VERSION ────────────────────────────────────────────────────

/// Registered spec_version values per SPEC §3.1.1.
///
/// Integer positions are stable (§1.4). Verifiers dispatch on this to select
/// the correct canonical-byte-sequence layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SpecVersion {
    /// v0.1-preview: 208-byte canonical layout, no provenance fields.
    /// Deprecated for new writes; retained for verifying historical rows.
    V01Preview = 1,
    /// v0.1-final: 248-byte canonical layout with provenance.
    V01Final = 2,
}

impl SpecVersion {
    /// Attempt to decode a raw u16 into a known SpecVersion. Returns
    /// `None` if the value is unknown so the caller can distinguish
    /// version-mismatch (report to operator: reader is behind) from
    /// malformed (report to operator: attestation is corrupt).
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(SpecVersion::V01Preview),
            2 => Some(SpecVersion::V01Final),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

// ── PROVENANCE ENUMS ────────────────────────────────────────────────

/// Registered source_type values per SPEC §9.2.
///
/// Integer positions are stable (§1.4). Renames of the string label do not
/// change integer values. Additions append at the next unused integer without
/// advancing spec_version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SourceType {
    Unknown = 0,
    SelfReported = 1,
    Orcid = 2,
    Doi = 3,
    OpenAlex = 4,
    GitCommit = 5,
    RssParsed = 6,
    OpenSourceProject = 7,
    CoordinatorConfirmed = 8,
    PeerWitnessed = 9,
    Computed = 10,
    SystemObserved = 11,
    RegulatoryFiling = 12,
    CommunityCuratedDb = 13,
    ExternalSwornAttestation = 14,
}

impl SourceType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(SourceType::Unknown),
            1 => Some(SourceType::SelfReported),
            2 => Some(SourceType::Orcid),
            3 => Some(SourceType::Doi),
            4 => Some(SourceType::OpenAlex),
            5 => Some(SourceType::GitCommit),
            6 => Some(SourceType::RssParsed),
            7 => Some(SourceType::OpenSourceProject),
            8 => Some(SourceType::CoordinatorConfirmed),
            9 => Some(SourceType::PeerWitnessed),
            10 => Some(SourceType::Computed),
            11 => Some(SourceType::SystemObserved),
            12 => Some(SourceType::RegulatoryFiling),
            13 => Some(SourceType::CommunityCuratedDb),
            14 => Some(SourceType::ExternalSwornAttestation),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// True when the source_type has no external source and source_hash
    /// MUST be 32 zero bytes per spec §2.4 / §9.2.
    pub fn requires_zero_source_hash(self) -> bool {
        matches!(self, SourceType::Unknown | SourceType::SelfReported)
    }
}

/// Registered witnessing_depth values per SPEC §9.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessingDepth {
    Unspecified = 0,
    PhysicallyObserved = 1,
    ReviewedArtifacts = 2,
    UiConfirmed = 3,
    ComputedMatch = 4,
    SelfAsserted = 5,
}

impl WitnessingDepth {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(WitnessingDepth::Unspecified),
            1 => Some(WitnessingDepth::PhysicallyObserved),
            2 => Some(WitnessingDepth::ReviewedArtifacts),
            3 => Some(WitnessingDepth::UiConfirmed),
            4 => Some(WitnessingDepth::ComputedMatch),
            5 => Some(WitnessingDepth::SelfAsserted),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Registered attestor_relationship values per SPEC §9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestorRelationship {
    Unknown = 0,
    Self_ = 1,
    Coordinator = 2,
    Peer = 3,
    Mentor = 4,
    Unaffiliated = 5,
    Institution = 6,
}

impl AttestorRelationship {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(AttestorRelationship::Unknown),
            1 => Some(AttestorRelationship::Self_),
            2 => Some(AttestorRelationship::Coordinator),
            3 => Some(AttestorRelationship::Peer),
            4 => Some(AttestorRelationship::Mentor),
            5 => Some(AttestorRelationship::Unaffiliated),
            6 => Some(AttestorRelationship::Institution),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ── ATTESTATION FIELDS (v0.1-final) ─────────────────────────────────

/// All fields required to construct v0.1-final `canonical_bytes` and to sign
/// or verify an attestation per spec §3.1.
///
/// This struct does NOT capture the semantic payload, the `activity_type`
/// URI, or the `signature` itself. Those live at higher layers.
///
/// `witness_for` is `[0u8; 32]` when the attestation is not a corroboration
/// (spec §2.6). `source_hash` is `[0u8; 32]` when `source_type` is Unknown
/// or SelfReported (spec §2.4).
///
/// Timestamp field is named `signer_asserted_at` in this crate to align with
/// the store schema's naming convention (`signer_asserted_at` vs the server-
/// observed `notarized_at`). The spec calls this field `created_at` in §2.7;
/// the two names refer to the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationFields {
    pub signer: Bytes32,
    pub subject: Bytes32,
    pub activity_hash: Bytes32,
    pub data_hash: Bytes32,
    pub witness_for: Bytes32,
    pub source_hash: Bytes32,
    pub source_type: SourceType,
    pub confidence: u16,
    pub witnessing_depth: WitnessingDepth,
    pub attestor_relationship: AttestorRelationship,
    pub signer_asserted_at: i64,
    pub retention_hint: i64,
    pub nonce: Bytes32,
}

impl AttestationFields {
    /// Construct the 248-byte v0.1-final canonical byte sequence per spec §3.1.
    ///
    /// The `spec_version` marker (u16 LE = 2) is written at position 0.
    ///
    /// Field order and widths are normative. Implementations MUST NOT include
    /// additional fields, framing, or other version markers.
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_BYTES_LEN_V2] {
        let mut out = [0u8; CANONICAL_BYTES_LEN_V2];
        let mut off = 0;

        // spec_version = 2 (v0.1-final) as u16 little-endian
        out[off..off + 2].copy_from_slice(&SpecVersion::V01Final.to_u16().to_le_bytes());
        off += 2;

        write32(&mut out, &mut off, &self.signer);
        write32(&mut out, &mut off, &self.subject);
        write32(&mut out, &mut off, &self.activity_hash);
        write32(&mut out, &mut off, &self.data_hash);
        write32(&mut out, &mut off, &self.witness_for);
        write32(&mut out, &mut off, &self.source_hash);

        out[off..off + 2].copy_from_slice(&self.source_type.to_u16().to_le_bytes());
        off += 2;
        out[off..off + 2].copy_from_slice(&self.confidence.to_le_bytes());
        off += 2;
        out[off] = self.witnessing_depth.to_u8();
        off += 1;
        out[off] = self.attestor_relationship.to_u8();
        off += 1;

        out[off..off + 8].copy_from_slice(&self.signer_asserted_at.to_le_bytes());
        off += 8;
        out[off..off + 8].copy_from_slice(&self.retention_hint.to_le_bytes());
        off += 8;

        write32(&mut out, &mut off, &self.nonce);

        debug_assert_eq!(off, CANONICAL_BYTES_LEN_V2);
        out
    }
}

// ── LEGACY (v0.1-preview) ATTESTATION FIELDS ────────────────────────

/// Legacy 208-byte canonical byte sequence for v0.1-preview attestations.
///
/// Retained so verifiers can validate historical rows written before the
/// v0.1-final restructure. Not used for signing new attestations.
///
/// Fields correspond to the pre-restructure struct: no provenance,
/// no spec_version prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyAttestationFieldsV01Preview {
    pub signer: Bytes32,
    pub subject: Bytes32,
    pub activity_hash: Bytes32,
    pub data_hash: Bytes32,
    pub witness_for: Bytes32,
    pub signer_asserted_at: i64,
    pub retention_hint: i64,
    pub nonce: Bytes32,
}

impl LegacyAttestationFieldsV01Preview {
    /// Reconstruct the 208-byte v0.1-preview canonical byte sequence.
    ///
    /// This exists to verify historical signatures. No new attestation
    /// SHOULD be signed against this layout.
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_BYTES_LEN_V1] {
        let mut out = [0u8; CANONICAL_BYTES_LEN_V1];
        let mut off = 0;

        write32_v1(&mut out, &mut off, &self.signer);
        write32_v1(&mut out, &mut off, &self.subject);
        write32_v1(&mut out, &mut off, &self.activity_hash);
        write32_v1(&mut out, &mut off, &self.data_hash);
        write32_v1(&mut out, &mut off, &self.witness_for);
        out[off..off + 8].copy_from_slice(&self.signer_asserted_at.to_le_bytes());
        off += 8;
        out[off..off + 8].copy_from_slice(&self.retention_hint.to_le_bytes());
        off += 8;
        write32_v1(&mut out, &mut off, &self.nonce);

        debug_assert_eq!(off, CANONICAL_BYTES_LEN_V1);
        out
    }
}

#[inline]
fn write32(dst: &mut [u8; CANONICAL_BYTES_LEN_V2], off: &mut usize, src: &Bytes32) {
    dst[*off..*off + HASH_LEN].copy_from_slice(src);
    *off += HASH_LEN;
}

#[inline]
fn write32_v1(dst: &mut [u8; CANONICAL_BYTES_LEN_V1], off: &mut usize, src: &Bytes32) {
    dst[*off..*off + HASH_LEN].copy_from_slice(src);
    *off += HASH_LEN;
}

// ── ERRORS ──────────────────────────────────────────────────────────

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

    #[error("source_hash MUST be 32 zero bytes for source_type {0:?}")]
    NonZeroSourceHashForSourceless(SourceType),

    #[error("unknown spec_version value {0}")]
    UnknownSpecVersion(u16),
}

// ── KEYGEN, SIGN, VERIFY ───────────────────────────────────────────

/// Generate a fresh Ed25519 keypair using the operating system's CSPRNG.
pub fn keygen() -> (SigningKey, Bytes32) {
    let mut seed = [0u8; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = sk.verifying_key().to_bytes();
    (sk, pk_bytes)
}

/// Sign a set of attestation fields per spec §3.2, targeting v0.1-final
/// canonical bytes.
///
/// Preconditions:
///   * The signer's public key MUST match `fields.signer`.
///   * If `fields.source_type` is Unknown or SelfReported, `fields.source_hash`
///     MUST be `[0u8; 32]`. Otherwise the signed bytes would misrepresent the
///     source claim (§2.4).
///
/// Returns `SignerMismatch` on pubkey mismatch, `NonZeroSourceHashForSourceless`
/// on the source_hash preconditions above.
pub fn sign(
    signing_key: &SigningKey,
    fields: &AttestationFields,
) -> Result<[u8; SIGNATURE_LENGTH], VerifyError> {
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = signing_key.verifying_key().to_bytes();
    if pk_bytes != fields.signer {
        return Err(VerifyError::SignerMismatch);
    }
    if fields.source_type.requires_zero_source_hash()
        && fields.source_hash != [0u8; HASH_LEN]
    {
        return Err(VerifyError::NonZeroSourceHashForSourceless(fields.source_type));
    }
    let bytes = fields.canonical_bytes();
    let sig: Signature = signing_key.sign(&bytes);
    Ok(sig.to_bytes())
}

/// Verify a signature against v0.1-final attestation fields per spec §3.1
/// verification procedure.
///
/// This function establishes ONLY that the holder of `fields.signer`'s
/// private key produced `signature` over the exact 248-byte sequence in
/// `fields.canonical_bytes()`. It does NOT verify:
///   * that any payload matches `data_hash` (payload verification is the
///     caller's responsibility per §3.1),
///   * that the external source referenced by `source_hash` is reachable or
///     authoritative (§2.5.1: signer's claim, not verifier's guarantee).
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

/// Verify a signature against v0.1-preview (legacy) attestation fields.
///
/// Used for historical rows written before the v0.1-final restructure. New
/// attestations SHOULD NOT be signed against this layout.
pub fn verify_legacy_v01_preview(
    fields: &LegacyAttestationFieldsV01Preview,
    signature: &[u8],
) -> Result<(), VerifyError> {
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

/// SHA-256 helper. Convenience for callers computing `activity_hash`,
/// `data_hash`, or `source_hash` per spec §2.4 from already-canonicalized
/// bytes.
///
/// This crate deliberately does not canonicalize JSON (spec §2.3) or source
/// identifiers (spec §9.2); those live at Layer 1 and belong to whichever
/// crate owns payload and provenance handling.
pub fn sha256(input: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

// ── TESTS ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// v0.1-final fixture with every field filled by a distinct known pattern
    /// so byte-layout regressions surface as failed offset assertions rather
    /// than cryptographic ones.
    fn fixture(signer: Bytes32) -> AttestationFields {
        AttestationFields {
            signer,
            subject: [0x02; HASH_LEN],
            activity_hash: [0x03; HASH_LEN],
            data_hash: [0x04; HASH_LEN],
            witness_for: [0x05; HASH_LEN],
            source_hash: [0x06; HASH_LEN],
            source_type: SourceType::Orcid,
            confidence: 9500,
            witnessing_depth: WitnessingDepth::ComputedMatch,
            attestor_relationship: AttestorRelationship::Self_,
            signer_asserted_at: 1_753_910_400, // Aug 1 2026 UTC, arbitrary but stable
            retention_hint: 30 * 24 * 60 * 60, // 30 days in seconds, arbitrary
            nonce: [0x08; HASH_LEN],
        }
    }

    /// Fixture that satisfies source_hash-zero requirement for SelfReported.
    fn self_reported_fixture(signer: Bytes32) -> AttestationFields {
        AttestationFields {
            signer,
            subject: [0x02; HASH_LEN],
            activity_hash: [0x03; HASH_LEN],
            data_hash: [0x04; HASH_LEN],
            witness_for: [0u8; HASH_LEN],
            source_hash: [0u8; HASH_LEN],
            source_type: SourceType::SelfReported,
            confidence: 8000,
            witnessing_depth: WitnessingDepth::SelfAsserted,
            attestor_relationship: AttestorRelationship::Self_,
            signer_asserted_at: 1_753_910_400,
            retention_hint: -1,
            nonce: [0x08; HASH_LEN],
        }
    }

    #[test]
    fn canonical_bytes_is_248_bytes_exactly() {
        let (_sk, pk) = keygen();
        let f = fixture(pk);
        let bytes = f.canonical_bytes();
        assert_eq!(bytes.len(), CANONICAL_BYTES_LEN_V2);
        assert_eq!(bytes.len(), 248);
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
            source_hash: [0xA6; HASH_LEN],
            source_type: SourceType::Doi,   // = 3
            confidence: 0x1234_u16,
            witnessing_depth: WitnessingDepth::ReviewedArtifacts, // = 2
            attestor_relationship: AttestorRelationship::Peer,    // = 3
            signer_asserted_at: 0x0102030405060708_i64,
            retention_hint: 0x1112131415161718_i64,
            nonce: [0xA8; HASH_LEN],
        };
        let b = f.canonical_bytes();

        // Byte-for-byte offset check against SPEC §3.1 field-by-field layout:
        //   0..2      spec_version (u16 LE) = 2 (v0.1-final)
        //   2..34     signer
        //   34..66    subject
        //   66..98    activity_hash
        //   98..130   data_hash
        //   130..162  witness_for
        //   162..194  source_hash
        //   194..196  source_type (u16 LE)
        //   196..198  confidence (u16 LE)
        //   198..199  witnessing_depth (u8)
        //   199..200  attestor_relationship (u8)
        //   200..208  signer_asserted_at (i64 LE)
        //   208..216  retention_hint (i64 LE)
        //   216..248  nonce
        // Total 248 bytes exactly.
        assert_eq!(&b[0..2], &[0x02, 0x00]); // spec_version = 2
        assert_eq!(&b[2..34], &[0xA1u8; 32]);
        assert_eq!(&b[34..66], &[0xA2u8; 32]);
        assert_eq!(&b[66..98], &[0xA3u8; 32]);
        assert_eq!(&b[98..130], &[0xA4u8; 32]);
        assert_eq!(&b[130..162], &[0xA5u8; 32]);
        assert_eq!(&b[162..194], &[0xA6u8; 32]);
        assert_eq!(&b[194..196], &[0x03, 0x00]); // Doi = 3
        assert_eq!(&b[196..198], &[0x34, 0x12]); // 0x1234 LE
        assert_eq!(b[198], 2u8);                  // ReviewedArtifacts = 2
        assert_eq!(b[199], 3u8);                  // Peer = 3
        assert_eq!(&b[200..208], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&b[208..216], &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        assert_eq!(&b[216..248], &[0xA8u8; 32]);

        // Guardrail: constant must equal field-by-field arithmetic.
        let expected: usize =
            2 + 32 * 6 + 2 + 2 + 1 + 1 + 8 + 8 + 32;
        assert_eq!(expected, CANONICAL_BYTES_LEN_V2, "layout arithmetic vs constant");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = keygen();
        let f = fixture(pk);
        let sig = sign(&sk, &f).expect("sign ok");
        verify(&f, &sig).expect("verify ok");
    }

    #[test]
    fn self_reported_roundtrip() {
        let (sk, pk) = keygen();
        let f = self_reported_fixture(pk);
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
    fn verify_rejects_tampered_provenance() {
        // Provenance fields are signed content: changing confidence should
        // invalidate the signature, same as changing subject.
        let (sk, pk) = keygen();
        let f = fixture(pk);
        let sig = sign(&sk, &f).expect("sign ok");

        let mut tampered = f;
        tampered.confidence = 100;
        assert!(verify(&tampered, &sig).is_err());

        let mut tampered = f;
        tampered.source_type = SourceType::SelfReported;
        assert!(verify(&tampered, &sig).is_err());

        let mut tampered = f;
        tampered.witnessing_depth = WitnessingDepth::PhysicallyObserved;
        assert!(verify(&tampered, &sig).is_err());

        let mut tampered = f;
        tampered.attestor_relationship = AttestorRelationship::Coordinator;
        assert!(verify(&tampered, &sig).is_err());

        let mut tampered = f;
        tampered.source_hash = [0xFF; HASH_LEN];
        assert!(verify(&tampered, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer_pubkey() {
        let (sk, pk_a) = keygen();
        let (_sk_b, pk_b) = keygen();
        let f = fixture(pk_a);
        let sig = sign(&sk, &f).expect("sign ok");

        let mut swapped = f;
        swapped.signer = pk_b;
        assert!(verify(&swapped, &sig).is_err());
    }

    #[test]
    fn sign_rejects_pubkey_mismatch() {
        let (sk_a, _pk_a) = keygen();
        let (_sk_b, pk_b) = keygen();
        let f = fixture(pk_b);
        let err = sign(&sk_a, &f).unwrap_err();
        assert!(matches!(err, VerifyError::SignerMismatch));
    }

    #[test]
    fn sign_rejects_nonzero_source_hash_for_self_reported() {
        // SelfReported and Unknown MUST carry all-zero source_hash.
        let (sk, pk) = keygen();
        let mut f = self_reported_fixture(pk);
        f.source_hash = [0x01; HASH_LEN];
        let err = sign(&sk, &f).unwrap_err();
        assert!(matches!(err, VerifyError::NonZeroSourceHashForSourceless(SourceType::SelfReported)));
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
        // subject with the same activity_hash MUST NOT share a nonce, and
        // MUST produce distinct signatures.
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
        let want = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
            0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
            0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
            0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
        ];
        assert_eq!(sha256(b""), want);
    }

    // ── Enum roundtrips ─────────────────────────────────────────────

    #[test]
    fn source_type_roundtrips_all_registered_values() {
        for i in 0u16..=14 {
            let st = SourceType::from_u16(i).expect("registered");
            assert_eq!(st.to_u16(), i);
        }
        assert!(SourceType::from_u16(15).is_none());
        assert!(SourceType::from_u16(255).is_none());
    }

    #[test]
    fn witnessing_depth_roundtrips_all_registered_values() {
        for i in 0u8..=5 {
            let d = WitnessingDepth::from_u8(i).expect("registered");
            assert_eq!(d.to_u8(), i);
        }
        assert!(WitnessingDepth::from_u8(6).is_none());
    }

    #[test]
    fn attestor_relationship_roundtrips_all_registered_values() {
        for i in 0u8..=6 {
            let r = AttestorRelationship::from_u8(i).expect("registered");
            assert_eq!(r.to_u8(), i);
        }
        assert!(AttestorRelationship::from_u8(7).is_none());
    }

    #[test]
    fn source_type_requires_zero_source_hash_matrix() {
        assert!(SourceType::Unknown.requires_zero_source_hash());
        assert!(SourceType::SelfReported.requires_zero_source_hash());
        for i in 2u16..=14 {
            let st = SourceType::from_u16(i).unwrap();
            assert!(!st.requires_zero_source_hash(), "{:?} should permit non-zero source_hash", st);
        }
    }

    #[test]
    fn spec_version_roundtrips_and_unknown_is_none() {
        assert_eq!(SpecVersion::from_u16(1), Some(SpecVersion::V01Preview));
        assert_eq!(SpecVersion::from_u16(2), Some(SpecVersion::V01Final));
        assert_eq!(SpecVersion::V01Preview.to_u16(), 1);
        assert_eq!(SpecVersion::V01Final.to_u16(), 2);
        assert!(SpecVersion::from_u16(0).is_none());
        assert!(SpecVersion::from_u16(3).is_none());
        assert!(SpecVersion::from_u16(65535).is_none());
    }

    // ── Legacy v0.1-preview compatibility ──────────────────────────

    #[test]
    fn legacy_canonical_bytes_still_208() {
        // Verify that the legacy struct produces the historically-published
        // 208-byte layout so old signatures remain verifiable.
        let f = LegacyAttestationFieldsV01Preview {
            signer: [0xA1; HASH_LEN],
            subject: [0xA2; HASH_LEN],
            activity_hash: [0xA3; HASH_LEN],
            data_hash: [0xA4; HASH_LEN],
            witness_for: [0xA5; HASH_LEN],
            signer_asserted_at: 0x0102030405060708_i64,
            retention_hint: 0x1112131415161718_i64,
            nonce: [0xA8; HASH_LEN],
        };
        let b = f.canonical_bytes();
        assert_eq!(b.len(), 208);

        // Spot-check the old layout offsets (no spec_version prefix).
        assert_eq!(&b[0..32], &[0xA1u8; 32]);
        assert_eq!(&b[176..208], &[0xA8u8; 32]);
    }
}
