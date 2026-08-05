//! Emit reference test vectors for SWORN v0.1-final.
//!
//! Each vector is a JSON object with:
//!   * `notes`: what edge case the vector exercises
//!   * `input_fields`: the AttestationFields values as JSON
//!   * `expected_canonical_bytes_hex`: the 248-byte canonical byte sequence
//!   * `expected_signature_hex`: Ed25519 signature over those bytes
//!   * `signer_secret_seed_hex`: the 32-byte Ed25519 seed used to sign
//!     (deterministic so the vector is reproducible)
//!
//! Vectors use fixed seeds so any implementation reproducing them can compare
//! byte-for-byte. Signature values are deterministic under RFC 8032 PureEdDSA
//! (Ed25519 signatures are a function of the seed and message, no randomness).
//!
//! Usage:
//!   cargo run -p sworn-verify --example emit_vectors > out.json
//!
//! Then split into individual .json files under fixtures/attestations/v0.1-final/
//! or land the whole file as v0.1-final-vectors.json.

use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use serde_json::json;
use sworn_verify::{
    sign, AttestationFields, AttestorRelationship, Bytes32, SourceType, WitnessingDepth,
    HASH_LEN,
};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn fixed_seed(byte: u8) -> [u8; SECRET_KEY_LENGTH] {
    [byte; SECRET_KEY_LENGTH]
}

/// Emit one vector. `notes` describes what edge case is being exercised.
fn emit_vector(
    name: &str,
    notes: &str,
    seed_byte: u8,
    build: impl FnOnce(Bytes32) -> AttestationFields,
) -> serde_json::Value {
    let seed = fixed_seed(seed_byte);
    let sk = SigningKey::from_bytes(&seed);
    let pk: [u8; 32] = sk.verifying_key().to_bytes();
    let fields = build(pk);
    let bytes = fields.canonical_bytes();
    let sig = sign(&sk, &fields).expect("sign");

    // Verify roundtrip locally so the vector we emit is guaranteed to be valid.
    sworn_verify::verify(&fields, &sig).expect("self-verify");

    json!({
        "name": name,
        "notes": notes,
        "spec_version": 2,
        "input_fields": {
            "signer_hex": hex_encode(&fields.signer),
            "subject_hex": hex_encode(&fields.subject),
            "activity_hash_hex": hex_encode(&fields.activity_hash),
            "data_hash_hex": hex_encode(&fields.data_hash),
            "witness_for_hex": hex_encode(&fields.witness_for),
            "source_hash_hex": hex_encode(&fields.source_hash),
            "source_type": fields.source_type.to_u16(),
            "confidence": fields.confidence,
            "witnessing_depth": fields.witnessing_depth.to_u8(),
            "attestor_relationship": fields.attestor_relationship.to_u8(),
            "signer_asserted_at": fields.signer_asserted_at,
            "retention_hint": fields.retention_hint,
            "nonce_hex": hex_encode(&fields.nonce),
        },
        "signer_secret_seed_hex": hex_encode(&seed),
        "expected_canonical_bytes_hex": hex_encode(&bytes),
        "expected_canonical_bytes_len": bytes.len(),
        "expected_signature_hex": hex_encode(&sig),
    })
}

fn main() {
    // Vector 1: happy-path attestation with all provenance fields filled.
    // ORCID-sourced authorship claim.
    let v1 = emit_vector(
        "orcid_authorship_happy_path",
        "ORCID-sourced authorship attestation. High confidence, computed match \
         (name-anchored against ORCID record), self-attested (subject is signer). \
         Baseline v0.1-final case with every field non-zero.",
        0x01,
        |signer| AttestationFields {
            signer,
            subject: [0x02; HASH_LEN],
            activity_hash: sworn_verify::sha256(b"work.extol.attestation/v1/authorship"),
            data_hash: sworn_verify::sha256(br#"{"paper_doi":"10.1234/example"}"#),
            witness_for: [0u8; HASH_LEN],
            // ORCID canonicalization: SHA-256 of the 19-char upper-hyphen form.
            source_hash: sworn_verify::sha256(b"0000-0002-1825-0097"),
            source_type: SourceType::Orcid,
            confidence: 9500,
            witnessing_depth: WitnessingDepth::ComputedMatch,
            attestor_relationship: AttestorRelationship::Self_,
            signer_asserted_at: 1_780_000_000,
            retention_hint: -1,
            nonce: [0x08; HASH_LEN],
        },
    );

    // Vector 2: self-attestation with zero source_hash and witness_for.
    // Exercises the sourceless path where source_type = SelfReported requires
    // source_hash = 32 zero bytes.
    let v2 = emit_vector(
        "self_reported_sourceless",
        "Self-reported contribution with no external source. source_hash and \
         witness_for both 32 zero bytes. source_type = SelfReported (1), \
         witnessing_depth = SelfAsserted (5), attestor_relationship = Self (1). \
         Exercises the zero-source-hash requirement from spec §2.4.",
        0x02,
        |signer| AttestationFields {
            signer,
            subject: signer, // subject is signer for self-attestation
            activity_hash: sworn_verify::sha256(
                b"credit.niso.org/contributor-roles/data-curation",
            ),
            data_hash: sworn_verify::sha256(br#"{"contribution_degree":"lead"}"#),
            witness_for: [0u8; HASH_LEN],
            source_hash: [0u8; HASH_LEN],
            source_type: SourceType::SelfReported,
            confidence: 8000,
            witnessing_depth: WitnessingDepth::SelfAsserted,
            attestor_relationship: AttestorRelationship::Self_,
            signer_asserted_at: 1_780_000_100,
            retention_hint: -1,
            nonce: [0x11; HASH_LEN],
        },
    );

    // Vector 3: peer-witnessed physically-observed attestation.
    // Highest-trust witnessing pattern.
    let v3 = emit_vector(
        "peer_witnessed_physical",
        "Peer-witnessed contribution with physical observation. source_type = \
         PeerWitnessed (9), witnessing_depth = PhysicallyObserved (1), \
         attestor_relationship = Peer (3). source_hash is SHA-256 of the peer's \
         signer pubkey (a distinct 32-byte pattern in this vector).",
        0x03,
        |signer| {
            // Simulate a distinct peer pubkey (the party being witnessed *for*
            // in some workflows, or the peer whose observation is being cited).
            let peer_pubkey: [u8; 32] = [0xEE; HASH_LEN];
            AttestationFields {
                signer,
                subject: peer_pubkey, // attesting about the peer
                activity_hash: sworn_verify::sha256(
                    b"work.extol.attestation/v1/contribution",
                ),
                data_hash: sworn_verify::sha256(br#"{"note":"saw the work"}"#),
                witness_for: [0u8; HASH_LEN],
                // source_hash = SHA-256(peer's pubkey) per spec §9.2 for
                // source_type = PeerWitnessed.
                source_hash: sworn_verify::sha256(&peer_pubkey),
                source_type: SourceType::PeerWitnessed,
                confidence: 10_000,
                witnessing_depth: WitnessingDepth::PhysicallyObserved,
                attestor_relationship: AttestorRelationship::Peer,
                signer_asserted_at: 1_780_000_200,
                retention_hint: -1,
                nonce: [0x33; HASH_LEN],
            }
        },
    );

    // Vector 4: backfilled attestation with degraded confidence and
    // unspecified witnessing_depth. Represents a v0.1-preview row that
    // has been backfilled with best-effort provenance during the migration.
    let v4 = emit_vector(
        "backfilled_migration",
        "Backfilled attestation from a legacy v0.1-preview record. Provenance \
         was reconstructed during migration; witnessing_depth is Unspecified \
         (0), attestor_relationship is Unknown (0), confidence is capped low \
         (5000 = 50%) to reflect the epistemic degradation. IMPORTANT: this \
         is still a valid v0.1-final signature over v0.1-final bytes; the row \
         is legitimate testimony even though its provenance is best-effort.",
        0x04,
        |signer| AttestationFields {
            signer,
            subject: [0x22; HASH_LEN],
            activity_hash: sworn_verify::sha256(
                b"work.extol.attestation/v1/participation",
            ),
            data_hash: sworn_verify::sha256(br#"{"event_id":"legacy-abc"}"#),
            witness_for: [0u8; HASH_LEN],
            source_hash: [0u8; HASH_LEN], // no known external source
            source_type: SourceType::SelfReported,
            confidence: 5000, // deliberately low: backfilled provenance
            witnessing_depth: WitnessingDepth::Unspecified,
            attestor_relationship: AttestorRelationship::Unknown,
            signer_asserted_at: 1_770_000_000, // older timestamp
            retention_hint: 90 * 24 * 60 * 60, // 90 days
            nonce: [0x44; HASH_LEN],
        },
    );

    // Vector 5: edge case, all-zero attestor_relationship and witnessing_depth,
    // source_type = Unknown. Tests the zero-value discipline.
    let v5 = emit_vector(
        "all_zero_provenance_edge_case",
        "Edge-case attestation where source_type = Unknown (0), \
         witnessing_depth = Unspecified (0), attestor_relationship = Unknown \
         (0), confidence = 0. Legitimate for backfilled rows or explicit \
         'I decline to characterize' cases. source_hash MUST be 32 zero \
         bytes for source_type Unknown.",
        0x05,
        |signer| AttestationFields {
            signer,
            subject: [0x99; HASH_LEN],
            activity_hash: sworn_verify::sha256(b"work.extol.attestation/v1/participation"),
            data_hash: sworn_verify::sha256(b"{}"),
            witness_for: [0u8; HASH_LEN],
            source_hash: [0u8; HASH_LEN],
            source_type: SourceType::Unknown,
            confidence: 0,
            witnessing_depth: WitnessingDepth::Unspecified,
            attestor_relationship: AttestorRelationship::Unknown,
            signer_asserted_at: 1_780_000_400,
            retention_hint: 0,
            nonce: [0x55; HASH_LEN],
        },
    );

    let vectors = json!({
        "spec_version": 2,
        "spec_version_name": "v0.1-final",
        "canonical_bytes_length": 248,
        "signature_algorithm": "Ed25519 PureEdDSA (RFC 8032)",
        "purpose": "Reference test vectors per SPEC §10.4. Any conforming \
                    SWORN implementation MUST reproduce expected_canonical_bytes_hex \
                    and expected_signature_hex byte-for-byte given the same \
                    input_fields and signer_secret_seed_hex.",
        "vectors": [v1, v2, v3, v4, v5],
    });

    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
