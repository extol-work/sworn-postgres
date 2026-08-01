-- SWORN reference storage. Append-only by convention (no UPDATE/DELETE paths
-- in the application). All hash/pubkey/signature columns are stored as raw
-- BYTEA and validated on read for exact byte width.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE attestations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Signed content (§2.1). Every field here goes into the canonical byte
    -- sequence (§3.1) that the signature covers.
    signer_pubkey       BYTEA  NOT NULL,
    subject             BYTEA  NOT NULL,
    activity_type_uri   TEXT   NOT NULL,
    activity_hash       BYTEA  NOT NULL,
    data_hash           BYTEA  NOT NULL,
    witness_for         BYTEA  NOT NULL,
    signer_asserted_at  BIGINT NOT NULL,
    retention_hint      BIGINT NOT NULL,
    nonce               BYTEA  NOT NULL,

    -- Signature over canonical_bytes.
    signature           BYTEA NOT NULL,

    -- Server-observed timestamp. Trust-relevant per OPEN_QUESTIONS Q2.
    notarized_at        BIGINT NOT NULL,

    -- Original payload (whose SHA-256 canonicalization equals data_hash).
    -- Nullable so a future reclaim job can clear it while keeping the row.
    payload             JSONB,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Byte-width invariants. Cheap and catches driver bugs immediately.
    CONSTRAINT signer_pubkey_len CHECK (octet_length(signer_pubkey) = 32),
    CONSTRAINT subject_len       CHECK (octet_length(subject)       = 32),
    CONSTRAINT witness_for_len   CHECK (octet_length(witness_for)   = 32),
    CONSTRAINT nonce_len         CHECK (octet_length(nonce)         = 32),
    CONSTRAINT activity_hash_len CHECK (octet_length(activity_hash) = 32),
    CONSTRAINT data_hash_len     CHECK (octet_length(data_hash)     = 32),
    CONSTRAINT signature_len     CHECK (octet_length(signature)     = 64),

    -- Idempotency (SCOPE.md §API surface). Same content + same nonce = same
    -- attestation. Handler returns 409 with the existing id on collision.
    CONSTRAINT unique_attestation UNIQUE
        (signer_pubkey, subject, activity_hash, data_hash, nonce)
);

-- Convenience view. Named in SCOPE.md.
CREATE OR REPLACE VIEW signers_seen AS
SELECT
    signer_pubkey,
    MIN(notarized_at) AS first_seen,
    MAX(notarized_at) AS last_seen,
    COUNT(*)          AS attestation_count
FROM attestations
GROUP BY signer_pubkey;

-- Deliberately NO index on signer_pubkey or subject. Enumeration by those
-- keys is a refused operation at the API layer; no reason to make it fast.
