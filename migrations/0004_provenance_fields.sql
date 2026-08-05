-- Migration 0004: Layer 1 v2 provenance fields for SWORN v0.1-final.
--
-- Adds the five provenance columns and spec_version marker per SPEC §2.5,
-- §3.1. Additive-only per IMPLEMENTATION_NOTES.md: existing rows are marked
-- spec_version = 1 (v0.1-preview, deprecated), new rows use spec_version = 2
-- (v0.1-final).
--
-- All new columns have defaults chosen so existing v0.1-preview rows remain
-- interpretable:
--   spec_version           = 1  (v0.1-preview marker)
--   source_hash            = 32 zero bytes (matches SelfReported semantics)
--   source_type            = 1  (SelfReported)
--   confidence             = 0  (no signer-asserted confidence available)
--   witnessing_depth       = 0  (Unspecified)
--   attestor_relationship  = 0  (Unknown)
--
-- After this migration deploys, new attestations submitted via /attestations
-- MUST supply the provenance fields and MUST be signed against v0.1-final
-- canonical bytes (spec_version = 2). Historical rows retain their v0.1-preview
-- signatures which verify against the 208-byte legacy layout.
--
-- Do NOT backfill provenance on historical rows without marking them
-- provenance_origin = 'backfilled'. See IMPLEMENTATION_NOTES.md.

ALTER TABLE attestations
    ADD COLUMN spec_version           SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN source_hash            BYTEA    NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
    ADD COLUMN source_type            SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN confidence             SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN witnessing_depth       SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN attestor_relationship  SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN provenance_origin      TEXT     NOT NULL DEFAULT 'original';

-- Byte-width invariant on the new source_hash column.
ALTER TABLE attestations
    ADD CONSTRAINT source_hash_len CHECK (octet_length(source_hash) = 32);

-- Enum bounds: registry values are defined by SPEC §9.2, §9.3, §9.4.
-- Ranges here match v0.1-final registrations; a future spec_version bump
-- with more values will require an ALTER on these CHECK constraints in a
-- subsequent migration.
ALTER TABLE attestations
    ADD CONSTRAINT spec_version_bounds
        CHECK (spec_version IN (1, 2)),
    ADD CONSTRAINT source_type_bounds
        CHECK (source_type BETWEEN 0 AND 14),
    ADD CONSTRAINT confidence_bounds
        CHECK (confidence BETWEEN 0 AND 10000),
    ADD CONSTRAINT witnessing_depth_bounds
        CHECK (witnessing_depth BETWEEN 0 AND 5),
    ADD CONSTRAINT attestor_relationship_bounds
        CHECK (attestor_relationship BETWEEN 0 AND 6),
    ADD CONSTRAINT provenance_origin_values
        CHECK (provenance_origin IN ('original', 'backfilled'));

-- Zero-source-hash requirement for SelfReported (1) and Unknown (0), per
-- SPEC §2.4. A non-zero source_hash paired with a sourceless source_type
-- would misrepresent the signer's claim and produce an unverifiable signature.
ALTER TABLE attestations
    ADD CONSTRAINT sourceless_zero_hash
        CHECK (
            source_type NOT IN (0, 1)
            OR source_hash = '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
        );

-- After this migration deploys, flip the default so new rows land as
-- v0.1-final without callers having to specify. Existing rows retain their
-- migration-time default of 1.
ALTER TABLE attestations
    ALTER COLUMN spec_version SET DEFAULT 2;
