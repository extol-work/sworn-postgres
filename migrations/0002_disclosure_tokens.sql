-- Disclosure tokens: single-use, time-limited credentials that authorize
-- retrieval of a specific attestation's payload via POST /disclose.
--
-- The signer of an attestation issues these on request. Verifiers cannot
-- enumerate; they must be handed a token out-of-band. This is the reference
-- implementation's expression of the spec's shown-never-pulled discipline.

CREATE TABLE disclosure_tokens (
    token           UUID       PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id  UUID       NOT NULL REFERENCES attestations(id) ON DELETE CASCADE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    redeemed_at     TIMESTAMPTZ,

    -- The nonce the signer included in their signed token-issuance request.
    -- Enforced unique per attestation so the same signed request can't be
    -- replayed to issue multiple tokens.
    issuance_nonce  BYTEA      NOT NULL,

    CONSTRAINT issuance_nonce_len CHECK (octet_length(issuance_nonce) = 32),
    CONSTRAINT one_token_per_issuance UNIQUE (attestation_id, issuance_nonce)
);

CREATE INDEX disclosure_tokens_by_attestation ON disclosure_tokens (attestation_id);
CREATE INDEX disclosure_tokens_by_expiry      ON disclosure_tokens (expires_at)
    WHERE redeemed_at IS NULL;
