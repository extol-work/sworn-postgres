# sworn-postgres, Scope

## In scope for v0.1

The narrow reference implementation, sized to ship alongside SWORN v0.1.

### API surface

Five endpoints, all defined in the OpenAPI spec that ships alongside this doc as [openapi.yaml](./openapi.yaml). The OpenAPI contract is frozen for v0.1.

- `POST /attestations`: create a new attestation. Signer supplies canonical payload plus signature; server verifies signature, computes hash, stores record, returns `attestation_id`. Idempotency: if a client submits an attestation whose `(signer, subject, activity_hash, data_hash, nonce)` tuple already exists, the server returns HTTP 409 Conflict with the existing `attestation_id` in the response body. This is deliberately noisier than production would be; the reference wants implementers to notice the case.
- `GET /attestations/{id}`: metadata-only. Returns signer pubkey, subject, activity type, hashes, notarization timestamp, retention hint, signature. No payload.
- `POST /attestations/{id}/disclosure-tokens`: signer mints a single-use, time-limited disclosure token. Requires the caller to prove control of the attestation's signing key by signing a canonical issuance message (81 bytes, prefixed with a domain separator so a leaked attestation signature cannot be replayed as a token-issuance signature). Idempotent by `(attestation_id, issuance_nonce)`.
- `POST /attestations/{id}/disclose`: redeem a disclosure token. Marks the token consumed atomically and returns the payload plus the server-computed `data_hash` for independent re-verification. Second redemption returns 410 Gone.
- `GET /verify/{id}`: pure verification. Reloads the record, reconstructs canonical bytes, re-verifies the signature. Returns `valid: true|false` plus reason. No side effects.

Refused endpoints (deliberately):

- `GET /attestations?signer=X` (list-by-signer)
- `GET /attestations?subject=X` (list-by-subject)
- `GET /attestations` (bulk enumeration)

These refusals express the spec's disclosure discipline (shown-never-pulled). The spec's Layer 5 required text will formalize this constraint.

Rate limits (in-memory per-IP token bucket): default 60 req/min; `POST /attestations/{id}/disclose` capped at 6 req/min because it returns payload bytes and is the endpoint a hostile enumerator would hammer if they got a leaked token. Production deploys front this with a real limiter (nginx / envoy / cloud provider).

### CLI

Wraps the API. Primary developer surface. Ships in v0.1:

- `sworn keygen`: generate an Ed25519 keypair
- `sworn attest --key <keyfile> --subject <hash|uri> --activity-type <uri> --payload <file|-> [--out sig.json]`: sign and submit
- `sworn verify <file|attestation_id>`: verify against a running sworn-postgres instance (offline for files, over HTTP for UUIDs)
- `sworn disclosure-token --id <attestation_id> --key <keyfile> [--expires-in secs]`: signer mints a disclosure token
- `sworn disclose --id <attestation_id> --token <token>`: redeem a token, print the payload JSON to stdout

Quickstart target: from install to first verified attestation in five shell commands or fewer.

### Storage

Postgres schema:

- `attestations`: (id, signer_pubkey, subject, activity_type_uri, activity_hash, data_hash, witness_for, signer_asserted_at, notarized_at, retention_hint, nonce, signature, payload nullable)
- `disclosure_tokens`: (token, attestation_id, issued_at, expires_at, redeemed_at nullable, issuance_nonce). Unique index on `(attestation_id, issuance_nonce)` guarantees idempotent token issuance under retry.

Timestamp policy: `notarized_at` is the trust-relevant timestamp, set by the Postgres INSERT time from operating system clock. `signer_asserted_at` is informational only, from the signer's own claim, and is never used by verification logic. This mirrors OPEN_QUESTIONS.md Q2 in the spec.

Append-only enforced at the schema level: no UPDATE, no DELETE on `attestations` after insertion, with one exception. A payload-reclaim job nulls the `payload` column past `notarized_at + retention_hint` while preserving every other column. The hash and signature remain durable; only the payload becomes undisclosable. This demonstrates that retention is a UX and cost convenience, not a validity property.

Revocation is a new attestation with `activity_type_uri = "sworn.dev/v1/revocation"` referencing the target. No mutation of the target row.

Convenience view: `signers_seen` materializes `SELECT DISTINCT signer_pubkey FROM attestations`. Not required by spec; every implementer will want it, so having it in the reference documents the pattern.

### Docker Compose

`docker compose up` from a fresh clone stands up Postgres plus the API plus a preloaded example vocabulary (one activity type). No manual migration, no seeding step, no external services.

## Out of scope for v0.1

- **Merkle batches:** deferred to v0.2. Batch commit and inclusion proofs are a cost-driven pattern that fits Extol's SAS-backed implementation but add implementation weight to a Postgres reference without demonstrating anything Postgres reveals uniquely. Cross-substrate conformance testing for batches will land when we have two implementations that actually need them.
- **Browser UI:** parallel Titania track, non-blocking.
- **Blockchain notarization:** this reference implementation is Postgres-only by design. The Extol/SAS binding lives in the SWORN spec's Solana appendix, not this repo.
- **Multi-tenancy or auth:** single-tenant, no user accounts. Signers are identified by their pubkey; that's the entire identity model.
- **Payload storage beyond a `payload` blob column:** no S3, no IPFS, no content addressing beyond the on-record hash.
- **Extended vocabularies:** one example activity type. Users bring their own via the URI-based extension mechanism.
- **Production hardening:** TLS termination, secret management, backups, HA. Reference implementation, not deploy target.
- **Any Extol-specific mechanic:** HMAC-KMS derivation, invisible wallets, √s voting, token issuance, alpha slider. See `EXTOL_SWORN_ADDITIONS.md` in the strategy folder for what belongs in Extol's implementation instead.

## Language

Rust. The `verify/` package is designed to be embeddable elsewhere (WASM for a browser UI, FFI for other language bindings), and Rust gives that property with the fewest tradeoffs. Contribution barrier is slightly higher than Node or Go, but the audience for a reference implementation is other implementers, not casual contributors.

## Testing

- Unit tests for the `verify/` package (pure crypto, deterministic)
- Integration tests for the HTTP API (docker-compose harness)
- **Conformance test suite** that any SWORN implementation should be able to run against itself. Ships in this repo as `conformance/`; the spec repo references it as the acceptance criterion for §10 (Conformance).

Conformance suite is the load-bearing testing artifact. Any implementation (Extol's SAS-backed production system, someone else's Ethereum binding, a hypothetical git-anchored implementation) should be able to pass the same tests.

## What "reference" means here

Not "canonical implementation everyone should build on." A reference is what you compare against when you're writing your own. Two properties:

1. **Correctness reference:** if the spec says something and this implementation does something else, the implementation is wrong until proven otherwise.
2. **Minimality reference:** if this implementation doesn't need a feature to conform, then the spec doesn't require the feature. Anything above and beyond is an implementer's choice.

Extol's production implementation ships more than this reference. That's expected. This reference is the floor, not the ceiling.
