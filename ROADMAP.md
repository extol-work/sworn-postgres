# sworn-postgres — Roadmap

Target: shipping alongside SWORN v0.1 in October 2026.

## Week 1 (Aug 4–8)

- [ ] Language decision (Rust / TS / Go) landed with initial scaffolding PR
- [ ] Repo structure created: `api/`, `cli/`, `store/`, `verify/`, `conformance/`
- [ ] OpenAPI stub — endpoint names, request/response schemas, no logic yet
- [ ] Postgres schema — DDL only, tested via docker-compose migration
- [ ] Ed25519 keygen + sign + verify in the `verify/` package (pure, no DB, no HTTP)

## Week 2 (Aug 11–15)

- [ ] `POST /attestations` end-to-end (sign → verify → store)
- [ ] `GET /attestations/{id}` metadata endpoint
- [ ] `GET /verify/{id}` pure verification
- [ ] CLI `keygen`, `attest`, `verify` — first three commands
- [ ] First integration test: seven-line quickstart passes

## Week 3 (Aug 18–22)

- [ ] Merkle batch commit and inclusion proof
- [ ] `POST /batches` + `sworn batch --commit`
- [ ] Revocation-by-additive-attestation flow
- [ ] Conformance test skeleton — first three tests
- [ ] **OpenAPI spec frozen** (this is Titania's dependency for Layer 5 UI work)

## Week 4 (Aug 25–29)

- [ ] Disclosure token generation and redemption
- [ ] `POST /attestations/{id}/disclose` + `sworn disclose`
- [ ] Rate limiting on all endpoints
- [ ] Refused-endpoint tests (list-by-signer, list-by-subject, bulk export all return 400)
- [ ] `docker compose up` smoke test in CI

## Week 5 (Sep 1–5)

- [ ] Full conformance suite (10–15 tests)
- [ ] Documentation pass: README quickstart, API reference, CLI reference
- [ ] `brew install sworn` recipe (if we go Go/Rust) or `npx sworn` (if we go TS)
- [ ] First cross-implementation test: verify a Postgres-signed attestation from Extol's SAS-backed verifier (proves substrate-agnostic verification works)

## Weeks 6–8 (Sep 8–26) — buffer + polish

- [ ] Bug fixes surfaced during dogfooding
- [ ] Performance smoke test (10K attestations, batch of 1K, verify latency)
- [ ] Security review of the `verify/` package (Ken + Charon + one external if we can get it)
- [ ] Publication-ready: repo README, CONTRIBUTING, examples, screenshots (or CLI transcripts) for launch

## Ship — Week 9 (Oct 6–10, target)

- [ ] Coordinated release with SWORN spec v0.1
- [ ] RFC intro publishes with a working demo
- [ ] Launch attestations captured — reviewers attest to spec commits from a running sworn-postgres

## Post-launch (October–November)

- [ ] Browser UI (Titania, on top of the frozen OpenAPI contract)
- [ ] Extended examples: validator disclosure schema, endorsement flows
- [ ] First external implementation feedback loops

## Dependencies

**Blocks:**
- SWORN v0.1 launch — no shipping the spec without a working reference implementation.
- Titania's Layer 5 UI work — needs the OpenAPI contract frozen at end of Week 3.

**Blocked by:**
- SWORN Layer 1 + 2 normative text — need the wire format finalized before I can implement it correctly. Charon owns both, so this is coordinated on the same calendar.
- Language decision (Week 1) — small, resolves itself once I start scaffolding.
