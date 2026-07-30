# sworn-postgres

Reference implementation of [SWORN v0.1](https://github.com/extol-work/sworn). Postgres + Ed25519. No blockchain required.

## Status

**Pre-alpha.** Scaffold only. Implementation lands per [SCOPE.md](./SCOPE.md).

## What this is

A working implementation of the SWORN specification that anyone can run locally, understand end-to-end in an afternoon, and use as the basis for their own implementation.

Deliberately minimal:

- **Storage:** Postgres. Nothing exotic.
- **Signing:** Ed25519. Standard library, no crypto novelty.
- **Notarization:** SHA256 hashes of attestation records stored in a Postgres table, with append-only semantics enforced by the schema. No blockchain.
- **API:** HTTP + OpenAPI. Curl-friendly. No client SDK required to attest or verify.
- **Interface:** CLI (`sworn`) wrapping the API. Seven lines to a first verified attestation.

## What this is not

- Production infrastructure for a paid product (that's Extol's job)
- The only conforming implementation (that's the point of the spec)
- A demonstration of blockchain notarization (that's [Appendix A of the spec](https://github.com/extol-work/sworn/blob/main/SPEC.md#appendix-a) — Extol's SAS-based binding)

## Quickstart (once implementation lands)

```bash
# Coming soon:
docker compose up
sworn keygen > mykey.pem
sworn attest --key mykey.pem --subject "sha256:abcdef..." --payload '{"kind":"endorsement"}'
sworn verify latest.sworn.json
```

## Architecture at a glance

Four packages, one substrate:

- `api/` — HTTP server implementing the SWORN Layer 5 endpoints
- `cli/` — command-line wrapper on top of the API (this is the primary developer surface)
- `store/` — Postgres schema + queries for attestation records and Merkle batches
- `verify/` — pure verification logic (no DB, no HTTP — safe to embed elsewhere)

Language TBD (see [SCOPE.md §Language](./SCOPE.md#language)).

## License

Apache 2.0.

## See also

- [SWORN specification](https://github.com/extol-work/sworn)
- [SCOPE.md](./SCOPE.md) — what's in v0.1, what's not, why
- [ROADMAP.md](./ROADMAP.md) — target dates and dependency chain
