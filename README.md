# sworn-postgres

Reference implementation of [SWORN](https://github.com/extol-work/sworn). Postgres + Ed25519. No blockchain required.

## Status

**Pre-alpha.** Working end-to-end signing, notarization, and verification. Merkle
batching and disclosure tokens are on the roadmap, not yet wired. See
[SCOPE.md](./SCOPE.md) for what's in v0.1.

## What this is

A working implementation of the SWORN specification that anyone can run locally, understand end-to-end in an afternoon, and use as the basis for their own implementation.

Deliberately minimal:

- **Storage:** Postgres. Nothing exotic.
- **Signing:** Ed25519. Standard library, no crypto novelty.
- **Notarization:** SHA256 hashes of attestation records stored in a Postgres table, with append-only semantics enforced by the schema. No blockchain.
- **API:** HTTP + OpenAPI. Curl-friendly. No client SDK required to attest or verify.
- **Interface:** CLI (`sworn`) wrapping the API. Five lines to a first verified attestation.

## What this is not

- Production infrastructure for a paid product
- The only conforming implementation (that's the point of the spec)
- A demonstration of blockchain notarization (see the SWORN spec appendix on Solana / SAS binding, once that appendix drafts)

## Quickstart

Requires Docker (for Postgres + the API) and Rust (to build the CLI).

```bash
# 1. Build the CLI (one-time; installs to ~/.cargo/bin/sworn)
cargo install --path cli

# 2. Bring up Postgres + sworn-api
docker compose up -d

# 3. Attest and verify
sworn keygen > my.key
echo '{"kind":"endorsement","note":"hello"}' > hello.json
sworn attest \
    --key my.key \
    --subject "sha256:$(printf 'my-subject' | shasum -a 256 | awk '{print $1}')" \
    --activity-type sworn.dev/v1/endorsement \
    --payload hello.json \
    --out attestation.json
sworn verify attestation.json
```

Five lines to a first verified attestation. Every operation is expressible via
curl if you prefer the wire directly; see `api/src/main.rs` for the OpenAPI
shape.

Offline verification (`sworn verify <file>`) works without contacting the API.
Verification by id (`sworn verify <uuid>`) hits `GET /verify/:id` on a running
sworn-api.

## Architecture at a glance

Four packages, one substrate:

- `api/`: HTTP server implementing the SWORN Layer 5 endpoints
- `cli/`: command-line wrapper on top of the API (primary developer surface)
- `store/`: Postgres schema and queries for attestation records
- `verify/`: pure verification logic (no DB, no HTTP), safe to embed elsewhere

Written in Rust. The `verify/` package is designed to be embeddable via FFI or WASM so other implementations can share the same verifier.

## License

Apache 2.0.

## See also

- [SWORN specification](https://github.com/extol-work/sworn)
- [SCOPE.md](./SCOPE.md): what's in v0.1, what's not, why
