# Multi-stage build for the sworn-api HTTP service.
#
# Not optimized for cache reuse yet; will iterate in a later CP if needed.
# Everything is built from source inside the image for reproducibility.

FROM rust:1.83-slim-bookworm AS builder

WORKDIR /src

# System deps for TLS-linked crates (rustls uses ring on some paths).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY verify ./verify
COPY store ./store
COPY api ./api
COPY cli ./cli
COPY migrations ./migrations

RUN cargo build --release --bin sworn-api

# ── Runtime image ────────────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin sworn

COPY --from=builder /src/target/release/sworn-api /usr/local/bin/sworn-api
COPY --from=builder /src/migrations /migrations

USER sworn
EXPOSE 8080

ENV DATABASE_URL="postgres://sworn:sworn@postgres:5432/sworn" \
    BIND="0.0.0.0:8080" \
    RUST_LOG="info,sqlx=warn"

# The api binary reads migrations from `../migrations` relative to CWD (the
# sqlx::migrate! path in store/). We run from /, so /migrations resolves.
WORKDIR /
CMD ["sworn-api"]
