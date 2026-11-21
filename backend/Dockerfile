# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# 1. Builder Stage: Compile all workspace crates and release binaries
# ------------------------------------------------------------------------------
FROM rust:bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace dependency manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/shared-types/Cargo.toml crates/shared-types/
COPY crates/core-domain/Cargo.toml crates/core-domain/
COPY crates/infra/Cargo.toml crates/infra/
COPY crates/api-server/Cargo.toml crates/api-server/
COPY crates/scan-worker/Cargo.toml crates/scan-worker/
COPY tests/e2e/Cargo.toml tests/e2e/

# Create stub source files to pre-build and cache external dependencies
RUN mkdir -p \
    crates/shared-types/src \
    crates/core-domain/src \
    crates/infra/src/db \
    crates/infra/migrations \
    crates/api-server/src \
    crates/scan-worker/src \
    tests/e2e/src && \
    echo "pub fn dummy() {}" > crates/shared-types/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/core-domain/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/infra/src/lib.rs && \
    echo "-- dummy" > crates/infra/migrations/0001_initial_schema.sql && \
    echo "pub fn dummy() {}" > crates/infra/src/db/mod.rs && \
    echo "fn main() {}" > crates/api-server/src/main.rs && \
    echo "pub fn dummy() {}" > crates/api-server/src/lib.rs && \
    echo "fn main() {}" > crates/scan-worker/src/main.rs && \
    echo "pub fn dummy() {}" > crates/scan-worker/src/lib.rs && \
    echo "fn main() {}" > tests/e2e/src/main.rs && \
    echo "pub fn dummy() {}" > tests/e2e/src/lib.rs

# Build dependencies only (layer cached)
RUN cargo build --release -p api-server -p scan-worker || true

# Copy full source tree
COPY crates/ crates/
COPY tests/ tests/

# Invalidate dummy artifacts and build release binaries
RUN touch \
    crates/shared-types/src/lib.rs \
    crates/core-domain/src/lib.rs \
    crates/infra/src/lib.rs \
    crates/api-server/src/main.rs \
    crates/scan-worker/src/main.rs && \
    cargo build --release -p api-server -p scan-worker

# ------------------------------------------------------------------------------
# 2. Base Runtime Stage: Minimal secure Debian Bookworm image
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -U appsec

WORKDIR /app

# ------------------------------------------------------------------------------
# Target: api-server
# ------------------------------------------------------------------------------
FROM runtime-base AS api-server

COPY --from=builder /app/target/release/api-server /usr/local/bin/api-server
USER appsec

ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/v1/auth/me || exit 1

ENTRYPOINT ["/usr/local/bin/api-server"]

# ------------------------------------------------------------------------------
# Target: scan-worker
# ------------------------------------------------------------------------------
FROM runtime-base AS scan-worker

COPY --from=builder /app/target/release/scan-worker /usr/local/bin/scan-worker
USER appsec

ENTRYPOINT ["/usr/local/bin/scan-worker"]

