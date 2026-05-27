# syntax=docker/dockerfile:1

FROM rust:1.95-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
COPY tests ./tests

RUN touch src/main.rs && cargo build --release && \
    strip target/release/squid-go && \
    mkdir -p /out/etc /out/var/lib/squid-go && \
    cp target/release/squid-go /out/squid-go && \
    echo 'nonroot:x:65532:65532:nonroot:/var/lib/squid-go:/sbin/nologin' > /out/etc/passwd && \
    echo 'nonroot:x:65532:' > /out/etc/group

FROM debian:bookworm-slim

# CA certificates are required at runtime: rustls-acme makes outbound HTTPS
# calls to Let's Encrypt.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Default storage path for the ACME account key and issued certificates.
# Override the env var to use a different location.
ENV CERT_STORAGE_PATH=/var/lib/squid-go

COPY --from=builder /out/etc/passwd /etc/passwd
COPY --from=builder /out/etc/group /etc/group
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/var/lib/squid-go /var/lib/squid-go
COPY --from=builder /out/squid-go /squid-go

WORKDIR /var/lib/squid-go
USER 65532:65532

EXPOSE 443

ENTRYPOINT ["/squid-go"]

