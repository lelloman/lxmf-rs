FROM rust:1.93.1-bookworm AS builder

WORKDIR /build
COPY rns-rs ./rns-rs
COPY lxmf-rs ./lxmf-rs

WORKDIR /build/rns-rs
RUN cargo build --release -p rns-ctl -p rns-server

WORKDIR /build/lxmf-rs
RUN cargo build --release -p lxmd -p lxmf-server
RUN cargo build --release -p lxmf-rs --example test_node

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl iproute2 iptables \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/rns-rs/target/release/rns-ctl /usr/local/bin/rns-ctl
COPY --from=builder /build/rns-rs/target/release/rns-server /usr/local/bin/rns-server
COPY --from=builder /build/lxmf-rs/target/release/lxmd /usr/local/bin/lxmd
COPY --from=builder /build/lxmf-rs/target/release/lxmf-server /usr/local/bin/lxmf-server
COPY --from=builder /build/lxmf-rs/target/release/examples/test_node /usr/local/bin/lxmf-test-node

RUN mkdir -p /etc/rns /data/rns /data/lxmf

EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=2s --retries=20 \
  CMD curl -sf http://localhost:8080/health || exit 1

CMD ["lxmf-test-node"]
