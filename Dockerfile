# Stage 1: Build the Rust binary
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential pkg-config libssl-dev perl git clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything needed for the build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build the server binary
RUN cargo build --release -p pike-server

# Stage 2: Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libc-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pike-server /usr/local/bin/pike-server
RUN chmod +x /usr/local/bin/pike-server

RUN mkdir -p /etc/pike/tls

COPY deploy/server-vps.toml /etc/pike/server.toml
COPY deploy/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

EXPOSE 443/udp
EXPOSE 8080/tcp
EXPOSE 9090/tcp

CMD ["/usr/local/bin/start.sh"]
