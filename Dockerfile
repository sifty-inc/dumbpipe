FROM rust:1.83-bookworm AS dumbpipe_builder

WORKDIR /app

ADD ./src /app/src
ADD ./Cargo.toml /app/Cargo.toml
ADD ./Cargo.lock /app/Cargo.lock

RUN cargo build --release


FROM serjs/go-socks5-proxy AS  proxy


FROM debian:bookworm-slim

COPY --from=proxy /socks5 /
COPY --from=dumbpipe_builder /app/target/release/dumbpipe /

RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash"]
COPY start_remote_client.sh /
COPY start_cloud_portal.sh /


