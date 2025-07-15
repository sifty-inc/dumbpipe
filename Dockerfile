FROM rust:1.88-bookworm AS dumbpipe_builder

WORKDIR /app

RUN mkdir /app/src/; echo "fn main() {}" > /app/src/main.rs; echo "fn main() {}" > /app/src/lib.rs; echo "fn main() {}" > /app/uniffi-bindgen.rs

ADD ./Cargo.toml /app/Cargo.toml
ADD ./Cargo.lock /app/Cargo.lock

# can only build dependencies if i build project
RUN cargo build --release
RUN rm -rf /app/src

ADD ./ /app/
RUN cargo build --release
RUN ls -lstarh target/release


FROM debian:bookworm-slim
COPY --from=dumbpipe_builder /app/target/release/dumbpipe /

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    iproute2 \
    iputils-ping \
    inetutils-traceroute \
    net-tools \
    dnsutils \
    curl \
    vim \
    iptables \
    && rm -rf /var/lib/apt/lists/*


ENTRYPOINT ["/bin/bash"]
COPY start_remote_client.sh /
COPY start_cloud_portal.sh /
COPY switch_route_entrypoint.sh /


