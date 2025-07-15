FROM rust:1.83-bookworm AS dumbpipe_builder

WORKDIR /app

RUN mkdir /app/src/; echo "fn main() {}" > /app/src/main.rs
RUN mkdir /app/src/; echo "fn main() {}" > /app/src/lib.rs
RUN mkdir /app/src/; echo "fn main() {}" > /app/uniffi-bindgen.rs
ADD ./Cargo.toml /app/Cargo.toml
ADD ./Cargo.lock /app/Cargo.lock
# can only build dependencies if i build project
RUN cargo build --release
RUN rm /app/src/main.rs

ADD ./src /app/src
RUN cargo build --release


FROM debian:bookworm-slim
COPY --from=dumbpipe_builder /app/target/release/dumbpipe /

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash"]
COPY start_remote_client.sh /
COPY start_cloud_portal.sh /


