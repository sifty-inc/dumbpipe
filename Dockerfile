FROM rust:1.83-bookworm AS dumbpipe_builder

WORKDIR /app

ADD . /app/

RUN cargo build --release


FROM serjs/go-socks5-proxy AS  proxy


FROM debian:bookworm

COPY --from=proxy /socks5 /
COPY --from=dumbpipe_builder /app/target/release/dumbpipe /

RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY ./dumbpipe /
COPY ./start_server.sh /

CMD ["./start.sh"]

