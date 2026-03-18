FROM rust:1.87-slim@sha256:437507c3e719e4f968033b88d851ffa9f5aceeb2dcc2482cc6cb7647811a55eb

RUN apt-get update && apt-get install -y build-essential pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-fuzz

COPY . /src
WORKDIR /src

RUN cd fuzz && cargo fuzz build 2>/dev/null || true
