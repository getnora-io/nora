FROM rust:1.87-slim

RUN apt-get update && apt-get install -y build-essential pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-fuzz

COPY . /src
WORKDIR /src

RUN cd fuzz && cargo fuzz build 2>/dev/null || true
