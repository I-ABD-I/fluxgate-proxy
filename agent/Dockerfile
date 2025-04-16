FROM rust:slim-bullseye AS builder

WORKDIR /app
COPY Cargo.toml ./

# Create a dummy main.rs to avoid rebuilding the application code
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pre-build dependencies
RUN cargo build --release
RUN rm -rf src

COPY . .

RUN cargo build --release
FROM debian:bullseye-slim

RUN useradd -m appuser
USER appuser

COPY --from=builder /app/target/release/agent /usr/local/bin/agent
EXPOSE 2749

CMD ["agent"]