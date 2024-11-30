# Use the official Rust image as the base for building
FROM rust:latest as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to avoid rebuilding the application code
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pre-build dependencies
RUN cargo build --release
RUN rm -rf src

# Copy the actual source code into the container
COPY . .

# Build the actual application
RUN cargo build --release

# Use a minimal runtime image for production
FROM debian:buster-slim

# Set up a non-root user for better security
RUN useradd -m appuser
USER appuser

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/proxy /usr/local/bin/fluxgate-proxy

# Expose the necessary ports
EXPOSE 80
EXPOSE 443

# Run the application
CMD ["fluxgate-proxy"]
