# Multi-stage Dockerfile for Virtual HSM
# Stage 1: Build
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    uuid-dev \
    libsodium-dev \
    libfido2-dev \
    libjson-c-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build the project
RUN make clean && \
    make all -j$(nproc) && \
    make test

# Stage 2: Runtime
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    uuid-runtime \
    libsodium23 \
    libfido2-1 \
    libjson-c5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r vhsm && useradd -r -g vhsm -s /bin/bash -d /app vhsm

# Set working directory
WORKDIR /app

# Copy built binaries and libraries from builder
COPY --from=builder /build/lib/ /app/lib/
COPY --from=builder /build/bin/ /app/bin/
COPY --from=builder /build/include/ /app/include/

# Set library path
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# Create directories for storage and certificates
RUN mkdir -p /app/storage /app/certs /app/logs && \
    chown -R vhsm:vhsm /app

# Switch to non-root user
USER vhsm

# Expose ports
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f https://localhost:8443/api/health -k || exit 1

# Default command - TLS server
CMD ["/app/bin/vhsm-server-tls", "-p", "8443", "-s", "/app/storage", "--generate-cert"]
