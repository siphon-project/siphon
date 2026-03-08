# ── Chef base ────────────────────────────────────────────────────────────────
FROM python:3.14-rc-slim AS chef

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-chef

WORKDIR /build

# ── Plan dependencies ────────────────────────────────────────────────────────
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo chef prepare --recipe-path recipe.json

# ── Build dependencies (cached until Cargo.toml/lock change) ─────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN PYO3_PYTHON=python3 cargo chef cook --release --recipe-path recipe.json

# Build the real binary
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN PYO3_PYTHON=python3 cargo build --release

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.14-rc-slim

# Runtime shared libraries needed by the siphon binary
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install runtime Python packages that scripts commonly need.
# Users can extend this by building FROM this image.
RUN pip install --no-cache-dir \
    httpx \
    redis \
    aioboto3 \
    prometheus_client \
    opentelemetry-api \
    opentelemetry-sdk

# SIPhon binary
COPY --from=builder /build/target/release/siphon /usr/local/bin/siphon

# Default scripts and config
COPY scripts/ /etc/siphon/scripts/
COPY examples/ /etc/siphon/examples/
COPY siphon.yaml /etc/siphon/siphon.yaml

# SIP ports
# 5060 UDP/TCP — standard SIP
# 5061 TCP     — SIP over TLS (future)
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp

WORKDIR /etc/siphon

# Run with host network mode for production to avoid NAT issues with SIP.
# Example:
#   docker run --network host -v ./siphon.yaml:/etc/siphon/siphon.yaml \
#              -v ./scripts:/etc/siphon/scripts siphon
ENTRYPOINT ["/usr/local/bin/siphon"]
CMD ["--config", "/etc/siphon/siphon.yaml"]
