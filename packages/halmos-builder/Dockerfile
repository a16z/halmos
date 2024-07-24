FROM ghcr.io/a16z/solvers:latest

RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
    python3 \
    python3-pip \
    wget \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry
COPY --from=ghcr.io/foundry-rs/foundry:latest \
    /usr/local/bin/forge \
    /usr/local/bin/cast \
    /usr/local/bin/

# Install uv
ADD --chmod=755 https://astral.sh/uv/install.sh /install.sh
RUN /install.sh && rm /install.sh
ENV PATH="/root/.cargo/bin:${PATH}"
