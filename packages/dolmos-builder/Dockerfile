FROM ghcr.io/dowsers/solvers:latest

RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
    python3 \
    python3-pip \
    wget \
    curl \
    python3-venv \
    build-essential \
    clang \
    python3.12-dev \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories for foundry
RUN mkdir -p /root/.foundry/bin /root/.foundry/share/man/man1

# Add foundry binaries to PATH
ENV PATH="/root/.foundry/bin:${PATH}"

# Download foundryup and install a pinned foundry version, so that the images (and
# the CI jobs that use them) do not change behaviour when foundry releases
ARG FOUNDRY_VERSION=v1.8.3
RUN curl -sSf -L https://raw.githubusercontent.com/foundry-rs/foundry/master/foundryup/foundryup \
    -o /root/.foundry/bin/foundryup && \
    chmod +x /root/.foundry/bin/foundryup && \
    foundryup --install ${FOUNDRY_VERSION}

# Set a nicer prompt
ENV IMAGE_NAME=dolmos-builder
RUN echo 'PS1="($IMAGE_NAME) \[\033[1;32m\]\u@\h \[\033[1;35m\]\w \$\[\033[0m\] "' >> /root/.bashrc
