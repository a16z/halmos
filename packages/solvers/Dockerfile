FROM ubuntu:24.04 as builder

# Install necessary packages
RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    git \
    build-essential \
    wget \
    unzip \
    autoconf \
    libffi-dev \
    cmake \
    python3 \
    python3-pip \
    python3-venv \
    ninja-build \
    software-properties-common \
    g++ zlib1g-dev libboost-all-dev flex bison

# Install Z3
COPY --from=ghcr.io/z3prover/z3:ubuntu-20.04-bare-z3-sha-770c51a /usr/bin/z3 /usr/local/bin/z3

# Install STP
COPY --from=msoos/stp /usr/local/bin/stp /usr/local/bin/stp

# Install Yices from the release binaries
WORKDIR /yices
ARG YICES_VERSION=2.6.4
RUN wget https://github.com/SRI-CSL/yices2/releases/download/Yices-${YICES_VERSION}/yices-${YICES_VERSION}-x86_64-pc-linux-gnu.tar.gz -O yices.tar.gz && \
    tar -xzvf yices.tar.gz --strip-components=1 && \
    mv /yices/bin/* /usr/local/bin/ && \
    mv /yices/lib/* /usr/local/lib/ && \
    mv /yices/include/* /usr/local/include/ && \
    rm -rf /yices

# Install cvc5 from release binaries
WORKDIR /cvc5
ARG CVC5_VERSION=1.1.2
RUN wget https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/cvc5-Linux-static.zip -O cvc5-Linux-static.zip && \
    unzip cvc5-Linux-static.zip && \
    mv cvc5-Linux-static/bin/cvc5 /usr/local/bin/cvc5 && \
    chmod +x /usr/local/bin/cvc5 && \
    rm -rf /cvc5

# Install Bitwuzla
WORKDIR /bitwuzla
RUN git clone --depth 1 https://github.com/bitwuzla/bitwuzla . && \
    python3 -m venv .venv && \
    . .venv/bin/activate && \
    python3 -m pip install meson && \
    ./configure.py && \
    cd build && \
    ninja install && \
    rm -rf /bitwuzla

# Install Boolector
WORKDIR /boolector
RUN git clone --depth 1 https://github.com/boolector/boolector . && \
    ./contrib/setup-lingeling.sh && \
    ./contrib/setup-btor2tools.sh && \
    ./configure.sh && \
    cd build && \
    make && \
    mv /boolector/build/bin/* /usr/local/bin/ && \
    rm -rf /boolector

# Create the final image
FROM ubuntu:24.04

# Copy installed files from builder

COPY --from=builder \
    /usr/local/bin/z3 \
    /usr/local/bin/stp \
    /usr/local/bin/cvc5 \
    /usr/local/bin/yices \
    /usr/local/bin/yices-smt2 \
    /usr/local/bin/bitwuzla \
    /usr/local/bin/boolector \
    /usr/local/bin/


# Set the default command for the container
WORKDIR /workspace
CMD ["/bin/bash"]
