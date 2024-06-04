# TODO: migrate to ubuntu:24.04 when yices is available in the repository
FROM ubuntu:22.04 as builder

# homebrew sets the user to 'linuxbrew'
USER root

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
    ninja-build \
    software-properties-common \
    g++ zlib1g-dev libboost-all-dev flex bison

# Install Z3
RUN apt-get install -y z3

# Install STP
RUN git clone --depth 1 https://github.com/stp/minisat.git && cd minisat && mkdir build && cd build && \
    cmake .. && \
    make && \
    make install && \
    cd / && rm -rf /tmp/minisat

RUN git clone --depth 1 https://github.com/stp/stp.git && \
    cd stp && mkdir build && cd build && \
    cmake .. && \
    make && \
    make install && \
    cd / && rm -rf /tmp/stp

# Install Yices from the release binaries
RUN wget https://github.com/SRI-CSL/yices2/releases/download/Yices-2.6.4/yices-2.6.4-x86_64-pc-linux-gnu.tar.gz -O /tmp/yices.tar.gz && \
    mkdir -p /tmp/yices && \
    tar -xzvf /tmp/yices.tar.gz -C /tmp/yices --strip-components=1 && \
    mv /tmp/yices/bin/* /usr/local/bin/ && \
    mv /tmp/yices/lib/* /usr/local/lib/ && \
    mv /tmp/yices/include/* /usr/local/include/ && \
    rm -rf /tmp/yices /tmp/yices.tar.gz

# Build cvc5 from source
# RUN git clone --depth 1 https://github.com/cvc5/cvc5.git && cd cvc5 && ./configure.sh --auto-download && \
#    cd ./build && \
#    make && \
#    make check && \
#    make install

# Install cvc5 from release binaries
RUN wget https://github.com/cvc5/cvc5/releases/download/cvc5-1.1.2/cvc5-Linux-static.zip -O /tmp/cvc5-Linux-static.zip && \
    unzip /tmp/cvc5-Linux-static.zip -d /tmp && \
    mv /tmp/cvc5-Linux-static/bin/cvc5 /usr/local/bin/cvc5 && \
    chmod +x /usr/local/bin/cvc5 && \
    rm /tmp/cvc5-Linux-static.zip

# Install Bitwuzla
RUN git clone --depth 1 https://github.com/bitwuzla/bitwuzla && \
    cd bitwuzla && \
    pip3 install meson && \
    ./configure.py && \
    cd build && \
    ninja install && \
    cd / && rm -rf /tmp/bitwuzla

# Install Boolector
RUN git clone --depth 1 https://github.com/boolector/boolector && cd boolector && ./contrib/setup-lingeling.sh && \
    ./contrib/setup-btor2tools.sh && \
    ./configure.sh && \
    cd build && \
    make && \
    mv /boolector/build/bin/* /usr/local/bin/ && \
    cd / && rm -rf /tmp/boolector

# Create the final image
FROM ubuntu:22.04

# Copy installed files from builder
COPY --from=builder /usr/local /usr/local

# Set the default command for the container
CMD ["bash"]

