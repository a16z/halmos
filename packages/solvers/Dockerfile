# TODO: migrate to ubuntu:24.04 when yices is available in the repository
FROM ubuntu:22.04

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
    g++ zlib1g-dev libboost-all-dev flex bison && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

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

# Install Yices
RUN add-apt-repository ppa:sri-csl/formal-methods -y && \
    apt-get update && \
    apt-get install -y \
    gnupg2 \
    software-properties-common \
    yices2

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
    ninja install \
    cd / && rm -rf /tmp/bitwuzla

# Install Boolector
RUN git clone --depth 1 https://github.com/boolector/boolector && cd boolector && ./contrib/setup-lingeling.sh && \
    ./contrib/setup-btor2tools.sh && \
    ./configure.sh && \
    cd build && \
    make && \
    ln -s /boolector/build/bin/boolector /usr/local/bin/boolector \
    cd / && rm -rf /tmp/boolector

# Set the default command for the container
CMD ["bash"]

