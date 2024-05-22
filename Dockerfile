# Start with an Ubuntu base image
FROM ubuntu:22.04

# Install necessary packages
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3-pip \
    build-essential \
    wget \
    unzip \
    autoconf \
    software-properties-common

# Install Yices
RUN add-apt-repository ppa:sri-csl/formal-methods
RUN apt-get update
RUN apt-get install yices2 -y

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash

# Set up Python and Install Halmos
RUN pip3 install pytest setuptools
RUN pip3 install z3-solver==4.12.2.0

# Add your application files
WORKDIR /app
COPY . /app

# Set the default command for the container
CMD ["bash"]
