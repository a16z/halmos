# Use the `solvers` package as base image
FROM ghcr.io/emperororokusaki/solvers:0.2.0

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
RUN ~/.foundry/bin/foundryup

# Ensure Foundry binaries are in PATH
ENV PATH="/root/.foundry/bin:${PATH}"

# Install halmos
RUN pip3 install halmos

CMD ["bash"]
