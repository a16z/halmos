FROM mcr.microsoft.com/devcontainers/python:3.12

# for local debuggging of the devcontainer
# RUN git clone https://github.com/a16z/halmos.git
# WORKDIR /halmos

RUN python -m venv .venv

# note that .venv/bin/activate is not executable by default
# and we don't have `source` command in sh
RUN chmod +x .venv/bin/activate && \
    .venv/bin/activate

RUN python -m pip install -r requirements.txt && \
    python -m pip install -r requirements-dev.txt

RUN pre-commit install && \
    pre-commit run --all-files

# install foundry
RUN mkdir foundry && \
    cd foundry && \
    curl -L https://foundry.paradigm.xyz | bash 
# Update PATH to include foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

# install halmos from local source
RUN python -m pip install -e .

# for fun, run some tests -- comment out when committing
# RUN pytest -v -k "not long and not ffi" --ignore=tests/lib --halmos-options="-v -st --storage-layout solidity --solver-timeout-assertion 0"
