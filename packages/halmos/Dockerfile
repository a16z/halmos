FROM ghcr.io/a16z/halmos-builder:latest

# Enable the virtual environment
ENV PATH="/halmos/.venv/bin:$PATH"
ENV VIRTUAL_ENV='/halmos/.venv'

# Install halmos, assuming it is checked out in the context directory
WORKDIR /halmos
RUN --mount=type=bind,source=../..,target=/src,readonly=false \
    uv venv && \
    uv pip install --no-cache /src && \
    uv pip install --no-cache -r /src/requirements-dev.txt

WORKDIR /workspace
ENTRYPOINT ["halmos"]
