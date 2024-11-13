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

# Set a nicer prompt
ENV IMAGE_NAME=halmos
RUN echo 'PS1="($IMAGE_NAME) \[\033[1;32m\]\u@\h \[\033[1;35m\]\w \$\[\033[0m\] "' >> /root/.bashrc

WORKDIR /workspace
CMD ["halmos"]
