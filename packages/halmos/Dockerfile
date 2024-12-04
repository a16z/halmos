FROM ghcr.io/a16z/halmos-builder:latest

# - enable the virtual environment
# - install halmos and its dependencies in UV_PROJECT_ENVIRONMENT
# - enable bytecode compilation for faster startup
# - disable downloading any additional packages
# - use copy mode for linking instead of symlinking (because we mount to /src temporarily)
ENV PATH="/halmos/.venv/bin:$PATH" \
    UV_PROJECT_ENVIRONMENT='/halmos/.venv' \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Install halmos, assuming it is checked out in the current host directory
RUN --mount=type=bind,source=../..,target=/src,readonly=false \
    cd /src && \
    uv sync --frozen --extra dev

# Set a nicer prompt
ENV IMAGE_NAME=halmos
RUN echo 'PS1="($IMAGE_NAME) \[\033[1;32m\]\u@\h \[\033[1;35m\]\w \$\[\033[0m\] "' >> /root/.bashrc

WORKDIR /workspace
CMD ["uv", "run", "halmos"]
