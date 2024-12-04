FROM ghcr.io/a16z/halmos-builder:latest

# inspired by https://hynek.me/articles/docker-uv/

# - enable the virtual environment
# - install halmos and its dependencies in UV_PROJECT_ENVIRONMENT
# - enable bytecode compilation for faster startup
# - disable downloading any additional packages
# - use copy mode for linking instead of symlinking (because we mount to /src temporarily)
ENV PATH="/halmos/bin:$PATH" \
    VIRTUAL_ENV='/halmos' \
    UV_PROJECT_ENVIRONMENT='/halmos' \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON=python3.13 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Install halmos, assuming it is checked out in the current host directory
# we don't specify --frozen or --locked because we don't check in uv.lock
RUN --mount=type=bind,source=../..,target=/src,readonly=false \
    cd /src && \
    uv sync --extra dev --no-editable

# Set a nicer prompt
ENV IMAGE_NAME=halmos
RUN echo 'PS1="($IMAGE_NAME) \[\033[1;32m\]\u@\h \[\033[1;35m\]\w \$\[\033[0m\] "' >> /root/.bashrc

# optional: print python version, site packages, and check that halmos can be imported
RUN <<EOT
python -V
python -Im site
python -Ic 'import halmos'
EOT

WORKDIR /workspace
CMD ["halmos"]
