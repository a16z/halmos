FROM ghcr.io/dowsers/dolmos-builder:latest

# inspired by https://hynek.me/articles/docker-uv/

# - enable the virtual environment
# - install dolmos and its dependencies in UV_PROJECT_ENVIRONMENT
# - enable bytecode compilation for faster startup
# - use the python of the builder image (ubuntu 24.04 ships 3.12), never download one
# - use copy mode for linking instead of symlinking (because we mount to /src temporarily)
ENV PATH="/dolmos/bin:$PATH" \
    VIRTUAL_ENV='/dolmos' \
    UV_PROJECT_ENVIRONMENT='/dolmos' \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON=python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

# Install dolmos, assuming it is checked out in the current host directory
# we don't specify --frozen or --locked because we don't check in uv.lock
RUN --mount=type=bind,source=../..,target=/src,readonly=false \
    cd /src && \
    uv sync --extra dev --no-editable

# Set a nicer prompt
ENV IMAGE_NAME=dolmos
RUN echo 'PS1="($IMAGE_NAME) \[\033[1;32m\]\u@\h \[\033[1;35m\]\w \$\[\033[0m\] "' >> /root/.bashrc

# optional: print python version, site packages, and check that dolmos can be imported
RUN <<EOT
python -V
python -Im site
python -Ic 'import dolmos'
EOT

WORKDIR /workspace
CMD ["dolmos"]
