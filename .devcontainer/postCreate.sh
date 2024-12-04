#!/bin/bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .[dev]
pre-commit install
pre-commit run --all-files

# Installing during postCreateCommand instead of at docker creation
# because foundryup installs the binaries in place not accessible by the
# current (vscode) user.
curl -L https://foundry.paradigm.xyz | bash
/home/vscode/.foundry/bin/foundryup

echo 'source .venv/bin/activate' >> ~/.bashrc

# just a test
# pytest -v -k "not long and not ffi" --ignore=tests/lib --halmos-options="-v -st --storage-layout solidity --solver-timeout-assertion 0"
