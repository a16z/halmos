#!/bin/bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
pre-commit install
pre-commit run --all-files
python -m pip install -e .

# Installing during postCreateCommand instead of at docker creation
# because foundryup installs the binaries in place not accessible by the
# current (vscode) user.
deactivate
mkdir foundry
cd foundry
curl -L https://foundry.paradigm.xyz | bash
/home/vscode/.foundry/bin/foundryup

# just a test
# pytest -v -k "not long and not ffi" --ignore=tests/lib --halmos-options="-v -st --storage-layout solidity --solver-timeout-assertion 0"
# same, but with force use of local pytest
# python -m pytest -v -k "not long and not ffi" --ignore=tests/lib --halmos-options="-v -st --storage-layout solidity --solver-timeout-assertion 0"
