#!/bin/bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
pre-commit install
pre-commit run --all-files
python -m pip install -e .

deactivate
mkdir foundry
cd foundry
curl -L https://foundry.paradigm.xyz | bash
/home/vscode/.foundry/bin/foundryup

# just a test
# pytest -v -k "not long and not ffi" --ignore=tests/lib --halmos-options="-v -st --storage-layout solidity --solver-timeout-assertion 0"
