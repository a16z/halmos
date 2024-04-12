#!/bin/bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
pre-commit install
pre-commit run --all-files
python -m pip install -e .
