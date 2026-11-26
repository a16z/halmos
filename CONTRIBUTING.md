# Contributing to dolmos

Bug reports, suggestions and pull requests are welcome on
[GitHub](https://github.com/Dowsers/dolmos/issues).

## Development Setup

Clone or fork the repository:

```sh
# if you want to submit a pull request, fork the repository:
gh repo fork Dowsers/dolmos

# Or, if you just want to develop locally, clone it:
git clone git@github.com:Dowsers/dolmos.git

# navigate to the project directory
cd dolmos
```

**Recommended**: set up the development environment using [uv](https://docs.astral.sh/uv/):

```sh
# install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# this does a lot of things:
# - install a suitable python version if one is not found
# - create a virtual environment in `.venv`
# - install the main dependencies
# - install the development dependencies
# - generates a `uv.lock` file
uv sync --extra dev

# install and run the pre-commit hooks
uv run pre-commit install
uv run pre-commit run --all-files

# make changes to dolmos, then run it with:
uv run dolmos

# run the tests with:
uv run pytest

# add a dependency to the project:
uv add <dependency>

# remove a dependency from the project:
uv remove <dependency>

# update a dependency to the latest version:
uv lock --upgrade-package <dependency>

# to manually update the environment and activate it:
uv sync
source .venv/bin/activate
```

Alternatively, you can manage the python version and the virtual environment manually using `pip` (not recommended for most users):

```sh
# create and activate a virtual environment with a suitable python version
python3.12 -m venv .venv && source .venv/bin/activate

# install dolmos and its runtime dependencies in editable mode
python -m pip install -e ".[dev]"

# install and run the pre-commit hooks
pre-commit install
pre-commit run --all-files
```


## Coding Style

We recommend enabling the [ruff] formatter in your editor, but you can run it manually if needed:

```sh
python -m ruff check src/
```

[ruff]: <https://docs.astral.sh/ruff/>

## GitHub Codespace

A pre-configured development environment is available as a GitHub Codespaces dev container.

## License

By contributing, you agree that your contributions will be licensed under its [AGPL-3.0](LICENSE) License.

## Disclaimer

See the disclaimer in the [README](README.md#disclaimer).
