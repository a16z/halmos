# Contributing to Halmos

We greatly appreciate your feedback, suggestions, and contributions to make Halmos a better tool for everyone!

Join the [Halmos Telegram Group][chat] for any inquiries or further discussions.

[chat]: <https://t.me/+4UhzHduai3MzZmUx>

## Development Setup

Clone or fork the repository:

```sh
# if you want to submit a pull request, fork the repository:
gh repo fork a16z/halmos

# Or, if you just want to develop locally, clone it:
git clone git@github.com:a16z/halmos.git

# navigate to the project directory
cd halmos
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

# make changes to halmos, then run it with:
uv run halmos

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

# install halmos and its runtime dependencies in editable mode
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

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
