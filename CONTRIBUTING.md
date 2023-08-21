# Contributing to Halmos

We greatly appreciate your feedback, suggestions, and contributions to make Halmos a better tool for everyone!

Join the [Halmos Telegram Group][chat] for any inquiries or further discussions.

[chat]: <https://t.me/+4UhzHduai3MzZmUx>

## Development Setup

If you want to submit a pull request, fork the repository:

```sh
gh repo fork a16z/halmos
```

Or, if you just want to develop locally, clone it:

```sh
git clone git@github.com:a16z/halmos.git
```

Create and activate a virtual environment:

```sh
python3.11 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```sh
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Install and run the git hook scripts:

```sh
pre-commit install
pre-commit run --all-files
```

## Coding Style

We recommend enabling the [black] formatter in your editor, but you can run it manually if needed:

```sh
python -m black .
```

[black]: <https://black.readthedocs.io/en/stable/>

## License

By contributing, you agree that your contributions will be licensed under its [AGPL-3.0](LICENSE) License.

## Disclaimer

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
