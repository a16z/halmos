# Halmos

[![License](https://img.shields.io/github/license/a16z/halmos)](https://github.com/a16z/halmos/blob/main/LICENSE)
[![chat](https://img.shields.io/badge/chat-telegram-blue)](https://t.me/+4UhzHduai3MzZmUx)

Halmos is a _symbolic testing_ tool for EVM smart contracts. A Solidity/Foundry frontend is currently offered by default, with plans to provide support for other languages, such as Vyper and Huff, in the future.

You can read more in our post: "_[Symbolic testing with Halmos: Leveraging existing tests for formal verification][post]_."

Join the [Halmos Telegram Group][chat] for any inquiries or further discussions.

[post]: <https://a16zcrypto.com/symbolic-testing-with-halmos-leveraging-existing-tests-for-formal-verification/>
[chat]: <https://t.me/+4UhzHduai3MzZmUx>

## Installation

```
pip install halmos
```

Or, if you want to try out the nightly build version:
```
pip install git+https://github.com/a16z/halmos
```

## Usage

```
cd /path/to/src
halmos
```

For more details:
```
halmos --help
```

## Examples

Refer to the [getting started guide](docs/getting-started.md) and the [examples](examples/README.md) directory.

## Contributing

Refer to the [contributing guidelines](CONTRIBUTING.md), and explore the list of issues labeled ["good first issue" or "help wanted."][issues]

[issues]: <https://github.com/a16z/halmos/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22%2C%22help+wanted%22>

## Disclaimer

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
