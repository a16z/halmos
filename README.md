# Halmos

[![License](https://img.shields.io/github/license/a16z/halmos)](https://github.com/a16z/halmos/blob/main/LICENSE)
[![chat](https://img.shields.io/badge/chat-telegram-blue)](https://t.me/+4UhzHduai3MzZmUx)

_Symbolic Bounded Model Checker for Ethereum Smart Contracts Bytecode_

**_Symbolic_:** Halmos executes the given contract bytecode with symbolic function arguments and symbolic storage states, enabling it to systematically explore all possible behaviors of the contract.

**_Bounded_:** Halmos unrolls loops up to a specified bound and sets the size of variable-length arrays, allowing it to run automatically without the need for additional user annotations.

**_Model Checking_:** Halmos proves that assertions are never violated by any inputs or provides a counter-example. This allows Halmos to be used for bug detection as well as formal verification of the contract.

For more information, refer to our post on "_[Symbolic testing with Halmos: Leveraging existing tests for formal verification][post]_."

[post]: <https://a16zcrypto.com/symbolic-testing-with-halmos-leveraging-existing-tests-for-formal-verification/>

## Installation

```
$ pip install halmos
```

## Usage

```
$ cd /path/to/src
$ halmos
```

For more details:
```
$ halmos --help
```

## Examples

Given a contract, [Example.sol](examples/src/Example.sol):
```solidity
contract Example {
    function totalPriceBuggy(uint96 price, uint32 quantity) public pure returns (uint128) {
        unchecked {
            return uint120(price) * quantity; // buggy type casting: uint120 vs uint128
        }
    }
}
```

You write some **property-based tests** (in Solidity), [Example.t.sol](examples/test/Example.t.sol):
```solidity
contract ExampleTest is Example {
    function testTotalPriceBuggy(uint96 price, uint32 quantity) public pure {
        uint128 total = totalPriceBuggy(price, quantity);
        assert(quantity == 0 || total >= price);
    }
}
```

Then you can run **fuzz testing** to quickly check those properties for **some random inputs**:
```
$ forge test
[PASS] testTotalPriceBuggy(uint96,uint32) (runs: 256, μ: 462, ~: 466)
```

Once it passes, you can also perform **symbolic testing** to verify the same properties for **all possible inputs** (up to a specified limit):
```
$ halmos
[FAIL] testTotalPriceBuggy(uint96,uint32) (paths: 6, time: 0.10s, bounds: [])
Counterexample: [p_price_uint96 = 39614081294025656978550816768, p_quantity_uint32 = 1073741824]
```

_(In this specific example, Halmos discovered an input that violated the assertion, which was missed by the fuzzer!)_

## Disclaimer

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
