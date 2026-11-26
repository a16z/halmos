# Simple Examples

Given a contract:
```solidity
contract Example {
    function totalPriceBuggy(uint96 price, uint32 quantity) public pure returns (uint128) {
        unchecked {
            return uint120(price) * quantity; // buggy type casting: uint120 vs uint128
        }
    }
}
```

You write some **property-based tests** (in Solidity):
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
$ dolmos --function test
[FAIL] testTotalPriceBuggy(uint96,uint32) (paths: 6, time: 0.10s, bounds: [])
Counterexample: [p_price_uint96 = 39614081294025656978550816768, p_quantity_uint32 = 1073741824]
```

_(In this specific example, Dolmos discovered an input that violated the assertion, which was missed by the fuzzer!)_

## Disclaimer

_This software and the smart contracts in this repository are provided as is,
without warranty of any kind, express or implied, including any warranty of
merchantability, non-infringement or fitness for a particular purpose. They have
not been audited. Passing symbolic tests is not a proof that a contract is free
of bugs. Nothing in this repository is investment or legal advice. See
[NOTICE](../../NOTICE) for the disclaimers attached to the original work this code is
derived from._
