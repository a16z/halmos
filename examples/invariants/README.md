# Dolmos Invariant Testing Examples

This directory contains examples demonstrating various approaches to invariant testing with dolmos.

## Examples

- **ERC20 Test** ([`ERC20.t.sol`](test/ERC20.t.sol)): Tests the fundamental ERC20 invariant: the sum of all balances equals the total supply. Shows how to write handlers for tracking token holders.

- **ERC721 Test** ([`ERC721.t.sol`](test/ERC721.t.sol)): Simple ERC721 invariant testing without handlers. Demonstrates how straightforward invariant testing can be when state tracking isn't needed.

- **MiniVat Test** ([`MiniVat.t.sol`](test/MiniVat.t.sol)): dolmos version of [Antonio's MiniVat test](https://github.com/aviggiano/property-based-testing-benchmark/blob/main/projects/dai-certora/test/TargetFunctions.sol). Unlike other fuzzers, no bounds are needed, so no handlers are required. Simply deploy the contract and write the invariant.

- **Vat Test** ([`Vat.t.sol`](test/Vat.t.sol)): Tests the full Vat contract using the same invariant as MiniVat. It is more comprehensive and takes longer to run.

- **SimpleState Test** ([`SimpleState.t.sol`](test/SimpleState.t.sol)): Example from the [ItyFuzz paper](https://arxiv.org/pdf/2306.17135) that's hard to detect with simple random testing. Dolmos uses exhaustive search and considers only unique state-generating call sequences for efficient space exploration.

- **Reentrancy Test** ([`Reentrancy.t.sol`](test/Reentrancy.t.sol)): Shows how to detect reentrancy exploits using dolmos invariant testing. Demonstrates attacker contract implementation using the [halmos-cheatcodes](https://github.com/a16z/halmos-cheatcodes) library.

## Running Tests

```bash
cd examples/invariants

# Run all invariant tests
dolmos

# Run specific test
dolmos --contract ERC20Test

# Run specific invariant
dolmos --function invariant_sumOfBalancesEqualsTotalSupply
```
