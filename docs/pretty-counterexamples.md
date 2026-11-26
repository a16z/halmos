# Pretty counterexamples

By default, a counterexample is printed as the raw solver model: one line per symbol, with
the full hexadecimal value of every word. A `bytes` argument of length 65 is printed as the
1024 bytes of its largest length candidate, a `bytes4` selector as `0x00`, and the same
values are repeated for every failing path.

`--pretty-counterexamples` (short: `-pcex`) prints counterexamples that can be acted upon:

```
dolmos -pcex
```

It can also be set in `dolmos.toml` (`pretty-counterexamples = true`), or for a contract or
a function with `/// @custom:dolmos --pretty-counterexamples`. The verdicts of the tests
and the JSON output are the same as without the option, except for counterexamples that
are proven spurious (see [Potentially invalid counterexamples](#potentially-invalid-counterexamples)).

## What it changes

- **Arguments decoded with the ABI of the test.** The lengths of dynamic arrays, `bytes` and
  `string` are applied, and values are printed by type: decimal integers (with a readable
  form such as `1e18`, `2**255` or `type(uint256).max` when there is one), checksummed
  addresses (with the contract deployed there and the state variable of the test holding
  it), quoted strings, `true`/`false`. Structs and arrays are flattened to one line per
  value (`p.a = 7`, `calls[1] = …`).
- **Calldata decoded** (halmos#369). `bytes` values whose first 4 bytes are the selector of a
  function of a compiled contract are decoded with its ABI, e.g.
  `Token.transfer(to: 0x…, amount: 2) + 956 trailing zero bytes`. Calls made by the test
  with calldata built from other symbols (e.g. by `svm.createCalldata`) are listed under
  `Calls made with symbolic calldata`.
- **Selectors** (halmos#419). `bytes4` values are printed with the function they select, and
  `0x00000000` as the empty selector of plain ether transfers (`receive()` or
  `fallback()`), unless some contract has a function with that selector.
- **Invariant call sequences with concrete values**: target, decoded arguments, `msg.sender`,
  `msg.value`, `tx.origin` and `block.timestamp` of each call. The symbolic trace is still
  printed with `-vv`.
- **A forge test replaying the counterexample**, to paste into the test contract. It fails
  if the counterexample is real.
- **Duplicates hidden** (halmos#398). A counterexample with the same values as one already
  printed for the test is counted but not printed; the number of hidden duplicates is
  printed after the result of the test. `--early-exit` stops at the first valid
  counterexample.
- **Potentially invalid counterexamples are checked**, and the reason is printed when they
  remain potentially invalid (halmos#280), see below.

## Example

From `tests/regression/test/PrettyCex.t.sol`:

```solidity
function check_pcex_calldata(bytes calldata data) external {
    (bool ok,) = address(token).call(data);
    assert(!ok || token.balanceOf(address(this)) == 1000);
}
```

Without the option, the counterexample is the 2048 hex digits of `data` (its largest length
candidate) and the length symbol. With it:

```
Counterexample: check_pcex_calldata(bytes)
    data = PcexToken.transfer(to: 0x0000000000000000000000000000000000000000, amount: 512) + 956 trailing zero bytes
           0xa9059cbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002 + 957 zero bytes (1024 bytes)
Reproduce: add to PrettyCexTest (test/PrettyCex.t.sol), then `forge test --mt test_pcex_check_pcex_calldata_1 -vvvv` (the test fails if the counterexample is real)
    function test_pcex_check_pcex_calldata_1() public {
        this.check_pcex_calldata(abi.encodePacked(hex"a9059cbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", new bytes(957)));
    }
```

For an invariant test, the call sequence is printed with concrete values:

```
Counterexample: invariant_pcex_balance()
    Sequence:
        [1] PcexToken(token).transfer(to: 0xFFA9385be102ac3EAc297483Dd6233d62b3e1496, amount: 492)
            msg.sender: 0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496 (PrettyCexTest), tx.origin: 0x0000000000000000000000000000000000000000
        then invariant_pcex_balance() at block.timestamp: 9223372036854775808
Reproduce: add to PrettyCexTest (test/PrettyCex.t.sol), then `forge test --mt test_pcex_invariant_pcex_balance_1 -vvvv` (the test fails if the counterexample is real)
    function test_pcex_invariant_pcex_balance_1() public {
        vm.prank(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496, address(0));
        token.transfer(0xFFA9385be102ac3EAc297483Dd6233d62b3e1496, 492);
        vm.warp(9223372036854775808);
        this.invariant_pcex_balance();
    }
```

## Reproduction tests

The generated function calls the test function through `this`, with the values of the
counterexample. When the arguments cannot be written as Solidity literals (a value that is
not a valid ABI encoding of its type, e.g. a `uint8` above 255, or an overloaded test
function), it replays the exact calldata with a low-level call instead.

Invariant sequences are replayed with `vm.prank`, `vm.deal` and `vm.warp`. A target is
called through the state variable of the test that holds it (`vault.deposit(…)`), so that
the call goes to the instance deployed by forge. Dolmos deploys contracts at its own
addresses (`0xaaaa…`, `0xcccc…`), so a target that is not held by a state variable of the
test is called at the dolmos address, with a note to replace it.

Values that the test creates itself with `svm.create*` cheatcodes (and the calldata it
builds with `svm.createCalldata`) cannot be injected: they are listed as comments at the
top of the function, to replace the cheatcodes with.

## Potentially invalid counterexamples

Dolmos approximates some operations with uninterpreted functions, so a model may rely on
values that the real operation never produces. Such counterexamples are reported as
*potentially invalid*. Without the option, the reason is not given (halmos#280).

With the option, the operands and the result of every exponentiation that dolmos
approximates (`x ** y` with a symbolic exponent, or with a symbolic base and a constant
exponent above `--smt-exp-by-const`) are compared with the real `**`:

- if they agree, the counterexample is valid;
- otherwise the query is solved again with facts that hold for the real `**`: constant
  exponents are expanded by square and multiply, constant bases are tabulated (exactly for
  an even base), and the real value is added at the operands chosen by the model. Every
  real counterexample is kept, so `unsat` proves that there is none, and the test passes.
  This is repeated up to 3 times, plus `--keccak-refinement-rounds` times for the keccak
  values checked in the same loop.

For example, `assert(x ** 3 != 27)` gives a potentially invalid counterexample `x = 8`
without the option, and the valid counterexample `x = 3` with it. When the model still
disagrees, the reason is printed:

```solidity
function check_pow(uint256 x, uint256 y) external pure {
    vm.assume(x % 2 == 0 && y > 0);
    assert(x ** y != 3);
}
```

```
Counterexample (potentially invalid): check_pow(uint256,uint256)
    reason: EXP is approximated: x ** y (symbolic base and exponent): the model takes 10 ** 16 = 3 instead of 10000000000000000 (constrain the operands with vm.assume (e.g. exponent < 256) or make the base or the exponent constant)
    x = 10
    y = 16
(see https://github.com/Dowsers/dolmos/blob/main/docs/warnings.md#counterexample-invalid)
```
