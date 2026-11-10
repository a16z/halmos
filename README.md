# Dolmos

[![License](https://img.shields.io/github/license/Dowsers/dolmos)](https://github.com/Dowsers/dolmos/blob/main/LICENSE)
[![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2FDowsers%2Fdolmos%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)](pyproject.toml)

(https://github.com/a16z/halmos/wiki/FAQ)


Dolmos is a _symbolic testing_ tool for EVM smart contracts, driven by
Foundry-style tests, maintained by [Dowsers](https://github.com/Dowsers) for its
audit and formal verification work. Tests look like fuzz tests, but inputs are
symbolic: a passing test holds for every input, and a failing one comes with a
counterexample.

Start with the [getting started guide](https://github.com/Dowsers/dolmos/blob/main/docs/getting-started.md) and the
[examples](https://github.com/Dowsers/dolmos/blob/main/examples/README.md).
Loops that reach the unrolling bound can be exported for termination analysis with
PaSTTeL (experimental): see [docs/loop-termination.md](https://github.com/Dowsers/dolmos/blob/main/docs/loop-termination.md).

## Features

On top of symbolic execution of Solidity (and Vyper) tests with `check_*` and
`invariant_*` functions, dolmos provides the following.

**CREATE address derivation and account nonces.** Accounts carry nonces (1 for a
newly created account per EIP-161, incremented by CREATE and CREATE2 even when
the creation fails), and CREATE addresses are derived from
`keccak256(rlp([sender, nonce]))`, mapped to a magic address as for CREATE2. A
contract that predicts its own deployment address, as every CREATE3 library
does, therefore agrees with the executor.

**Nonce cheatcodes.** `vm.getNonce`, `vm.setNonce`, `vm.setNonceUnsafe` and
`vm.resetNonce`, with foundry's semantics: `setNonce` only raises a nonce,
`resetNonce` gives 0 to EOAs and 1 to accounts with code.

**File cheatcodes.** `vm.readFile`, `vm.readFileBinary`, `vm.parseBytes` and
`vm.projectRoot`, so a test can deploy bytecode compiled outside solc (Huff, for
instance) from a file. Reads are subject to `fs_permissions` in `foundry.toml`,
resolved with `forge config` and applied as foundry does (paths normalized
against the project root, most specific permission wins, denied by default), so
a test that reads a file passes or fails the same way under `forge test`.

**Fusaka / Cancun opcodes.** `CLZ` (EIP-7939), with a concrete fast path and a
logarithmic symbolic encoding, plus `BLOBHASH` and `BLOBBASEFEE` (EIP-4844).

**Vyper.** Test contracts can be written in Vyper, and Solidity tests can target
Vyper contracts. forge's Vyper artifacts have no AST, no metadata and an empty
`methodIdentifiers`; dolmos reads `.vy`/`.vyi` artifacts, computes the selectors
from the ABI, takes the source path and compiler version from forge's cache, and
makes Vyper contracts visible to Solidity tests (deployed code, ABI for
invariant targets and traces, including contracts with immutables).
`vm.getCode` accepts `Foo.vy`, `src/Foo.vy` and `Foo.vy:Foo`.

A Vyper test looks like a Solidity one: `setUp()` and `check_*`/`invariant_*`
functions, with cheatcodes called through an interface at
`0x7109709ECfa91a80626fF3989D68f67F5b1DD12D`. Use `assert ..., UNREACHABLE` for
properties: it compiles to the INVALID opcode, which the `--invalid-as-failure`
option reports as a failure, even when it is hit in a nested call and bubbles up
as an empty revert. A plain `assert` is an empty revert, indistinguishable from
a `require`, so the path is silently discarded. The `vm.assert*` cheatcodes work
as well. `@custom:dolmos` annotations go in the module and function docstrings.

When the build contains Vyper contracts, `--storage-layout generic` (Vyper
computes `HashMap` slots as `keccak256(slot . key)`) and `--invalid-as-failure`
become the defaults; a value set in `dolmos.toml`, an annotation or on the
command line still wins. Coverage reports do not include Vyper code, since forge
emits no source maps for it. See `tests/vyper` for examples.

## Compatibility with halmos

Dolmos is derived from halmos (see [NOTICE](https://github.com/Dowsers/dolmos/blob/main/NOTICE)) and accepts the names used
by test suites written for it, so they should run without changes:

| halmos | dolmos | |
|---|---|---|
| `@custom:halmos` | `@custom:dolmos` | both accepted, in contracts and functions |
| `halmos.toml` | `dolmos.toml` | `dolmos.toml` is read first |
| `HALMOS_ALLOW_DOWNLOAD` | `DOLMOS_ALLOW_DOWNLOAD` | both honored |
| `halmos-cheatcodes` | unchanged | the `svm.*` cheatcodes of this library are supported |

Some things do change: the command and the Python package are named `dolmos`
(`import dolmos`), symbolic variables in counterexamples are prefixed with
`dolmos_`, and solvers downloaded on demand are cached in `~/.dolmos/solvers`.

## Installation

Requires Python ≥ 3.11 and [Foundry](https://getfoundry.sh).

With [uv](https://docs.astral.sh/uv/) (recommended, installs `dolmos` as an
isolated command-line tool):

```sh
uv tool install dolmos
dolmos --version
```

With pipx or pip:

```sh
pipx install dolmos
# or, in a virtual environment
pip install dolmos
```

Upgrade with `uv tool upgrade dolmos` (or `pipx upgrade dolmos`,
`pip install -U dolmos`).

### Docker

Each release is published as a Docker image that bundles dolmos, Foundry and the
SMT solvers (yices, z3, cvc5, bitwuzla, stp):

```sh
docker run --rm -v "$PWD":/workspace ghcr.io/dowsers/dolmos:latest dolmos
# or a fixed version
docker run --rm -v "$PWD":/workspace ghcr.io/dowsers/dolmos:0.1.0 dolmos
```

### From source

```sh
git clone https://github.com/Dowsers/dolmos.git
cd dolmos
uv sync --extra dev        # or: python -m venv .venv && pip install -e ".[dev]"
uv run dolmos --version
```

See [CONTRIBUTING.md](https://github.com/Dowsers/dolmos/blob/main/CONTRIBUTING.md)
for the development setup.

## Usage

```sh
cd /path/to/foundry/project
forge build
dolmos
```

```sh
dolmos --help
dolmos -test <regex>          # alias for --match-test
dolmos --match-contract <regex>
```

Options can be set per project in `dolmos.toml` at the project root:

```toml
[global]
solver-timeout-assertion = 10000
# invariant testing calls ERC-1967 proxies with the ABI of their implementation;
# set to false to call them with their own ABI (same as --no-detect-proxies)
detect-proxies = true
```

`python -m dolmos.config` prints every option with its default value, in that
format. Warnings link to their explanation in [docs/warnings.md](https://github.com/Dowsers/dolmos/blob/main/docs/warnings.md).

## Tests

```sh
pytest                                   # unit tests and integration tests
pytest tests/test_dolmos.py -k "not long"
```

The regression suite lives in `tests/regression` and runs with both forge (real
EVM) and dolmos (symbolic):

```sh
cd tests/regression
forge build
dolmos
```

A few notes on the toolchain:

- The suite sets `evm_version = 'osaka'` because of the CLZ tests, and
  `test/OpCodesCLZ.sol` needs a solc recent enough to accept `clz()` in assembly
  (0.8.31 or later); an older compiler fails with `Function "clz" not found`.
- `test/Invalid.t.sol` requires solc `^0.5.2`; if that version is unavailable,
  `forge build` stops there.
- `test/Arith.t.sol` uses the `bitwuzla-abs` solver; set
  `DOLMOS_ALLOW_DOWNLOAD=1` to let dolmos download it.
- The Vyper tests live in `tests/vyper` and need the `vyper` compiler in `PATH`
  (`pip install vyper`); pytest skips them otherwise.

## Contributing

See [CONTRIBUTING.md](https://github.com/Dowsers/dolmos/blob/main/CONTRIBUTING.md).

## Roadmap

- MODEXP precompile (EIP-198): concrete evaluation and a typed uninterpreted
  function instead of the current opaque one
- performance: skip the Z3 `substitute()` traversal when no free variable
  matches, bound the concurrency of solver subprocesses, memoize invariant
  target resolution
- support multiple `setUp()` states

## License

AGPL-3.0, see [LICENSE](https://github.com/Dowsers/dolmos/blob/main/LICENSE). Dolmos is a modified version of another
AGPL-3.0 program; [NOTICE](https://github.com/Dowsers/dolmos/blob/main/NOTICE) gives its origin and the notices that come
with it.

## Disclaimer

_This software and the smart contracts in this repository are provided as is,
without warranty of any kind, express or implied, including any warranty of
merchantability, non-infringement or fitness for a particular purpose. They have
not been audited. Passing symbolic tests is not a proof that a contract is free
of bugs. Nothing in this repository is investment or legal advice. See
[NOTICE](https://github.com/Dowsers/dolmos/blob/main/NOTICE) for the disclaimers attached to the original work this code is
derived from._
