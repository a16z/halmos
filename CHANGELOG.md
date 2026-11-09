# Changelog

All notable changes to dolmos are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Dolmos is derived from halmos; see
[NOTICE](NOTICE) for the upstream commit it is based on.

## [Unreleased]

### Added

- invariant testing through proxies (halmos#553): an ERC-1967 proxy found after
  `setUp` is called with the ABI of its implementation (read once from the
  implementation slot, upgrades during the run are not followed), and forge-std's
  `targetInterfaces()` gives the ABI to use for any address, e.g. a proxy with a
  non-standard layout (`targetInterface(FuzzInterface(proxy, ["Impl"]))`). The target
  functions panel shows the ABI used, e.g. `Proxy @ 0x… (as Impl)`. The detection of
  ERC-1967 proxies is enabled by default, and disabled with `--no-detect-proxies` or
  `detect-proxies = false` in `dolmos.toml`; `targetInterfaces()` always applies.
  Boolean options enabled by default accept `--name` and `--no-name` on the command
  line and in `@custom:dolmos` annotations

- `vm.toString` for `address`, `bytes`, `bytes32`, `bool`, `uint256` and `int256`, with
  foundry's formatting (checksummed addresses, lowercase hex, signed decimals), e.g.
  for forge-std's `bound(int256, int256, int256)`, which logs its result with it.
  Symbolic values are converted exactly for `bytes` and `bytes32`, exactly up to the
  case of the letters for `address`, with one path per value for `bool`; for `uint256`
  and `int256`, whose length depends on the value, the result is approximated by a
  string of digits of the maximal length, and a warning is printed (halmos#565)
- addresses in counterexamples are annotated with what is known about them: their
  label, set by `vm.label` (also on symbolic addresses, resolved with the values of the
  counterexample), and the contract deployed there, e.g.
  `p_user_address_… = 0xa11ce (alice)`; with `--pretty-counterexamples`, labels are
  added to the existing hints (halmos#447)
- `vm.getLabel`, which returns the latest label of an address, or
  `unlabeled:<address>` as in foundry

### Fixed

- counterexamples were empty when the solver answers `(get-model)` with equalities,
  `(= p_x_uint256_… #b…)`, instead of `define-fun` (e.g. models saved in smt files):
  both formats are parsed (halmos#449)
- solver failures are described instead of `solver_output.error=''
  (solver_output.returncode=-4)`: a negative return code is named after the signal
  that killed the solver, with the likely cause (e.g. SIGILL: a solver binary built
  for another CPU; SIGKILL: out of memory), or on Windows after the exception code
  (e.g. 0xC000001D, illegal instruction), along with the solver and its stderr
  (halmos#580)
- a counterexample printed by a solver thread while the status line starts or stops
  could crash the callback (`AttributeError: 'cell' object has no attribute
  '_FileProxy__buffer'`): the solver callbacks and the status changes are serialized,
  and the replaced stdout proxies are kept alive (halmos#557)
- `vm.addr` could return the address of a deployed contract, so a counterexample
  could sign a message "from" a contract: its result is now above `2**64`, where
  contracts are created, and differs from every concrete address with code at the
  time of the call, e.g. a contract etched at a hardcoded address (halmos#413)
- a library that links another library crashed with `non-hexadecimal number found in
  fromhex()`: the libraries linked by libraries are now deployed too, before the
  libraries that link them, and their placeholders are replaced (halmos#555)
- a RecursionError could abort a test with a deep call tree: copying the call context
  at each branch copied the whole tree of completed subcalls. The completed elements
  of the trace, which do not change, are now shared between paths, which also makes
  branching cheaper (halmos#416)
- the status line could show a frozen number of completed paths while the
  exploration went on, e.g. when every path stops at a loop bound: it now also counts
  the paths stopped at a loop bound, dropped as infeasible, or stopped by `--depth`
  (halmos#444)

- `NOT` applied to the result of a comparison (`EQ`, `LT`, `ISZERO`, ...) complements
  the 256-bit word, instead of negating it logically: `not(eq(1, 1))` is
  `2**256 - 2`, not `0` (halmos#593)
- `JUMPI` to an invalid destination with a symbolic condition halts only the path
  where the jump is taken; the fall-through path was dropped, which could hide a
  failure and report a test as passing (halmos#594)
- `ADDMOD` and `MULMOD` with a concrete zero modulus return 0 instead of crashing
  with `ZeroDivisionError` (halmos#595)
- `RETURNDATACOPY` checks `offset + size <= RETURNDATASIZE` even when `size` is 0,
  and halts exceptionally otherwise, as in the EVM (halmos#596)
- every memory access expands the active memory reported by `MSIZE`, reads
  included: `MLOAD`, `KECCAK256`, `LOG*`, the source of `MCOPY`, the input of
  `CREATE*` and `*CALL`, and the output region of `*CALL` whatever the size of the
  return data. A call with a huge output size therefore runs out of gas, as in the
  EVM, instead of succeeding (halmos#597)
- artifacts that forge writes to a subdirectory of the build output to resolve a
  name conflict (e.g. `out/nested/A.sol/Token.json` when `src/A.sol` and
  `src/nested/A.sol` both define `Token`) are no longer ignored: their test contracts
  are run, their contracts are named in traces, libraries are linked from them, and
  `vm.getCode` finds them from a source path such as `src/nested/A.sol:Token` (a
  bare file name matching several artifacts is an error, as in foundry). A contract
  name alone, e.g. `svm.createCalldata("IERC20")`, still resolves to the top-level
  artifact when nested artifacts share its name (halmos#582)

## [0.2.0] - 2026-10-16

### Added

- file cheatcodes `vm.readFile`, `vm.readFileBinary`, `vm.parseBytes` and
  `vm.projectRoot`, e.g. to deploy Huff bytecode read from a file; reads honor
  `fs_permissions` from `foundry.toml` with foundry's semantics, and
  `vm.parseBytes` accepts exactly what foundry accepts (halmos#213)
- `vm.expectRevert` (all overloads, including the reverter address and `count`
  variants), `vm.expectPartialRevert`, `vm.expectEmit` and
  `vm.expectEmitAnonymous` (including the emitter address and `count` variants),
  with foundry's semantics; symbolic revert data and event fields are matched
  symbolically and a counterexample is reported when an expectation can be
  violated (halmos#409)
- multiple setup states: when `setUp()` has several feasible successful paths,
  each test and each invariant test sequence is run from every one of them,
  instead of failing with "Multiple paths were found in setUp()" (halmos#186)
- experimental: `--dump-lassos DIR` exports each loop that reaches the unrolling
  bound as a lasso program, and `--pasttel BINARY` analyses it with PaSTTeL
  (termination proof with a ranking function, or non-termination). Lassos use
  a small-constants encoding by default, because PaSTTeL computes with doubles
  and is unsound on 2^256 constants; `--lasso-exact-constants` gives the exact
  encoding. See docs/loop-termination.md
- `SELFDESTRUCT` opcode, with the EIP-6780 (Cancun) semantics: the balance is sent to
  the beneficiary and the frame halts; the account (code, storage, balance, nonce) is
  deleted at the end of the transaction only if it was created in that transaction;
  forbidden in static contexts (halmos#411). With `BLOBHASH` and `BLOBBASEFEE`
  (0.1.0), and `TLOAD`, `TSTORE` and `MCOPY` inherited from halmos, every opcode
  introduced by Cancun is supported (halmos#290)
- EVM version setting, `--evm-version VERSION` (also usable in `dolmos.toml` and
  `@custom:dolmos` annotations): opcodes introduced after the selected fork are invalid,
  and `SELFDESTRUCT` deletes the account unconditionally before Cancun. Defaults to the
  `evmVersion` the test contract was compiled for (foundry's `evm_version`), or to the
  latest supported fork, `osaka` (halmos#128)
- `--pretty-counterexamples` (`-pcex`) prints counterexamples that can be acted upon; see
  docs/pretty-counterexamples.md:
  - test arguments decoded with the ABI of the test, with the lengths of dynamic values
    applied and values rendered by type (decimal, checksummed addresses, strings)
  - `bytes` holding calldata decoded with the ABIs of the compiled contracts, and calls
    made with calldata built by `svm.createCalldata` listed (halmos#369)
  - `bytes4` values rendered as selectors, `0x00000000` as the empty selector of plain
    ether transfers (halmos#419)
  - invariant call sequences with concrete senders, values, arguments and timestamps
  - a forge test replaying each counterexample
  - duplicate counterexamples hidden, and counted (halmos#398)
  - potentially invalid counterexamples relying on the approximation of `EXP` checked
    against the real exponentiation: they are confirmed, replaced by a valid one, or
    proven spurious; otherwise the reason is printed (halmos#280)

### Fixed

- `--early-exit` no longer reports the queries cancelled after the first counterexample as
  solver errors (`executor has been shutdown`), nor saves them as failed queries
  (halmos#398)
- SHA256, RIPEMD160 and MODEXP precompiles with symbolic input no longer crash
  with a z3 sort mismatch (input sizes were given in bytes instead of bits).
  Concrete inputs are now evaluated exactly; MODEXP follows EIP-198 (zero-padded
  input, output on `len(M)` bytes) and EIP-7823 (lengths above 1024 bytes make
  the call fail), and its symbolic model guarantees `result < M` (halmos#402)
- storage slots written as precomputed keccak256 literals (e.g. constant-folded by the
  via-IR optimizer in a constructor) and read through SHA3 at runtime now hit the same
  storage cell, instead of reading zero and reporting a false counterexample; applies to
  both storage layouts (halmos#579)
- counterexamples relying on keccak256 values that differ from the real hash function
  (keccak256 is uninterpreted, so the solver could pick e.g. `x = 0` and assume that its
  hash is the key of a storage entry) are no longer reported as valid. The real hashes of
  the preimages chosen by the model are added to the query, which is solved again, up to
  `--keccak-refinement-rounds` times (default 3, 0 disables the check); a counterexample
  that still disagrees is reported as potentially invalid (halmos#562)
- on Windows, `--solver-command` with a path such as `C:\solvers\z3.exe` is no
  longer mangled (backslashes were parsed as shell escapes); quotes still group words
- on Windows, `vm.readFile` no longer falls back to foundry's default `fs_permissions`
  when `forge config` writes non-ascii output, and `fs_permissions` paths are matched
  case-insensitively, as by foundry

## [0.1.0] - 2026-09-22

First release of dolmos.

### Added

- CREATE address derivation from `keccak256(rlp([sender, nonce]))` and account
  nonces (EIP-161), so that CREATE3-style address prediction matches execution
- nonce cheatcodes: `vm.getNonce`, `vm.setNonce`, `vm.setNonceUnsafe`,
  `vm.resetNonce`
- opcodes `CLZ` (EIP-7939, halmos#586), `BLOBHASH` and `BLOBBASEFEE` (EIP-4844)
- experimental Vyper support: Vyper test contracts, Solidity tests targeting
  Vyper contracts, `@custom:dolmos` annotations in docstrings,
  `--invalid-as-failure` (halmos#154)
- `dolmos.toml` configuration file and `@custom:dolmos` annotations
  (`halmos.toml`, `@custom:halmos` and `HALMOS_ALLOW_DOWNLOAD` remain accepted)
- PyPI package and Docker image `ghcr.io/dowsers/dolmos`

### Changed

- command, Python package and symbolic variable prefix renamed from `halmos` to
  `dolmos`; downloaded solvers are cached in `~/.dolmos/solvers`

### Fixed

- Vyper artifact lookup in the forge cache on Windows
- builds with forge ≥ 1.8: `dynamic_test_linking` is disabled when dolmos runs
  `forge build`, since it rewrites `new C()` into unsupported `vm.deployCode`
  calls

[Unreleased]: https://github.com/Dowsers/dolmos/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Dowsers/dolmos/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Dowsers/dolmos/releases/tag/v0.1.0
