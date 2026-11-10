# Warnings

Each warning printed by dolmos ends with a link to its section below.

## parsing-error

A build artifact in the forge output directory could not be parsed and was
skipped, so the contracts it defines are neither tested nor available to
`vm.getCode`/`deployCode`. Rebuild with `forge build --force`; if the artifact
comes from an unusual compiler setup, run with `--debug` to see the full error.

## internal-error

Symbolic execution hit a case dolmos does not handle, or a cheatcode was used
in a way it does not support (for instance `vm.ffi` without `--ffi`). The
affected path is dropped, so the result of the test may be incomplete. Run with
`--debug` for details, and report it if the input looks legitimate.

## library-placeholder

The bytecode still contains unlinked library placeholders (`__$...$__`). Only
libraries compiled in the same build can be linked; deploy or link external
libraries explicitly in `setUp()`.

## counterexample-invalid

The solver produced a model for a failing path, but replaying it did not
reproduce the failure. This usually comes from approximations in the symbolic
model (hash functions, unbounded arrays, precompiles). The test is still
reported as failing; inspect the counterexample before trusting it.

With `--pretty-counterexamples`, counterexamples relying on the approximation of
exponentiation are checked against the real `**` (and replaced by a valid
counterexample, or proven spurious, when possible), and the reason is printed when
they remain potentially invalid, e.g. a symbolic base and exponent, or keccak256
values that differ from the real hash function. See
[pretty counterexamples](pretty-counterexamples.md#potentially-invalid-counterexamples).

## counterexample-unknown

The solver could not decide whether a failing path is feasible within
`--solver-timeout-assertion`. The test is reported as a timeout rather than a
pass. Increase the timeout, try another `--solver`, or reduce the input space
with `vm.assume` and smaller `--array-lengths`.

## unsupported-opcode

An opcode dolmos does not implement was executed; the path is dropped.

## revert-all

Every path of the test reverted, so nothing was actually checked. Typical
causes: `vm.assume` conditions that can never hold, a `setUp()` state that makes
the target always revert, or input bounds that are too tight.

## loop-bound

Some paths were cut at the loop unrolling bound (`--loop`), so they have not
been fully explored and bugs beyond that bound can be missed. Raise `--loop`
(globally or with a `@custom:dolmos --loop N` annotation) if the loops in
question are bounded by a small constant.

To find out whether these loops terminate, export them with `--dump-lassos` and
analyse them with PaSTTeL: see [loop-termination.md](loop-termination.md).
