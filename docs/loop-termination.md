# Loop termination analysis with PaSTTeL (experimental)

dolmos explores loops by unrolling them up to a bound (`--loop`, 2 by default). When a
path would need more iterations, it is dropped and the test reports
`bounds: [...]`: the exploration is incomplete, and nothing is known about the loop
itself.

With `--dump-lassos`, every loop that reaches the unrolling bound is exported as a
*lasso program*, which [PaSTTeL](https://github.com/Dowsers/PaSTTeL) can analyse to
prove termination (with a ranking function) or non-termination.

- [Usage](#usage)
- [Reading the results](#reading-the-results)
- [How a loop becomes a lasso](#how-a-loop-becomes-a-lasso)
- [From bitvectors to integers](#from-bitvectors-to-integers)
- [The small-constants encoding (PaSTTeL workaround)](#the-small-constants-encoding-pasttel-workaround)
- [Limitations](#limitations)

## Usage

```bash
# export the lassos only
dolmos --dump-lassos lassos/

# export and analyse them
dolmos --dump-lassos lassos/ --pasttel /path/to/pasttel [--pasttel-timeout 30]
```

| Option | Description |
|---|---|
| `--dump-lassos DIR` | export each loop that reaches the unrolling bound to `DIR` |
| `--pasttel BINARY` | run PaSTTeL on each exported lasso and report the verdict |
| `--pasttel-timeout SECONDS` | time limit per PaSTTeL run (default: 30) |
| `--lasso-exact-constants` | exact wrap-around encoding with 2^256 constants, for tools with exact arithmetic (not PaSTTeL, see below) |

The option has no effect on the test results: the extraction runs on a separate
solver, and a failed extraction is reported without affecting the test.

For each loop, three files are written:

- `<test>_<loop id>_<branch>.json`: the lasso, in PaSTTeL's JSON trace format
- `<test>_<loop id>_<branch>.meta.json`: which stack slots the program variables
  `v0, v1, ...` stand for, the number of body paths, the encoding, and warnings
- `<test>_<loop id>_<branch>.pasttel.txt`: PaSTTeL's output (with `--pasttel`)

and a line is printed after the test result:

```
[PASS] check_count_down(uint256) (paths: 5, time: 0.15s, bounds: [])
    loop 2129:473 (false branch): TERMINATING [RankingBased(AffineTemplate): v0] -> lassos/check_count_down_2129_473_f.json
```

## Reading the results

- **TERMINATING**, with a ranking function: the loop terminates. This result is
  reliable: the lasso over-approximates the behaviours of the loop, and a proof for
  more behaviours is a proof for the actual ones.
- **NON-TERMINATING**: PaSTTeL found an infinite execution *of the lasso*. If the lasso
  is exact (`"exact": true` in the metadata), the witness is an infinite execution of
  the loop. Otherwise the verdict is printed as *unconfirmed*: the witness may rely on
  behaviours that the over-approximation introduced.
- **UNKNOWN / TIMEOUT**: no conclusion.
- **Warnings**:
  - `storage written in the loop body`: only stack variables are tracked (see
    [Limitations](#limitations)). If the loop condition depends on a storage slot
    written in the body, the result is not reliable, including a TERMINATING verdict.
  - `body path not explored`, `too many body paths`, `step budget exhausted`: the
    extraction is incomplete; the result is only indicative.

## How a loop becomes a lasso

A lasso is a *stem* (how the execution reaches the loop) followed by a *loop*
transition that repeats forever. dolmos builds both from the symbolic execution:

1. **Loop variables.** At each visit of a symbolic `JUMPI`, the stack is recorded.
   When the unrolling bound is reached, the stack slots that differ from the previous
   visit are the loop variables.
2. **Cut point.** The lasso is cut right after the `JUMPI`, on the branch that
   stays in the loop. The bound is often reached on a `JUMPI` inside an internal
   function that solc generates (e.g. checked arithmetic): any point of the cycle is
   a valid cut point, but it must be identified precisely. Like the unrolling
   counters, dolmos uses the program counter and the jump destinations on the stack,
   plus the stack height to tell apart the call sites of the same internal function.
3. **Generalized iteration.** The loop body is executed once more from a state where
   the loop variables are fresh symbols, until the execution is back at the cut
   point in the same frame. Each path that comes back *and takes the loop branch
   again* is a disjunct of the loop transition. This execution runs on a separate
   solver, with its own step budget.
4. **Stem.** The path condition up to the cut point, sliced to the conditions that
   relate to the initial values of the loop variables.

Subterms that don't depend on the loop variables (inputs, values read before the
loop) become constant program variables, shared by the stem and the loop: without
them, `for (i = 0; i < n; i++)` could not be proven, as `n` would change at every
iteration.

## From bitvectors to integers

EVM words are 256-bit bitvectors; PaSTTeL works on integers. Every w-bit value
becomes an integer `x` with `0 <= x`, and:

| Bitvector | Integer encoding |
|---|---|
| `bvadd`, `bvsub`, `bvneg`, `bvmul`/`bvshl` by a constant | exact, with the wrap-around made explicit (see below) |
| `bvudiv`, `bvurem`, `bvlshr` by a constant, `extract`, `concat`, `zero_extend` | exact, with a quotient `q` such that `c*q <= a <= c*q + c - 1` |
| unsigned comparisons, boolean connectives | exact |
| `ite` | a fresh variable and a disjunction (PaSTTeL doesn't parse arithmetic `ite`) |
| anything else (keccak, storage and memory reads, bitwise operations, nonlinear arithmetic...) | a fresh variable: over-approximation |

## The small-constants encoding (PaSTTeL workaround)

### The problem

The natural encoding of a wrap-around is `r = e - 2^256 * k`. It needs 2^256
constants, and PaSTTeL cannot represent them: it parses and stores numbers as C++
`double` (`std::stod` in its SMT parser, `double` coefficients in `AffineTerm`),
which are exact for integers up to 2^53 only. 2^256 and 2^256 - 1 become the same
number, and the analysis becomes unsound. In our experiments, PaSTTeL reported a
simple countdown loop as non-terminating, with a witness that is impossible even over
the rationals; it also produced ranking functions with coefficients equal to
`DBL_MAX`, and, worse, a termination proof for a loop that does not terminate (see
[Results](#results)).

(A second, independent issue: ranking function synthesis works over the rationals.
With a free integer `k`, a fractional `k` allows any result, so the encoding
`r = e - 2^256 * k` loses all precision even with exact arithmetic. The exact
encoding therefore uses one disjunct per possible value of `k`.)

The proper fix is exact rational arithmetic in PaSTTeL. Until then, dolmos produces
lassos without large constants: this is the default encoding.

### The encoding

No literal in the lasso exceeds 2^52 (this is checked before writing the file).

1. **Wrap-arounds are proven absent when possible.** For each addition, subtraction
   or multiplication by a constant, dolmos asks z3, with the bitvector semantics,
   whether the operation can wrap around on the path. If it cannot, the result is
   the plain integer expression (`x + 1`, `x - 1`), which is exact.
   - With checked arithmetic (Solidity >= 0.8), the overflow checks are on the path,
     so the proof usually succeeds.
   - `x - 1` is compiled as `x + (2^256 - 1)`: an addition of a constant `C >=
     2^255` is handled as a subtraction of `2^256 - C`, with the borrow condition
     `x >= 1`.
2. **The prover knows how the iteration was entered.** An increment `i + 1` only
   wraps around if `i = 2^256 - 1`, which is excluded by the loop condition `i < n`
   checked *before* the iteration, i.e. at the end of the previous one. The prover is
   given this fact, as a disjunction over the body paths with renamed variables. It
   is valid because the unrolling bound was reached (so there was a previous
   iteration), and only used when the body paths are complete.
3. **Facts about the inputs are used.** The path conditions of the stem are about
   input symbols, which never change: they hold at every iteration. For instance,
   `vm.assume(n < 1000)` lets the prover show that `i += 3` doesn't wrap while
   `i < n`.
4. **Otherwise, a sound over-approximation without large constants:**
   - addition, multiplication (the result can only wrap downwards): `0 <= r <= e`
   - subtraction (the result can only wrap upwards):
     `(e >= 0 and r = e) or e < 0`, where `r` is unconstrained in the second case
   - truncation (`extract`, masks): same as addition
   - division or remainder by a large constant: `0 <= q <= a`
5. **Large literals become constant program variables** (`c0, c1, ...`), constrained
   by their order (`0 <= c0 < c1 < ...`): comparisons such as `x < 2^200` keep their
   structure.
6. **Upper bounds `x < 2^256` are dropped** (only `0 <= x` is kept): an
   over-approximation.
7. **Signed comparisons** are exact when both operands are provably below 2^255
   (then they are unsigned comparisons); otherwise they are over-approximated.

The metadata records the encoding and whether the lasso is exact
(`"exact": false` as soon as one over-approximation was used).

### Results

On a set of test loops (countdown, count-up, `unchecked` step of 3, loops leaving
through a wrap-around):

| Loop | exact encoding (`--lasso-exact-constants`) | small-constants encoding (default) |
|---|---|---|
| `while (x > 0) x -= 1;` | TERMINATING, coefficients ~2^251 (unreliable) | TERMINATING, rank `v0` |
| `for (i = 0; i < n; i++) s += 1;` | TERMINATING, huge coefficients (unreliable) | TERMINATING, rank `5·k0 + v0 − 3·v1 − 3` |
| `while (i < n) unchecked { i += 3; }` (`n < 1000`) | TERMINATING, huge coefficients (unreliable) | TERMINATING, rank `8·k0 − 2·v0 − 27` |
| `while (x != 0) { unchecked { x -= 2; } if (x > 1000) break; }` | TERMINATING, rank `10·v0 − 1` | TERMINATING, rank `10·v0 + 19` |
| `while (x != 0) unchecked { x -= 2; }` (non-terminating for odd `x`) | **TERMINATING (wrong)** | NON-TERMINATING, unconfirmed (correct) |

The fourth loop terminates: for odd `x`, `x - 2` eventually wraps around to
`2^256 - 1 > 1000`. An earlier version of the extraction, with the exact encoding,
reported it and the countdown loop as non-terminating.

On the regression suite, the 20 loops reaching the bound are all extracted; the
test results are unchanged.

### Exact encoding

`--lasso-exact-constants` produces the exact encoding (2^256 constants, one
disjunct per wrap-around case). It is meant for termination tools with exact
arithmetic; with the current PaSTTeL, its results are unreliable.

## Limitations

- **Only stack variables are tracked.** Storage and memory are not generalized:
  values read from them are either constants (if they don't depend on the loop
  variables) or fresh values. Loops whose body writes to storage are flagged.
  Loops that index memory with the loop counter (`arr[i]` on a memory array) often
  cannot be extracted, as dolmos doesn't support symbolic memory offsets.
- **Non-termination is not confirmed.** A NON-TERMINATING verdict on an
  over-approximated lasso would need to be replayed with the bitvector semantics;
  this is not implemented yet.
- **Loops whose condition becomes constant are not exported.** dolmos only applies
  the unrolling bound to loops whose condition is symbolic. A loop that makes no
  progress, like `while (x > y) {}`, has a condition that becomes known after the
  first iteration: dolmos keeps unrolling it forever, and the bound, hence the export,
  is never reached. This is an existing dolmos limitation.
- **One cut point per loop and branch** is exported per test; the lasso describes
  the loop from that point, with the paths found from the state where the bound was
  reached.
- The ranking function proves termination, but it is not used yet to raise the
  unrolling bound of the loop.
