# Equivalence proofs of the keccak256 SAT encodings

Lean 4 proofs that the CNF encodings of `src/dolmos/keccak_sat.py` are equivalent to
keccak-f[1600]. See [docs/keccak-sat.md](../../docs/keccak-sat.md) for the statements
and for what is not covered.

```sh
lake build        # Lean 4.36.0, no dependency
python -m dolmos.keccak_sat lean-templates > KeccakSat/Templates.lean   # after a change of the templates
```
