import KeccakSat.Spec
import KeccakSat.Templates
import KeccakSat.Encoding
import KeccakSat.Cofactor

/-! Axioms used by the main theorems (expected: propext, Classical.choice, Quot.sound, and
`Lean.ofReduceBool` for the SAT certificates checked by `bv_decide`). -/
open KeccakSat in
#print axioms roundCnf_iff
open KeccakSat in
#print axioms squeezeCnf_sound
open KeccakSat in
#print axioms squeezeCnf_complete
open KeccakSat in
#print axioms cofactorCnf_iff
open KeccakSat in
#print axioms cofactor_eq_circuit
