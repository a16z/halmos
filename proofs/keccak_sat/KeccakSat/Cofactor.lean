/-
  Shannon cofactoring of keccak256 on the free bits of the message (`cofactor_cnf` of
  src/dolmos/keccak_sat.py): when the message has `k` free bits `x`, the circuit is replaced
  by the lookup of `x` in the table of the 2^k digests.

  The clauses use one selector variable `sel u` per entry `u` of the table:
    sel u → x[j] = u[j]            for each free bit j      (binary clauses)
    (∀ j, x[j] = u[j]) → sel u                              (one clause of k+1 literals)
    sel u → h[b] = (table u)[b]    for each digest bit b    (binary clauses)
-/
import KeccakSat.Encoding

namespace KeccakSat

/-- the clauses of the table lookup, at the bit level -/
def CofactorCnf {k n : Nat} (table : BitVec k → BitVec n) (x : BitVec k)
    (sel : BitVec k → Bool) (h : BitVec n) : Prop :=
  ∀ u : BitVec k,
    (∀ j : Fin k, sel u = true → x[j] = u[j]) ∧
    ((∀ j : Fin k, x[j] = u[j]) → sel u = true) ∧
    (∀ b : Fin n, sel u = true → h[b] = (table u)[b])

theorem bitVec_eq_iff_bits {k : Nat} (x u : BitVec k) : x = u ↔ ∀ j : Fin k, x[j] = u[j] := by
  constructor
  · rintro rfl j; rfl
  · intro h; apply BitVec.eq_of_getElem_eq; intro i hi; exact h ⟨i, hi⟩

/-- The clauses of the table lookup hold exactly when the selectors decode `x` and `h` is the
entry `x` of the table: the lookup is a sound and complete encoding of `h = table x`. -/
theorem cofactorCnf_iff {k n : Nat} (table : BitVec k → BitVec n) (x : BitVec k)
    (sel : BitVec k → Bool) (h : BitVec n) :
    CofactorCnf table x sel h ↔ (∀ u, sel u = decide (x = u)) ∧ h = table x := by
  constructor
  · intro hc
    have hsel : ∀ u, sel u = true ↔ x = u := fun u =>
      ⟨fun hs => (bitVec_eq_iff_bits x u).mpr (fun j => (hc u).1 j hs),
       fun hx => (hc u).2.1 ((bitVec_eq_iff_bits x u).mp hx)⟩
    refine ⟨?_, ?_⟩
    · intro u
      by_cases hx : x = u
      · simp [hx, (hsel u).mpr hx]
      · have : sel u ≠ true := fun hs => hx ((hsel u).mp hs)
        simp [hx, this]
    · exact (bitVec_eq_iff_bits h (table x)).mpr (fun b => (hc x).2.2 b ((hsel x).mpr rfl))
  · rintro ⟨hsel, rfl⟩ u
    refine ⟨?_, ?_, ?_⟩
    · intro j hs
      have : x = u := by simpa [hsel u] using hs
      rw [this]
    · intro hx
      simp [hsel u, (bitVec_eq_iff_bits x u).mpr hx]
    · intro b hs
      have : x = u := by simpa [hsel u] using hs
      rw [this]

/-- lane `i` (of the 4 digest lanes) as a slice of a 256-bit digest -/
def digestLane (h : BitVec 256) (i : Fin 4) : Lane := (h >>> (64 * i.val)).setWidth 64

/-- the keccak256 digest of a state: the lanes 0..3, lane 0 in the low bits -/
def digest (A : State) : BitVec 256 := A[3] ++ A[2] ++ A[1] ++ A[0]

theorem digestLane_concat (a0 a1 a2 a3 : Lane) :
    digestLane (a3 ++ a2 ++ a1 ++ a0) 0 = a0 ∧ digestLane (a3 ++ a2 ++ a1 ++ a0) 1 = a1 ∧
    digestLane (a3 ++ a2 ++ a1 ++ a0) 2 = a2 ∧ digestLane (a3 ++ a2 ++ a1 ++ a0) 3 = a3 := by
  simp only [digestLane]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> bv_decide

theorem digestLane_digest (A : State) (i : Fin 4) : digestLane (digest A) i = A[i.val] := by
  have h := digestLane_concat A[0] A[1] A[2] A[3]
  have : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 := by omega
  rcases this with rfl | rfl | rfl | rfl
  · exact h.1
  · exact h.2.1
  · exact h.2.2.1
  · exact h.2.2.2

/-- **Equivalence of the two encodings.** Let `embed x` be the initial state of the final
permutation for the value `x` of the free bits of the message. If an assignment satisfies
the clauses of the table lookup, with the table of the digests of the specification, and
another one satisfies the clauses of the circuit on the same message, then the digest
variables of both encodings have the same values, namely the keccak256 digest. -/
theorem cofactor_eq_circuit {k : Nat} (embed : BitVec k → State) (x : BitVec k)
    (sel : BitVec k → Bool) (h : BitVec 256) (S : Nat → State) (W : Nat → Aux)
    (hc : CofactorCnf (fun u => digest (keccakF (embed u))) x sel h)
    (hs : SqueezeCnf S W) (h0 : S 0 = embed x) (i : Fin 4) :
    digestLane h i = (S 24)[i.val] ∧ digestLane h i = (keccakF (embed x))[i.val] := by
  have hh := ((cofactorCnf_iff _ x sel h).mp hc).2
  have hS := squeezeCnf_sound hs ⟨i.val, by omega⟩ (by simp)
  rw [h0] at hS
  subst hh
  rw [digestLane_digest]
  exact ⟨hS.symm, rfl⟩

end KeccakSat
