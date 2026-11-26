/-
  Equivalence between the optimized CNF encoding of keccak-f[1600] produced by
  `KeccakCNF(optimized=True)` (src/dolmos/keccak_sat.py) and the specification of `Spec.lean`.

  The encoding is modeled in bit-sliced form: its variables are grouped in lanes of 64 bits,
  and each clause template of `Templates.lean` is instantiated at the 64 bit positions.
  Rotations (rho, and the rotation of theta) are renamings of the bit variables, and iota
  flips the polarity of the output literals of the chi gates of lane 0.
-/
import KeccakSat.Spec
import KeccakSat.Templates

namespace KeccakSat

/-- the auxiliary variables of one round -/
structure Aux where
  /-- parity of the lanes y = 0, 1, 2 of a column -/
  P : Fin 5 → Lane
  /-- column parities -/
  C : Fin 5 → Lane
  /-- theta effect -/
  D : Fin 5 → Lane
  /-- state after theta -/
  T : Fin 25 → Lane

theorem Aux.eq_of_fields {w v : Aux} (hP : w.P = v.P) (hC : w.C = v.C) (hD : w.D = v.D)
    (hT : w.T = v.T) : w = v := by
  cases w; cases v; simp_all

/-- the auxiliary variables are functions of the input state -/
def auxOf (A : State) : Aux where
  P x := A[idx x 0] ^^^ A[idx x 1] ^^^ A[idx x 2]
  C x := colParity A x
  D x := thetaD A x
  T i := (theta A)[i]

/-- input lane `i` of chi: a theta lane, with its bit variables renamed by rho and pi -/
def bLane (w : Aux) (i : Fin 25) : Lane := (w.T (piSrc i)).rotateLeft ROT[piSrc i]

/-- column parities (two 3-input xors per column) and theta effect (one 2-input xor) -/
def ThetaCnf (A : State) (w : Aux) : Prop :=
  (∀ x : Fin 5, xor3Cnf A[idx x 0] A[idx x 1] A[idx x 2] (w.P x)) ∧
  (∀ x : Fin 5, xor3Cnf (w.P x) A[idx x 3] A[idx x 4] (w.C x)) ∧
  (∀ x : Fin 5, xor2Cnf (w.C (x + 4)) ((w.C (x + 1)).rotateLeft 1) (w.D x))

/-- theta lane `i` -/
def TLaneCnf (A : State) (w : Aux) (i : Fin 25) : Prop :=
  xor2Cnf A[i] (w.D (xOf i)) (w.T i)

/-- output lane `i` of the round: one chi gate per bit, with the polarity flips of iota -/
def ChiLaneCnf (r : Fin 24) (w : Aux) (A' : State) (i : Fin 25) : Prop :=
  chiCnf (bLane w i) (bLane w (idx (xOf i + 1) (yOf i))) (bLane w (idx (xOf i + 2) (yOf i)))
    (A'[i] ^^^ iotaMask r i)

/-- the clauses of a full round, from the state `A` to the state `A'` -/
def RoundCnf (r : Fin 24) (A : State) (w : Aux) (A' : State) : Prop :=
  ThetaCnf A w ∧ (∀ i, TLaneCnf A w i) ∧ (∀ i, ChiLaneCnf r w A' i)

/-- The clauses of the last round of keccak256: only the lanes 0..3 of the result are
computed, which only read the row y = 0 of the chi inputs, i.e. 5 theta lanes. -/
def LastRoundCnf (r : Fin 24) (A : State) (w : Aux) (A' : State) : Prop :=
  ThetaCnf A w ∧ (∀ i : Fin 25, i.val < 5 → TLaneCnf A w (piSrc i)) ∧
  (∀ i : Fin 25, i.val < 4 → ChiLaneCnf r w A' i)

/-! ### One round -/

theorem thetaCnf_iff (A : State) (w : Aux) :
    ThetaCnf A w ↔ w.P = (auxOf A).P ∧ w.C = (auxOf A).C ∧ w.D = (auxOf A).D := by
  simp only [ThetaCnf, xor3Cnf_iff, xor2Cnf_iff, auxOf, funext_iff]
  constructor
  · rintro ⟨hP, hC, hD⟩
    have hC' : ∀ x, w.C x = colParity A x := by intro x; rw [hC, hP]; rfl
    refine ⟨hP, hC', ?_⟩
    intro x; rw [hD, hC', hC']; rfl
  · rintro ⟨hP, hC, hD⟩
    refine ⟨hP, ?_, ?_⟩
    · intro x; rw [hC, hP]; rfl
    · intro x; rw [hD, hC, hC]; rfl

theorem tLane_eq {A : State} {w : Aux} (hD : w.D = (auxOf A).D) (i : Fin 25)
    (h : TLaneCnf A w i) : w.T i = (theta A)[i] := by
  rw [TLaneCnf, xor2Cnf_iff] at h
  rw [h, hD]; simp [auxOf, theta]

theorem bLane_eq {A : State} {w : Aux} (i : Fin 25) (h : w.T (piSrc i) = (theta A)[piSrc i]) :
    bLane w i = (rhoPi (theta A))[i] := by
  simp [bLane, rhoPi, h]

theorem xor_eq_iff (a b m : Lane) : a ^^^ m = b ↔ a = b ^^^ m := by
  constructor <;> (intro h; subst h; rw [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero])

theorem chiLane_iff {r : Fin 24} {A : State} {w : Aux} {A' : State} (i : Fin 25)
    (h0 : bLane w i = (rhoPi (theta A))[i])
    (h1 : bLane w (idx (xOf i + 1) (yOf i)) = (rhoPi (theta A))[idx (xOf i + 1) (yOf i)])
    (h2 : bLane w (idx (xOf i + 2) (yOf i)) = (rhoPi (theta A))[idx (xOf i + 2) (yOf i)]) :
    ChiLaneCnf r w A' i ↔ A'[i] = (round r A)[i] := by
  rw [ChiLaneCnf, chiCnf_iff, h0, h1, h2, xor_eq_iff]
  simp [round, iota, chi]

/-- soundness and completeness of the clauses of a round: they hold exactly when the
auxiliary variables and the output state have the values of the specification -/
theorem roundCnf_iff (r : Fin 24) (A : State) (w : Aux) (A' : State) :
    RoundCnf r A w A' ↔ w = auxOf A ∧ A' = round r A := by
  constructor
  · rintro ⟨hθ, hT, hχ⟩
    obtain ⟨hP, hC, hD⟩ := (thetaCnf_iff A w).mp hθ
    have hT' : ∀ i, w.T i = (theta A)[i] := fun i => tLane_eq hD i (hT i)
    refine ⟨?_, ?_⟩
    · exact Aux.eq_of_fields hP hC hD (funext hT')
    · apply Vector.ext; intro i hi
      exact (chiLane_iff (r := r) (A' := A') ⟨i, hi⟩ (bLane_eq _ (hT' _)) (bLane_eq _ (hT' _))
        (bLane_eq _ (hT' _))).mp (hχ ⟨i, hi⟩)
  · rintro ⟨rfl, rfl⟩
    have hT' : ∀ i, (auxOf A).T i = (theta A)[i] := fun _ => rfl
    refine ⟨(thetaCnf_iff A _).mpr ⟨rfl, rfl, rfl⟩, ?_, ?_⟩
    · intro i; rw [TLaneCnf, xor2Cnf_iff]; simp [auxOf, theta]
    · intro i
      exact (chiLane_iff i (bLane_eq _ (hT' _)) (bLane_eq _ (hT' _)) (bLane_eq _ (hT' _))).mpr rfl

/-! ### The truncated last round -/

theorem idx_lt_five (x : Fin 5) : (idx x 0).val < 5 := by simp [idx]

theorem yOf_eq_zero (i : Fin 25) (h : i.val < 5) : yOf i = 0 := by
  apply Fin.ext; simp [yOf]; omega

/-- the clauses of a full round imply the ones of the truncated round -/
theorem lastRoundCnf_of_roundCnf {r : Fin 24} {A : State} {w : Aux} {A' : State}
    (h : RoundCnf r A w A') : LastRoundCnf r A w A' :=
  ⟨h.1, fun i _ => h.2.1 (piSrc i), fun i _ => h.2.2 i⟩

/-- the truncated round computes the lanes 0..3 of the specification -/
theorem lastRoundCnf_sound {r : Fin 24} {A : State} {w : Aux} {A' : State}
    (h : LastRoundCnf r A w A') (i : Fin 25) (hi : i.val < 4) : A'[i] = (round r A)[i] := by
  obtain ⟨hθ, hT, hχ⟩ := h
  obtain ⟨-, -, hD⟩ := (thetaCnf_iff A w).mp hθ
  have hB : ∀ j : Fin 25, j.val < 5 → bLane w j = (rhoPi (theta A))[j] :=
    fun j hj => bLane_eq j (tLane_eq hD _ (hT j hj))
  have hy : yOf i = 0 := yOf_eq_zero i (by omega)
  refine (chiLane_iff i (hB i (by omega)) (hB _ ?_) (hB _ ?_)).mp (hχ i hi) <;>
    (rw [hy]; exact idx_lt_five _)

/-! ### The permutation -/

/-- The clauses of keccak-f[1600] without truncation (absorption of a non final block):
`S r` is the state before round `r`, and `W r` the auxiliary variables of round `r`. -/
def PermCnf (S : Nat → State) (W : Nat → Aux) : Prop :=
  ∀ r (h : r < 24), RoundCnf ⟨r, h⟩ (S r) (W r) (S (r + 1))

/-- The clauses of the final keccak-f[1600] of keccak256: 23 full rounds and a truncated one. -/
def SqueezeCnf (S : Nat → State) (W : Nat → Aux) : Prop :=
  (∀ r (h : r < 23), RoundCnf ⟨r, by omega⟩ (S r) (W r) (S (r + 1))) ∧
  LastRoundCnf ⟨23, by omega⟩ (S 23) (W 23) (S 24)

theorem rounds_of_roundCnf {S : Nat → State} {W : Nat → Aux} (n : Nat) (hn : n ≤ 24)
    (h : ∀ r (h : r < n), RoundCnf ⟨r, by omega⟩ (S r) (W r) (S (r + 1))) :
    S n = rounds n hn (S 0) := by
  induction n with
  | zero => rfl
  | succ n ih =>
    have := ((roundCnf_iff _ _ _ _).mp (h n (by omega))).2
    rw [this, ih (by omega) (fun r hr => h r (by omega))]; rfl

/-- soundness: any assignment satisfying the clauses of the permutation maps the input
state to its image by keccak-f[1600] -/
theorem permCnf_sound {S : Nat → State} {W : Nat → Aux} (h : PermCnf S W) :
    S 24 = keccakF (S 0) :=
  rounds_of_roundCnf 24 (Nat.le_refl _) (fun r hr => h r hr)

/-- soundness of the encoding with a truncated last round: the lanes 0..3 of the result,
i.e. the keccak256 digest, are those of keccak-f[1600] -/
theorem squeezeCnf_sound {S : Nat → State} {W : Nat → Aux} (h : SqueezeCnf S W)
    (i : Fin 25) (hi : i.val < 4) : (S 24)[i] = (keccakF (S 0))[i] := by
  rw [lastRoundCnf_sound h.2 i hi, rounds_of_roundCnf 23 (by omega) h.1]; rfl

/-- the states of the specification, as an assignment of the state variables -/
def specStates (A : State) (n : Nat) : State :=
  if h : n ≤ 24 then rounds n h A else A

/-- completeness: for any input state, the values of the specification satisfy the clauses
(with or without truncation), hence the encoding does not exclude any input -/
theorem permCnf_complete (A : State) :
    PermCnf (specStates A) (fun r => auxOf (specStates A r)) := by
  intro r hr
  refine (roundCnf_iff _ _ _ _).mpr ⟨rfl, ?_⟩
  simp only [specStates, show r ≤ 24 by omega, show r + 1 ≤ 24 by omega, dite_true]; rfl

theorem squeezeCnf_complete (A : State) :
    SqueezeCnf (specStates A) (fun r => auxOf (specStates A r)) :=
  ⟨fun r hr => permCnf_complete A r (by omega),
   lastRoundCnf_of_roundCnf (permCnf_complete A 23 (by omega))⟩

theorem specStates_zero (A : State) : specStates A 0 = A := rfl

theorem specStates_final (A : State) : specStates A 24 = keccakF A := rfl

end KeccakSat
