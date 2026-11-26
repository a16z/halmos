/-
  Keccak-f[1600] reference specification (FIPS 202, section 3.2), on 25 lanes of 64 bits.

  Lane (x, y) is stored at index x + 5*y. This is the "specification side" of the
  equivalence proofs of `Encoding.lean`: nothing here is optimized.
-/
namespace KeccakSat

abbrev Lane := BitVec 64
abbrev State := Vector Lane 25

/-- index of lane (x, y) -/
def idx (x y : Fin 5) : Fin 25 := ⟨x.val + 5 * y.val, by omega⟩
def xOf (i : Fin 25) : Fin 5 := ⟨i.val % 5, by omega⟩
def yOf (i : Fin 25) : Fin 5 := ⟨i.val / 5, by omega⟩

theorem idx_xOf_yOf (i : Fin 25) : idx (xOf i) (yOf i) = i := by
  apply Fin.ext; simp [idx, xOf, yOf]; omega

/-- round constants of iota -/
def RC : Vector Lane 24 := #v[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

/-- rotation offsets of rho, indexed by x + 5*y -/
def ROT : Vector Nat 25 := #v[
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14]

/-- column parity -/
def colParity (A : State) (x : Fin 5) : Lane :=
  A[idx x 0] ^^^ A[idx x 1] ^^^ A[idx x 2] ^^^ A[idx x 3] ^^^ A[idx x 4]

/-- theta effect -/
def thetaD (A : State) (x : Fin 5) : Lane :=
  colParity A (x + 4) ^^^ (colParity A (x + 1)).rotateLeft 1

def theta (A : State) : State := Vector.ofFn fun i => A[i] ^^^ thetaD A (xOf i)

/-- source lane of the lane (X, Y) after pi: (x, y) = (X + 3Y, X) -/
def piSrc (i : Fin 25) : Fin 25 := idx (xOf i + 3 * yOf i) (xOf i)

/-- rho followed by pi -/
def rhoPi (A : State) : State := Vector.ofFn fun i => (A[piSrc i]).rotateLeft ROT[piSrc i]

def chi (B : State) : State := Vector.ofFn fun i =>
  B[i] ^^^ (~~~B[idx (xOf i + 1) (yOf i)] &&& B[idx (xOf i + 2) (yOf i)])

/-- the constant xored into lane `i` by iota at round `r` -/
def iotaMask (r : Fin 24) (i : Fin 25) : Lane := if i.val = 0 then RC[r] else 0

def iota (r : Fin 24) (A : State) : State := Vector.ofFn fun i => A[i] ^^^ iotaMask r i

def round (r : Fin 24) (A : State) : State := iota r (chi (rhoPi (theta A)))

/-- the first `n` rounds -/
def rounds : (n : Nat) → n ≤ 24 → State → State
  | 0, _, A => A
  | n + 1, h, A => round ⟨n, by omega⟩ (rounds n (by omega) A)

def keccakF (A : State) : State := rounds 24 (Nat.le_refl _) A

/-! ### Sanity check of the specification: keccak256 of the empty string

The padded block of the empty message is `01 00 ... 00 80` (136 bytes), i.e. lane 0 = 1 and
lane 16 = 2^63. The digest is `c5d24601 86f7233c 927e7db2 dcc703c0 e500b653 ca82273b
7bfad804 5d85a470`, read as four little-endian lanes. -/
def emptyBlock : State :=
  Vector.ofFn fun i => if i.val = 0 then 1 else if i.val = 16 then 0x8000000000000000 else 0

#guard (keccakF emptyBlock)[0] == 0x3c23f7860146d2c5#64
#guard (keccakF emptyBlock)[1] == 0xc003c7dcb27d7e92#64
#guard (keccakF emptyBlock)[2] == 0x3b2782ca53b600e5#64
#guard (keccakF emptyBlock)[3] == 0x70a4855d04d8fa7b#64

end KeccakSat
