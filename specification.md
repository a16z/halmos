# CLI options #

New option : 
detect-proxies
This option allows to choose between the verification of the implementation code from proxy or the proxy code.

# Modeling choices #

## CLZ operator ##


## Self Destruct ##

## Keccak256 256 operator ##

Simplified explanation

Dolmos models keccak256 using a family of uninterpreted functions, f_sha3_N, with one function for each input size. Instead of encoding the whole hash algorithm bit by bit—which would make SMT solving impractical—Dolmos only adds a few basic properties to these functions.

When the input is concrete, Dolmos computes the real keccak256 value and stores the input/output pair for that execution path. This makes it possible to recover the preimage of a concrete storage slot and decode it into its structure, such as the base slot, mapping keys, and offsets. When the input is symbolic, the hash remains uninterpreted and is constrained only by a small set of axioms. An inverse function guarantees injectivity, so two different inputs cannot have the same hash. Hash values are also assumed to be non-zero and smaller than 2^256 − 2^64, preventing a struct or array offset from overflowing when added to a hashed storage slot.

These assumptions are sound in practice, but they are deliberately incomplete: they do not formally connect the symbolic function to the real keccak256. As a result, the solver can invent a hash value. For example, it may choose an input whose symbolic hash matches a storage key written in setUp(), producing a counterexample that cannot actually be reproduced (halmos#562).

Dolmos handles this lazily through counterexample-guided refinement. When the solver finds a satisfiable model, Dolmos reads the concrete preimages chosen by the model, computes their real keccak256 values, adds facts such as f_sha3_N(v) = keccak256(v), and runs the solver again. Because these facts are true for the real hash function, a real counterexample is never removed. Therefore, an unsat result proves that no counterexample exists under the stated assumptions. If the model remains inconsistent after a bounded number of refinement rounds, or if refinement cannot determine whether it is valid, Dolmos still reports it but marks it as potentially invalid instead of silently discarding it.

Two additional design choices complete this approach. First, the optimizer may fold a keccak256 computation into a precomputed constant. If the resulting storage location is later decoded structurally, the value stored at the raw location is moved to the corresponding structured location (halmos#579). Second, the alternative generic storage layout can decode hashed storage keys purely structurally. This implicitly assumes that a hash cannot be equal to an unrelated constant.

Example: halmos#562

The issue halmos#562, reproduced in KeccakRefinement.t.sol, shows why this refinement mechanism is necessary. In setUp(), the contract executes balances[key] = 50, where key is a concrete value. The test then checks that balances[uint256(keccak256(abi.encodePacked(amt)))] != 50 for every symbolic amt.

When balances[key] is written, its storage location is keccak256(key . 0). Because the input is concrete, Dolmos computes the real hash and records it. It can therefore decode the storage location as (slot 0, key) rather than treating it as an arbitrary 256-bit value.

During the test, however, keccak256(amt) is symbolic. Dolmos represents it as h = f_sha3_256(amt), so the read becomes a lookup at (slot 0, h). The read returns 50 if h = key. The current axioms do not prevent this: injectivity only says that two different inputs cannot have the same hash. The solver can therefore invent a model such as amt = 0 together with f_sha3_256(0) = key. It reports sat, but this is a false counterexample because the real keccak256(0) is not equal to key.

Refinement then starts. Dolmos takes the model's preimage, 0, computes the real value of keccak256(0), and adds the constraint f_sha3_256(0) = keccak256(0). The previous model is now impossible. The solver may then try another value, for example amt = 1, with another invented hash. Dolmos adds the corresponding real hash and repeats the process. After the configured three refinement rounds (--keccak-refinement-rounds), the counterexample is reported as potentially invalid, rather than being presented as a valid exploit.

The same mechanism behaves differently when a real preimage exists. In check_keccak_known_preimage, the test searches for an amt such that keccak256(amt) == keccak256(42). The solver proposes amt = 42, and the refinement step confirms that this matches the real hash. The counterexample is therefore validated immediately.

The example also shows the effect of the two other modeling choices. With the generic storage layout, h is structurally understood as the hash of amt. It therefore cannot simply be treated as the unrelated constant key, so the problematic path can be eliminated before SMT solving. This is why the test uses the Solidity storage layout. Finally, if key were a compile-time constant, the optimizer could fold keccak256(key . 0) into a PUSH32 constant (halmos#579). The value would initially be stored under the raw location and then moved to the structured location when that location is later decoded. This is why the test keeps key in a state variable.
