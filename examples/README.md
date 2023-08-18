# Halmos Examples

#### Usage Examples

- [Simple examples](toy/README.md)
- [ERC20](tokens/ERC20/): verifying OpenZeppelin and Solmate ERC20 tokens, and finding the DEI token bug exploited by the [Deus DAO hack](https://rekt.news/deus-dao-r3kt/).
- [ERC721](tokens/ERC721/): verifying OpenZeppelin and Solmate ERC721 tokens.

#### Halmos Tests in External Projects

- [Morpho Data Structures] ([TestProveLogarithmicBuckets]): verifying Morpho's complex data structure.
- [Cicada] ([LibPrimeTest], [LibUint1024Test]): verifying Cicada's big (1024-bit) number arithmetic library.
- [Farcaster] ([IdRegistrySymTest], [KeyRegistrySymTest]): verifying the state machine invariants of Farcaster onchain registry contracts.
- [Solady Verification]: verifying the fixed-point math library of Solady.

[Morpho Data Structures]: <https://github.com/morpho-org/morpho-data-structures>
[TestProveLogarithmicBuckets]: <https://github.com/morpho-org/morpho-data-structures/blob/7f40c102e6bb852746d0d3c2f97ac3f39dae3c9c/test/TestLogarithmicBuckets.t.sol#L121-L182>

[Cicada]: <https://github.com/a16z/cicada>
[LibPrimeTest]: <https://github.com/a16z/cicada/blob/c4dde7737778df759172ecdf7b4b044c60ce1f09/test/LibPrime.t.sol#L220-L232>
[LibUint1024Test]: <https://github.com/a16z/cicada/blob/c4dde7737778df759172ecdf7b4b044c60ce1f09/test/LibUint1024.t.sol#L222-L245>

[Farcaster]: <https://github.com/farcasterxyz/contracts>
[IdRegistrySymTest]: <https://github.com/farcasterxyz/contracts/blob/e56b5765ca28a7df149fb434315df0188a6ab14a/test/IdRegistry/IdRegistry.st.sol>
[KeyRegistrySymTest]: <https://github.com/farcasterxyz/contracts/blob/e56b5765ca28a7df149fb434315df0188a6ab14a/test/KeyRegistry/KeyRegistry.st.sol>

[Solady Verification]: <https://github.com/zobront/halmos-solady>

## Disclaimer

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
