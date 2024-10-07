# Halmos Examples

#### Usage Examples

- [Simple examples](simple/test/)
- [ERC20](tokens/ERC20/test/): verifies OpenZeppelin, Solady, Solmate ERC20 tokens, and CurveTokenV3.
  - Includes identifying the DEI token bug exploited in the [Deus DAO hack](https://rekt.news/deus-dao-r3kt/).
- [ERC721](tokens/ERC721/test/): verifies OpenZeppelin, Solady, and Solmate ERC721 tokens.

#### Halmos Tests in External Projects

- [Morpho Blue] ([HalmosTest]): verifies the Morpho Blue protocol.
- [Farcaster] ([IdRegistrySymTest], [KeyRegistrySymTest]): verifies state machine invariants in Farcaster's onchain registry contracts.
- [Snekmate] ([ERC20TestHalmos], [ERC721TestHalmos], [ERC1155TestHalmos]): verifies Snekmate's Vyper token contracts.
- [Cicada] ([LibPrimeTest], [LibUint1024Test]): verifies Cicada's 1024-bit number arithmetic library.
- [Solady Verification]: verifies Solady's fixed-point math library.

[Morpho Blue]: <https://github.com/morpho-org/morpho-blue>
[HalmosTest]: <https://github.com/morpho-org/morpho-blue/blob/main/test/halmos/HalmosTest.sol>

[Snekmate]: <https://github.com/pcaversaccio/snekmate>
[ERC20TestHalmos]: <https://github.com/pcaversaccio/snekmate/blob/main/test/tokens/halmos/ERC20TestHalmos.t.sol>
[ERC721TestHalmos]: <https://github.com/pcaversaccio/snekmate/blob/main/test/tokens/halmos/ERC721TestHalmos.t.sol>
[ERC1155TestHalmos]: <https://github.com/pcaversaccio/snekmate/blob/main/test/tokens/halmos/ERC1155TestHalmos.t.sol>

[Cicada]: <https://github.com/a16z/cicada>
[LibPrimeTest]: <https://github.com/a16z/cicada/blob/c4dde7737778df759172ecdf7b4b044c60ce1f09/test/LibPrime.t.sol#L220-L232>
[LibUint1024Test]: <https://github.com/a16z/cicada/blob/c4dde7737778df759172ecdf7b4b044c60ce1f09/test/LibUint1024.t.sol#L222-L245>

[Farcaster]: <https://github.com/farcasterxyz/contracts>
[IdRegistrySymTest]: <https://github.com/farcasterxyz/contracts/blob/main/test/IdRegistry/IdRegistry.symbolic.t.sol>
[KeyRegistrySymTest]: <https://github.com/farcasterxyz/contracts/blob/main/test/KeyRegistry/KeyRegistry.symbolic.t.sol>

[Solady Verification]: <https://github.com/zobront/halmos-solady>

## Disclaimer

_These smart contracts and code are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts and code. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE SMART CONTRACTS AND CODE CONTAINED HEREIN ARE FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON-INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of these smart contracts and code may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts and code may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. a16z is not liable for any use of the foregoing, and users should proceed with caution and use at their own risk. See a16z.com/disclosures for more info._
