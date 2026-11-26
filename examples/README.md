# Dolmos Examples

#### Usage Examples

- [Simple examples](simple/test/)
- [Invariant testing](invariants/README.md)
- [ERC20](tokens/ERC20/test/): verifies OpenZeppelin, Solady, Solmate ERC20 tokens, and CurveTokenV3.
  - Includes identifying the DEI token bug exploited in the [Deus DAO hack](https://rekt.news/deus-dao-r3kt/).
- [ERC721](tokens/ERC721/test/): verifies OpenZeppelin, Solady, and Solmate ERC721 tokens.

#### Symbolic Tests in External Projects

These suites were written for halmos; thanks to dolmos' compatibility with
`@custom:halmos` annotations and `halmos.toml` they should run with dolmos as
they are.


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

_This software and the smart contracts in this repository are provided as is,
without warranty of any kind, express or implied, including any warranty of
merchantability, non-infringement or fitness for a particular purpose. They have
not been audited. Passing symbolic tests is not a proof that a contract is free
of bugs. Nothing in this repository is investment or legal advice. See
[NOTICE](../NOTICE) for the disclaimers attached to the original work this code is
derived from._
