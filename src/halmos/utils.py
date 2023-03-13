# SPDX-License-Identifier: AGPL-3.0

from typing import Dict
from collections import defaultdict

def color_good(text: str) -> str:
    return '\033[32m' + text + '\033[0m'

def color_warn(text: str) -> str:
    return '\033[31m' + text + '\033[0m'

opcodes : Dict[str, str] = {
    '00' : 'STOP',
    '01' : 'ADD',
    '02' : 'MUL',
    '03' : 'SUB',
    '04' : 'DIV',
    '05' : 'SDIV',
    '06' : 'MOD',
    '07' : 'SMOD',
    '08' : 'ADDMOD',
    '09' : 'MULMOD',
    '0a' : 'EXP',
    '0b' : 'SIGNEXTEND',
    '10' : 'LT',
    '11' : 'GT',
    '12' : 'SLT',
    '13' : 'SGT',
    '14' : 'EQ',
    '15' : 'ISZERO',
    '16' : 'AND',
    '17' : 'OR',
    '18' : 'XOR',
    '19' : 'NOT',
    '1a' : 'BYTE',
    '1b' : 'SHL',
    '1c' : 'SHR',
    '1d' : 'SAR',
    '20' : 'SHA3',
    '30' : 'ADDRESS',
    '31' : 'BALANCE',
    '32' : 'ORIGIN',
    '33' : 'CALLER',
    '34' : 'CALLVALUE',
    '35' : 'CALLDATALOAD',
    '36' : 'CALLDATASIZE',
    '37' : 'CALLDATACOPY',
    '38' : 'CODESIZE',
    '39' : 'CODECOPY',
    '3a' : 'GASPRICE',
    '3b' : 'EXTCODESIZE',
    '3c' : 'EXTCODECOPY',
    '3d' : 'RETURNDATASIZE',
    '3e' : 'RETURNDATACOPY',
    '3f' : 'EXTCODEHASH',
    '40' : 'BLOCKHASH',
    '41' : 'COINBASE',
    '42' : 'TIMESTAMP',
    '43' : 'NUMBER',
    '44' : 'DIFFICULTY',
    '45' : 'GASLIMIT',
    '46' : 'CHAINID',
    '47' : 'SELFBALANCE',
    '50' : 'POP',
    '51' : 'MLOAD',
    '52' : 'MSTORE',
    '53' : 'MSTORE8',
    '54' : 'SLOAD',
    '55' : 'SSTORE',
    '56' : 'JUMP',
    '57' : 'JUMPI',
    '58' : 'PC',
    '59' : 'MSIZE',
    '5a' : 'GAS',
    '5b' : 'JUMPDEST',
    '60' : 'PUSH1',
    '61' : 'PUSH2',
    '62' : 'PUSH3',
    '63' : 'PUSH4',
    '64' : 'PUSH5',
    '65' : 'PUSH6',
    '66' : 'PUSH7',
    '67' : 'PUSH8',
    '68' : 'PUSH9',
    '69' : 'PUSH10',
    '6a' : 'PUSH11',
    '6b' : 'PUSH12',
    '6c' : 'PUSH13',
    '6d' : 'PUSH14',
    '6e' : 'PUSH15',
    '6f' : 'PUSH16',
    '70' : 'PUSH17',
    '71' : 'PUSH18',
    '72' : 'PUSH19',
    '73' : 'PUSH20',
    '74' : 'PUSH21',
    '75' : 'PUSH22',
    '76' : 'PUSH23',
    '77' : 'PUSH24',
    '78' : 'PUSH25',
    '79' : 'PUSH26',
    '7a' : 'PUSH27',
    '7b' : 'PUSH28',
    '7c' : 'PUSH29',
    '7d' : 'PUSH30',
    '7e' : 'PUSH31',
    '7f' : 'PUSH32',
    '80' : 'DUP1',
    '81' : 'DUP2',
    '82' : 'DUP3',
    '83' : 'DUP4',
    '84' : 'DUP5',
    '85' : 'DUP6',
    '86' : 'DUP7',
    '87' : 'DUP8',
    '88' : 'DUP9',
    '89' : 'DUP10',
    '8a' : 'DUP11',
    '8b' : 'DUP12',
    '8c' : 'DUP13',
    '8d' : 'DUP14',
    '8e' : 'DUP15',
    '8f' : 'DUP16',
    '90' : 'SWAP1',
    '91' : 'SWAP2',
    '92' : 'SWAP3',
    '93' : 'SWAP4',
    '94' : 'SWAP5',
    '95' : 'SWAP6',
    '96' : 'SWAP7',
    '97' : 'SWAP8',
    '98' : 'SWAP9',
    '99' : 'SWAP10',
    '9a' : 'SWAP11',
    '9b' : 'SWAP12',
    '9c' : 'SWAP13',
    '9d' : 'SWAP14',
    '9e' : 'SWAP15',
    '9f' : 'SWAP16',
    'a0' : 'LOG0',
    'a1' : 'LOG1',
    'a2' : 'LOG2',
    'a3' : 'LOG3',
    'a4' : 'LOG4',
    'f0' : 'CREATE',
    'f1' : 'CALL',
    'f2' : 'CALLCODE',
    'f3' : 'RETURN',
    'f4' : 'DELEGATECALL',
    'f5' : 'CREATE2',
    'fa' : 'STATICCALL',
    'fd' : 'REVERT',
    'fe' : 'INVALID',
    'ff' : 'SELFDESTRUCT',
#   'ff' : 'SUICIDE',
}

def groupby_gas(cnts: Dict[str,int]) -> Dict[str,int]:
    new_cnts = defaultdict(int)

    for (op, cnt) in cnts.items():
        if (
               op == 'STOP'
            or op == 'RETURN'
            or op == 'REVERT'
        ):
            new_cnts['_0_zero'] += cnt
        elif (
               op == 'JUMPDEST'
        ):
            new_cnts['_1_jumpdest'] += cnt
        elif (
               op == 'ADDRESS'
            or op == 'ORIGIN'
            or op == 'CALLER'
            or op == 'CALLVALUE'
            or op == 'CALLDATASIZE'
            or op == 'RETURNDATASIZE'
            or op == 'CODESIZE'
            or op == 'GASPRICE'
            or op == 'COINBASE'
            or op == 'TIMESTAMP'
            or op == 'NUMBER'
            or op == 'DIFFICULTY'
            or op == 'GASLIMIT'
            or op == 'POP'
            or op == 'PC'
            or op == 'MSIZE'
            or op == 'GAS'
            or op == 'CHAINID'
        ):
            new_cnts['_2_base'] += cnt
        elif (
               op == 'ADD'
            or op == 'SUB'
            or op == 'NOT'
            or op == 'LT'
            or op == 'GT'
            or op == 'SLT'
            or op == 'SGT'
            or op == 'EQ'
            or op == 'ISZERO'
            or op == 'AND'
            or op == 'OR'
            or op == 'XOR'
            or op == 'BYTE'
            or op == 'SHL'
            or op == 'SHR'
            or op == 'SAR'
            or op == 'CALLDATALOAD'
            or op == 'MLOAD'
            or op == 'MSTORE'
            or op == 'MSTORE8'
            or op == 'PUSH1' or op == 'PUSH2' or op == 'PUSH3' or op == 'PUSH4' or op == 'PUSH5' or op == 'PUSH6' or op == 'PUSH7' or op == 'PUSH8' or op == 'PUSH9' or op == 'PUSH10' or op == 'PUSH11' or op == 'PUSH12' or op == 'PUSH13' or op == 'PUSH14' or op == 'PUSH15' or op == 'PUSH16' or op == 'PUSH17' or op == 'PUSH18' or op == 'PUSH19' or op == 'PUSH20' or op == 'PUSH21' or op == 'PUSH22' or op == 'PUSH23' or op == 'PUSH24' or op == 'PUSH25' or op == 'PUSH26' or op == 'PUSH27' or op == 'PUSH28' or op == 'PUSH29' or op == 'PUSH30' or op == 'PUSH31' or op == 'PUSH32'
            or op == 'DUP1' or op == 'DUP2' or op == 'DUP3' or op == 'DUP4' or op == 'DUP5' or op == 'DUP6' or op == 'DUP7' or op == 'DUP8' or op == 'DUP9' or op == 'DUP10' or op == 'DUP11' or op == 'DUP12' or op == 'DUP13' or op == 'DUP14' or op == 'DUP15' or op == 'DUP16'
            or op == 'SWAP1' or op == 'SWAP2' or op == 'SWAP3' or op == 'SWAP4' or op == 'SWAP5' or op == 'SWAP6' or op == 'SWAP7' or op == 'SWAP8' or op == 'SWAP9' or op == 'SWAP10' or op == 'SWAP11' or op == 'SWAP12' or op == 'SWAP13' or op == 'SWAP14' or op == 'SWAP15' or op == 'SWAP16'
        ):
            new_cnts['_3_verylow'] += cnt
        elif (
               op == 'MUL'
            or op == 'DIV'
            or op == 'SDIV'
            or op == 'MOD'
            or op == 'SMOD'
            or op == 'SIGNEXTEND'
            or op == 'SELFBALANCE'
        ):
            new_cnts['_5_low'] += cnt
        else:
            new_cnts[op] = cnt

    return new_cnts

class hevm_cheat_code:
    # https://github.com/dapphub/ds-test/blob/cd98eff28324bfac652e63a239a60632a761790b/src/test.sol

    # address constant HEVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('hevm cheat code')))));
    address: int = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D

    # abi.encodePacked(
    #     bytes4(keccak256("store(address,bytes32,bytes32)")),
    #     abi.encode(HEVM_ADDRESS, bytes32("failed"), bytes32(uint256(0x01)))
    # )
    fail_payload: int = int(
        '70ca10bb' +
        '0000000000000000000000007109709ecfa91a80626ff3989d68f67f5b1dd12d' +
        '6661696c65640000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000001', 16
    )

    # bytes4(keccak256("assume(bool)"))
    assume_sig: int = 0x4C63E562

    # bytes4(keccak256("getCode(string)))
    get_code_sig: int = 0x8d1cc925

sha3_inv: Dict[int, int] = { # sha3(x) -> x
    0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 : 0,
    0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 : 1,
    0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace : 2,
    0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b : 3,
    0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b : 4,
    0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0 : 5,
    0xf652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f : 6,
    0xa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c688 : 7,
    0xf3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee3 : 8,
    0x6e1540171b6c0c960b71a7020d9f60077f6af931a8bbf590da0223dacf75c7af : 9,
    0xc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a8 : 10,
    0x0175b7a638427703f0dbe7bb9bbf987a2551717b34e79f33b5b1008d1fa01db9 : 11,
    0xdf6966c971051c3d54ec59162606531493a51404a002842f56009d7e5cf4a8c7 : 12,
    0xd7b6990105719101dabeb77144f2a3385c8033acd3af97e9423a695e81ad1eb5 : 13,
    0xbb7b4a454dc3493923482f07822329ed19e8244eff582cc204f8554c3620c3fd : 14,
    0x8d1108e10bcb7c27dddfc02ed9d693a074039d026cf4ea4240b40f7d581ac802 : 15,
    0x1b6847dc741a1b0cd08d278845f9d819d87b734759afb55fe2de5cb82a9ae672 : 16,
    0x31ecc21a745e3968a04e9570e4425bc18fa8019c68028196b546d1669c200c68 : 17,
    0xbb8a6a4669ba250d26cd7a459eca9d215f8307e33aebe50379bc5a3617ec3444 : 18,
    0x66de8ffda797e3de9c05e8fc57b3bf0ec28a930d40b0d285d93c06501cf6a090 : 19,
    0xce6d7b5282bd9a3661ae061feed1dbda4e52ab073b1f9285be6e155d9c38d4ec : 20,
    0x55f448fdea98c4d29eb340757ef0a66cd03dbb9538908a6a81d96026b71ec475 : 21,
    0xd833147d7dc355ba459fc788f669e58cfaf9dc25ddcd0702e87d69c7b5124289 : 22,
    0xc624b66cc0138b8fabc209247f72d758e1cf3343756d543badbf24212bed8c15 : 23,
    0xb13d2d76d1f4b7be834882e410b3e3a8afaf69f83600ae24db354391d2378d2e : 24,
    0x944998273e477b495144fb8794c914197f3ccb46be2900f4698fd0ef743c9695 : 25,
    0x057c384a7d1c54f3a1b2e5e67b2617b8224fdfd1ea7234eea573a6ff665ff63e : 26,
    0x3ad8aa4f87544323a9d1e5dd902f40c356527a7955687113db5f9a85ad579dc1 : 27,
    0x0e4562a10381dec21b205ed72637e6b1b523bdd0e4d4d50af5cd23dd4500a211 : 28,
    0x6d4407e7be21f808e6509aa9fa9143369579dd7d760fe20a2c09680fc146134f : 29,
    0x50bb669a95c7b50b7e8a6f09454034b2b14cf2b85c730dca9a539ca82cb6e350 : 30,
    0xa03837a25210ee280c2113ff4b77ca23440b19d4866cca721c801278fd08d807 : 31,
    0xc97bfaf2f8ee708c303a06d134f5ecd8389ae0432af62dc132a24118292866bb : 32,
    0x3a6357012c1a3ae0a17d304c9920310382d968ebcc4b1771f41c6b304205b570 : 33,
    0x61035b26e3e9eee00e0d72fd1ee8ddca6894550dca6916ea2ac6baa90d11e510 : 34,
    0xd57b2b5166478fd4318d2acc6cc2c704584312bdd8781b32d5d06abda57f4230 : 35,
    0x7cd332d19b93bcabe3cce7ca0c18a052f57e5fd03b4758a09f30f5ddc4b22ec4 : 36,
    0x401968ff42a154441da5f6c4c935ac46b8671f0e062baaa62a7545ba53bb6e4c : 37,
    0x744a2cf8fd7008e3d53b67916e73460df9fa5214e3ef23dd4259ca09493a3594 : 38,
    0x98a476f1687bc3d60a2da2adbcba2c46958e61fa2fb4042cd7bc5816a710195b : 39,
    0xe16da923a2d88192e5070f37b4571d58682c0d66212ec634d495f33de3f77ab5 : 40,
    0xcb7c14ce178f56e2e8d86ab33ebc0ae081ba8556a00cd122038841867181caac : 41,
    0xbeced09521047d05b8960b7e7bcc1d1292cf3e4b2a6b63f48335cbde5f7545d2 : 42,
    0x11c44e4875b74d31ff9fd779bf2566af7bd15b87fc985d01f5094b89e3669e4f : 43,
    0x7416c943b4a09859521022fd2e90eac0dd9026dad28fa317782a135f28a86091 : 44,
    0x4a2cc91ee622da3bc833a54c37ffcb6f3ec23b7793efc5eaf5e71b7b406c5c06 : 45,
    0x37fa166cbdbfbb1561ccd9ea985ec0218b5e68502e230525f544285b2bdf3d7e : 46,
    0xa813484aef6fb598f9f753daf162068ff39ccea4075cb95e1a30f86995b5b7ee : 47,
    0x6ff97a59c90d62cc7236ba3a37cd85351bf564556780cf8c1157a220f31f0cbb : 48,
    0xc54045fa7c6ec765e825df7f9e9bf9dec12c5cef146f93a5eee56772ee647fbc : 49,
    0x11df491316f14931039edfd4f8964c9a443b862f02d4c7611d18c2bc4e6ff697 : 50,
    0x82a75bdeeae8604d839476ae9efd8b0e15aa447e21bfd7f41283bb54e22c9a82 : 51,
    0x46bddb1178e94d7f2892ff5f366840eb658911794f2c3a44c450aa2c505186c1 : 52,
    0xcfa4bec1d3298408bb5afcfcd9c430549c5b31f8aa5c5848151c0a55f473c34d : 53,
    0x4a11f94e20a93c79f6ec743a1954ec4fc2c08429ae2122118bf234b2185c81b8 : 54,
    0x42a7b7dd785cd69714a189dffb3fd7d7174edc9ece837694ce50f7078f7c31ae : 55,
    0x38395c5dceade9603479b177b68959049485df8aa97b39f3533039af5f456199 : 56,
    0xdc16fef70f8d5ddbc01ee3d903d1e69c18a3c7be080eb86a81e0578814ee58d3 : 57,
    0xa2999d817b6757290b50e8ecf3fa939673403dd35c97de392fdb343b4015ce9e : 58,
    0xbbe3212124853f8b0084a66a2d057c2966e251e132af3691db153ab65f0d1a4d : 59,
    0xc6bb06cb7f92603de181bf256cd16846b93b752a170ff24824098b31aa008a7e : 60,
    0xece66cfdbd22e3f37d348a3d8e19074452862cd65fd4b9a11f0336d1ac6d1dc3 : 61,
    0x8d800d6614d35eed73733ee453164a3b48076eb3138f466adeeb9dec7bb31f70 : 62,
    0xc03004e3ce0784bf68186394306849f9b7b1200073105cd9aeb554a1802b58fd : 63,
    0x352feee0eea125f11f791c1b77524172e9bc20f1b719b6cef0fc24f64db8e15e : 64,
    0x7c9785e8241615bc80415d89775984a1337d15dc1bf4ce50f41988b2a2b336a7 : 65,
    0x38dfe4635b27babeca8be38d3b448cb5161a639b899a14825ba9c8d7892eb8c3 : 66,
    0x9690ad99d6ce244efa8a0f6c2d04036d3b33a9474db32a71b71135c695102793 : 67,
    0x9b22d3d61959b4d3528b1d8ba932c96fbe302b36a1aad1d95cab54f9e0a135ea : 68,
    0xa80a8fcc11760162f08bb091d2c9389d07f2b73d0e996161dfac6f1043b5fc0b : 69,
    0x128667f541fed74a8429f9d592c26c2c6a4beb9ae5ead9912c98b2595c842310 : 70,
    0xc43c1e24e1884c4e28a16bbd9506f60b5ca9f18fc90635e729d3cfe13abcf001 : 71,
    0x15040156076f78057c0a886f6dbac29221fa3c2646adbc8effedab98152ff32b : 72,
    0x37e472f504e93744df80d87316862f9a8fd41a7bc266c723bf77df7866d75f55 : 73,
    0xfcc5ba1a98fc477b8948a04d08c6f4a76181fe75021370ab5e6abd22b1792a2a : 74,
    0x17b0af156a929edf60c351f3df2d53ed643fdd750aef9eda90dc7c8759a104a8 : 75,
    0x42859d4f253f4d4a28ee9a59f9c9683a9404da2c5d329c733ab84f150db798a8 : 76,
    0x1b524e1c8b5382bb913d0a2aae8ad83bb92a45fcb47761fa4a12f5b6316c2b20 : 77,
    0x9b65e484ce3d961a557081a44c6c68a0a27eca0b88fce820bdd99c3dc223dcc7 : 78,
    0xa2e8f972dc9f7d0b76177bb8be102e6bec069ee42c61080745e8825470e80c6c : 79,
    0x5529612556959ef813dbe8d0ed29336ab75e80a9b7855030760b2917b01e568a : 80,
    0x994a4b4eddb300691ee19901712848b1114bad8a1a4ae195e5abe0ec38021b94 : 81,
    0xa9144a5e7efd259b8b0d55467f4696ed47ec83317d61501b76366dbcca65ce73 : 82,
    0x4c83efb3982afbd500ab7c66d02b996df5fdc3d20660e61600390aad6d5f7f1e : 83,
    0xf0d642dbc7517672e217238a2f008f4f8cdad0586d8ce5113e9e09dcc6860619 : 84,
    0x71beda120aafdd3bb922b360a066d10b7ce81d7ac2ad9874daac46e2282f6b45 : 85,
    0xea7419f5ae821e7204864e6a0871433ba612011908963bb42a64f42d65ad2f72 : 86,
    0xe8e5595d268aaa85b36c3557e9d96c14a4fffaee9f45bcae0c407968a7109630 : 87,
    0x657000d47e971dcfb21375bcfa3496f47a2a2f0f12c8aeb78a008ace6ae55ca5 : 88,
    0xd73956b9e00d8f8bc5e44f7184df1387cdd652e7726b8ccda3db4859e02f31bf : 89,
    0xe8c3abd4193a84ec8a3fff3eeb3ecbcbd0979e0c977ac1dee06c6e01a60aca1b : 90,
    0xfcebc02dd307dc58cd01b156d63c6948b8f3422055fac1d836349b01722e9c52 : 91,
    0xec0b854938343f85eb39a6648b9e449c2e4aee4dc9b4e96ab592f9f497d05138 : 92,
    0x2619ec68b255542e3da68c054bfe0d7d0f27b7fdbefc8bbccdd23188fc71fe7f : 93,
    0x34d3c319f536deb74ed8f1f3205d9aefef7487c819e77d3351630820dbff1118 : 94,
    0xcc7ee599e5d59fee88c83157bd897847c5911dc7d317b3175e0b085198349973 : 95,
    0x41c7ae758795765c6664a5d39bf63841c71ff191e9189522bad8ebff5d4eca98 : 96,
    0xf0ecb75dd1820844c57b6762233d4e26853b3a7b8157bbd9f41f280a0f1cee9b : 97,
    0xb912c5eb6319a4a6a83580b9611610bedb31614179330261bfd87a41347cae1c : 98,
    0xd86d8a3f7c82c89ed8e04140017aa108a0a1469249f92c8f022b9dbafa87b883 : 99,
    0x26700e13983fefbd9cf16da2ed70fa5c6798ac55062a4803121a869731e308d2 : 100,
    0x8ff97419363ffd7000167f130ef7168fbea05faf9251824ca5043f113cc6a7c7 : 101,
    0x46501879b8ca8525e8c2fd519e2fbfcfa2ebea26501294aa02cbfcfb12e94354 : 102,
    0x9787eeb91fe3101235e4a76063c7023ecb40f923f97916639c598592fa30d6ae : 103,
    0xa2153420d844928b4421650203c77babc8b33d7f2e7b450e2966db0c22097753 : 104,
    0x7fb4302e8e91f9110a6554c2c0a24601252c2a42c2220ca988efcfe399914308 : 105,
    0x116fea137db6e131133e7f2bab296045d8f41cc5607279db17b218cab0929a51 : 106,
    0xbd43cb8ece8cd1863bcd6082d65c5b0d25665b1ce17980f0da43c0ed545f98b4 : 107,
    0x2b4a51ab505fc96a0952efda2ba61bcd3078d4c02c39a186ec16f21883fbe016 : 108,
    0x5006b838207c6a9ae9b84d68f467dd4bb5c305fbfb6b04eab8faaabeec1e18d8 : 109,
    0x9930d9ff0dee0ef5ca2f7710ea66b8f84dd0f5f5351ecffe72b952cd9db7142a : 110,
    0x39f2babe526038520877fc7c33d81accf578af4a06c5fa6b0d038cae36e12711 : 111,
    0x8f6b23ffa15f0465e3176e15ca644cf24f86dc1312fe715484e3c4aead5eb78b : 112,
    0xa1fcd19bfe8c32a61095b6bfbb2664842857e148fcbb5188386c8cd40348d5b6 : 113,
    0xdffbd64cc7c1a7eb27984335d9416d51137a03d3fabec7141025c62663253fe1 : 114,
    0xf79bde9ddd17963ebce6f7d021d60de7c2bd0db944d23c900c0c0e775f530052 : 115,
    0x19a0b39aa25ac793b5f6e9a0534364cc0b3fd1ea9b651e79c7f50a59d48ef813 : 116,
    0x9a8d93986a7b9e6294572ea6736696119c195c1a9f5eae642d3c5fcd44e49dea : 117,
    0xb5732705f5241370a28908c2fe1303cb223f03b90d857fd0573f003f79fefed4 : 118,
    0x7901cb5addcae2d210a531c604a76a660d77039093bac314de0816a16392aff1 : 119,
    0x8dc6fb69531d98d70dc0420e638d2dfd04e09e1ec783ede9aac77da9c5a0dac4 : 120,
    0x957bbdc7fad0dec56e7c96af4a3ab63aa9daf934a52ffce891945b7fb622d791 : 121,
    0xf0440771a29e57e18c66727944770b82cc77924aef333c927ce6bdd2cdb3ae03 : 122,
    0x5569044719a1ec3b04d0afa9e7a5310c7c0473331d13dc9fafe143b2c4e8148a : 123,
    0x9222cbf5d0ddc505a6f2f04716e22c226cee16a955fef88c618922096dae2fd0 : 124,
    0xa913c8ac5320dae1c4a00ff23343947ed0fdf88d251e9bd2a5519d3d6162d222 : 125,
    0x0f2ada1f2dbae48ae468fe0cdb7bcda7d0cffee8545442e682273ba01a6203a7 : 126,
    0x66925e85f1a4743fd8d60ba595ed74887b7caf321dd83b21e04d77c115383408 : 127,
    0x59f3fb058c6bba7a4e76396639fc4dd21bd59163db798899cf56cef48b3c9ec9 : 128,
    0x76fce494794d92ac286b20d6126fc49ecb9cca2fa94b5c726f6ec1109b891414 : 129,
    0xb2244e644cfe16f72b654fbc48ff0fecec8fc59649ca8625094bebd9bd2e4035 : 130,
    0x1397b88f412a83a7f1c0d834c533e486ff1f24f42a31819e91b624931060a863 : 131,
    0x50250e93f8c73d2c1be015ec28e8cd2feb871efa71e955ad24477aafb09484fa : 132,
    0xdbdaec72d84124d8c7c57ae448f5a4e3eedb34dba437fdcbe6d26496b68afe87 : 133,
    0x46b7ea84944250856a716737059479854246a026d947c13d5a0929bc8c1bc81d : 134,
    0x171ab08901be24769dbebedbdf7e0245486fbc64ab975cd431a39533032d5415 : 135,
    0x7ef464cf5a521d70c933977510816a0355b91a50eca2778837fb82da8448ecf6 : 136,
    0x5bfa74c743914028161ae645d300d90bbdc659f169ca1469ec86b4960f7266cb : 137,
    0x834355d35cbfbd33b2397e201af04b52bdd40b9b51275f279ea47e93547b631e : 138,
    0x7b6bb1e9d1b017ff82945596cf3cfb1a6cee971c1ebb16f2c6bd23c2d642728e : 139,
    0x5f2f2dca1d951c7429b52007f396328c64c25e226c1867318158f7f2cbdd40a9 : 140,
    0x37a1be2a88dadcd0e6062f54ddcc01a03360ba61ca7784a744e757488bf8ceb2 : 141,
    0x8edd81ff20324ea0cfe70c700ff4e9db7580d269b423d9f61470b370819cbd17 : 142,
    0x337f7913db22d91ef425f82102bc8075ef67e23a2be359965ea316e78e1eff3f : 143,
    0x60b1e32550f9d5f25f9dd040e7a106b15d8eb282dd6b3e1914c73d8066896412 : 144,
    0xcdae184edd6bf71c1fb62d6e6682fdb2032455c0e50143742135fbbe809bd793 : 145,
    0x6e452848784197f00927d379e3db9e69a5131d2269f862bfcd05a0b38f6abf7f : 146,
    0x28da5ca8143bfa5e9f642e58e5e87bef0a2eb0c00bcd4efdd01050293f5fac91 : 147,
    0x7047a3cc0a76edcee45792ca71527c753f6167484f14b94c4a3bd2997516725c : 148,
    0x947035e97d0f7e1937f791bc189f60c984ceaaa7a8494fc67f9f8f4de8ccf2c6 : 149,
    0x6aa7ec8ac2a999a90ce6c78668dffe4e487e2576a97ca366ec81ecb335af90d0 : 150,
    0x354a83ed9988f79f6038d4c7a7dadbad8af32f4ad6df893e0e5807a1b1944ff9 : 151,
    0x2237a976fa961f5921fd19f2b03c925c725d77b20ce8f790c19709c03de4d814 : 152,
    0x72a152ddfb8e864297c917af52ea6c1c68aead0fee1a62673fcc7e0c94979d00 : 153,
    0x44da158ba27f9252712a74ff6a55c5d531f69609f1f6e7f17c4443a8e2089be4 : 154,
    0xbba9db4cdbea0a37c207bbb83e20f828cd4441c49891101dc94fd20dc8efc349 : 155,
    0xaf85b9071dfafeac1409d3f1d19bafc9bc7c37974cde8df0ee6168f0086e539c : 156,
    0xd26e832454299e9fabb89e0e5fffdc046d4e14431bc1bf607ffb2e8a1ddecf7b : 157,
    0xcfe2a20ff701a1f3e14f63bd70d6c6bc6fba8172ec6d5a505cdab3927c0a9de6 : 158,
    0x0bc14066c33013fe88f66e314e4cf150b0b2d4d6451a1a51dbbd1c27cd11de28 : 159,
    0x78fdc8d422c49ced035a9edf18d00d3c6a8d81df210f3e5e448e045e77b41e88 : 160,
    0xaadc37b8ba5645e62f4546802db221593a94729ccbfc5a97d01365a88f649878 : 161,
    0xaaf4f58de99300cfadc4585755f376d5fa747d5bc561d5bd9d710de1f91bf42d : 162,
    0x60859188cffe297f44dde29f2d2865634621f26215049caeb304ccba566a8b17 : 163,
    0xe434dc35da084cf8d7e8186688ea2dacb53db7003d427af3abf351bd9d0a4e8d : 164,
    0xb29a2b3b6f2ff1b765777a231725941da5072cc4fcc30ac4a2ce09706e8ddeff : 165,
    0x2da56674729343acc9933752c8c469a244252915242eb6d4c02d11ddd69164a1 : 166,
    0xb68792697ed876af8b4858b316f5b54d81f6861191ad2950c1fde6c3dc7b3dea : 167,
    0xbee89403b5bf0e626c2f71adb366311c697013df53107181a963adc459ef4d99 : 168,
    0xdc471888e6136f84c49e531e9c9240dc4e3fba66da9d3a49e2af6202133683e0 : 169,
    0x550d3de95be0bd28a79c3eb4ea7f05692c60b0602e48b49461e703379b08a71a : 170,
    0xfc377260a69a39dd786235c89f4bcd5d9639157731cac38071a0508750eb115a : 171,
    0x0a0a1bcadd9f6a5539376fa82276e043ae3cb4499daaaf8136572ecb1f9f0d60 : 172,
    0x0440fd76b4e685d17019b0eef836cea9994650028b99dddfb48be06fa4240aa6 : 173,
    0xdf5d400f265039450228fa547df2bee79e6a350daa43fba4bd328bc654824c64 : 174,
    0xdef993a65205231625280c5e3c23e44b263d0aa948fbc330055626b8ab25a5a1 : 175,
    0x238ba8d02078544847438db7773730a25d584074eac94489bd8eb86ca267c937 : 176,
    0x04cb44c80b6fbf8ceb1d80af688c9f7c0b2ab5bf4a964cabe37041f23b23f7a8 : 177,
    0xbbf265bea1b905c854054a8dbe97fedcc06fa54306551423711231a4ad0610c9 : 178,
    0x236f2840bfc5dc34b28742dd0b4c9defe8a4a5fa9592e49ceffb9ab51b7eb974 : 179,
    0x1c5f5ac147ec2dee04d8ce29bdbebbc58f578e0e1392da66f352a62e5c09c503 : 180,
    0x22b88d74a6b23be687aa96340c881253c2e9873c526eec7366dc5f733ada306a : 181,
    0x3ae797ceef265e3a4f9c1978c47c759eb34a32909251dee7276db339b17b3de3 : 182,
    0x6a79cc294e25eb1a13381e9f3361ee96c47ee7ed00bf73abadb8f9664bffd0a7 : 183,
    0xd91d691c894f8266e3f2d5e558ad2349d6783327a752a4949bc554f514e34988 : 184,
    0xe35848a7c6477cfe9366ae64571069fd3a5ad752a460d28c5f73d438b5e432bf : 185,
    0xf3b9eb9e163af2088b11de0a369fb583f58f9440e0e5c70fce0c59909ecece8a : 186,
    0x28afdd85196b637a3c64ff1f53af1ad8de145cf652297ede1b38f2cbd6a4b4bf : 187,
    0x6f1f0041084f67ced174808484bd05851de94443d775585e9d86d4c2589dba59 : 188,
    0xd344f074c815fded543cd5a29a47659de529cd0adb1c1fae6eda2d685d422bd8 : 189,
    0x4082d8aa0be13ab143f55d600665a8ae7ef90ba09d57c38fa538a2604d7e9827 : 190,
    0xb52cf138a3505dc3d3cd84a77912f4be1a33df2c3065d3e4cb37fb1d5d1b5072 : 191,
    0x5e29e30c8ea9a89560281b90dbe96fe6f067a8acc0f164a71449bf0da7d58d7e : 192,
    0xa4c9b5d989fa12d608052e66dc5a37a431d679e93d0ed25572f97f67460bb157 : 193,
    0xb93edcd1e74716ac76d71e26ce3491be20745375dcd4848d8f3b91a3f785dbb1 : 194,
    0x6d918f650e2b4a9f360977c4447e6376eb632ec1f687ba963aa9983e90086594 : 195,
    0x2bde9b0c0857aee2cffdea6b8723eaf59894499ec278c18f020edd3c2295e424 : 196,
    0xbacdda17ed986c07f827229709e1ded99d4da917a5e7e7ec15816eaf2cacf54c : 197,
    0xcfc479828d8133d824a47fe26326d458b6b94134276b945404197f42411564c3 : 198,
    0xc1d0558604082af4380f8af6e6df686f24c7438ca4f2a67c86a71ee7852601f9 : 199,
    0xe71fac6fb785942cc6c6404a423f94f32a28ae66d69ff41494c38bfd4788b2f8 : 200,
    0x66be4f155c5ef2ebd3772b228f2f00681e4ed5826cdb3b1943cc11ad15ad1d28 : 201,
    0x42d72674974f694b5f5159593243114d38a5c39c89d6b62fee061ff523240ee1 : 202,
    0xa7ce836d032b2bf62b7e2097a8e0a6d8aeb35405ad15271e96d3b0188a1d06fb : 203,
    0x47197230e1e4b29fc0bd84d7d78966c0925452aff72a2a121538b102457e9ebe : 204,
    0x83978b4c69c48dd978ab43fe30f077615294f938fb7f936d9eb340e51ea7db2e : 205,
    0xd36cd1c74ef8d7326d8021b776c18fb5a5724b7f7bc93c2f42e43e10ef27d12a : 206,
    0xacb8d954e2cfef495862221e91bd7523613cf8808827cb33edfe4904cc51bf29 : 207,
    0xe89d44c8fd6a9bac8af33ce47f56337617d449bf7ff3956b618c646de829cbcb : 208,
    0x695fb3134ad82c3b8022bc5464edd0bcc9424ef672b52245dcb6ab2374327ce3 : 209,
    0xf2192e1030363415d7b4fb0406540a0060e8e2fc8982f3f32289379e11fa6546 : 210,
    0x915c3eb987b20e1af620c1403197bf687fb7f18513b3a73fde6e78c7072c41a6 : 211,
    0x9780e26d96b1f2a9a18ef8fc72d589dbf03ef788137b64f43897e83a91e7feec : 212,
    0x51858de9989bf7441865ebdadbf7382c8838edbf830f5d86a9a51ac773676dd6 : 213,
    0xe767803f8ecf1dee6bb0345811f7312cda556058b19db6389ad9ae3568643ddd : 214,
    0x8a012a6de2943a5aa4d77acf5e695d4456760a3f1f30a5d6dc2079599187a071 : 215,
    0x5320ad99a619a90804cd2efe3a5cf0ac1ac5c41ad9ff2c61cf699efdad771096 : 216,
    0xcc6782fd46dd71c5f512301ab049782450b4eaf79fdac5443d93d274d3916786 : 217,
    0xb3d6e86317c38844915b053a0c35ff2fc103b684e96cef2918ab06844eb51aaf : 218,
    0x4c0d3471ead8ee99fbd8249e33f683e07c6cd6071fe102dd09617b2c353de430 : 219,
    0x3162b0988d4210bff484413ed451d170a03887272177efc0b7d000f10abe9edf : 220,
    0xac507b9f8bf86ad8bb770f71cd2b1992902ae0314d93fc0f2bb011d70e796226 : 221,
    0xfae8130c0619f84b4b44f01b84806f04e82e536d70e05f2356977fa318aecc1a : 222,
    0x65e3d48fa860a761b461ce1274f0d562f3db9a6a57cf04d8c90d68f5670b6aea : 223,
    0x8b43726243eeaf8325404568abece3264b546cf9d88671f09c24c87045fccb4f : 224,
    0x3efdd7a884ff9e18c9e5711c185aa6c5e413b68f23197997da5b1665ca978f99 : 225,
    0x26a62d79192c78c3891f38189368673110b88734c09ed7453515def7525e07d8 : 226,
    0x37f6a7f96b945f2f9a9127ccb4a8552fcb6938e53fe8f046db8da238398093e9 : 227,
    0x04e4a0bb093261ee16386dadcef9e2a83913f4e1899464891421d20c1bbff74d : 228,
    0x5625f7c930b8b40de87dc8e69145d83fd1d81c61b6c31fb7cfe69fac65b28642 : 229,
    0xd31ddb47b5e8664717d3718acbd132396ff496fe337159c99410be8658408a27 : 230,
    0x6cb0db1d7354dfb4a1464318006df0643cafe2002a86a29ff8560f900fef28a1 : 231,
    0x53c8da29bfa275271df3f270296d5a7d61b57f8848c89b3f65f49e21340b7592 : 232,
    0xea6426b4b8d70caa8ece9a88fb0a9d4a6b817bb4a43ac6fbef64cb0e589129ee : 233,
    0x61c831beab28d67d1bb40b5ae1a11e2757fa842f031a2d0bc94a7867bc5d26c2 : 234,
    0x0446c598f3355ed7d8a3b7e0b99f9299d15e956a97faae081a0b49d17024abd2 : 235,
    0xe7dfac380f4a6ed3a03e62f813161eff828766fa014393558e075e9ceb77d549 : 236,
    0x0504e0a132d2ef5ca5f2fe74fc64437205bc10f32d5f13d533bf552916a94d3f : 237,
    0xdb444da68c84f0a9ce08609100b69b8f3d5672687e0ca13fa3c0ac9eb2bde5d2 : 238,
    0xdd0dc620e7584674cb3dba490d2eba9e68eca0bef228ee569a4a64f6559056e9 : 239,
    0x681483e2251cd5e2885507bb09f76bed3b99d3c377dd48396177647bfb4aafda : 240,
    0xc29b39917e4e60f0fee5b6871b30a38e50531d76d1b0837811bd6351b34854ec : 241,
    0x83d76afc3887c0b7edd14a1affa7554bed3345ba68ddcd2a3326c7eae97b80d8 : 242,
    0x2f5553803273e8bb29d913cc31bab953051c59f3ba57a71cf5591563ca721405 : 243,
    0xfc6a672327474e1387fcbce1814a1de376d8561fc138561441ac6e396089e062 : 244,
    0x81630654dfb0fd282a37117995646cdde2cf8eefe9f3f96fdb12cfda88df6668 : 245,
    0xddf78cfa378b5e068a248edaf3abef23ea9e62c66f86f18cc5e695cd36c9809b : 246,
    0xe9944ebef6e5a24035a31a727e8ff6da7c372d99949c1224483b857f6401e346 : 247,
    0x6120b123382f98f7efe66abe6a3a3445788a87e48d4e6991f37baadcac0bef95 : 248,
    0x168c8166292b85070409830617e84bdd7e3518b38e5ac430dc35ed7d16b07a86 : 249,
    0xd84f57f3ffa76cc18982da4353cc5991158ec5ae4f6a9109d1d7a0ae2cba77ed : 250,
    0x3e7257b7272bb46d49cd6019b04ddee20da7c0cb13f7c1ec3391291b2ccebabc : 251,
    0x371f36870d18f32a11fea0f144b021c8b407bb50f8e0267c711123f454b963c0 : 252,
    0x9346ac6dd7de6b96975fec380d4d994c4c12e6a8897544f22915316cc6cca280 : 253,
    0x54075df80ec1ae6ac9100e1fd0ebf3246c17f5c933137af392011f4c5f61513a : 254,
    0xe08ec2af2cfc251225e1968fd6ca21e4044f129bffa95bac3503be8bdb30a367 : 255,
}
