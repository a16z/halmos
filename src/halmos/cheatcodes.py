# SPDX-License-Identifier: AGPL-3.0

from typing import List, Dict, Set, Tuple, Any

from z3 import *

from .utils import assert_address, con_addr

class Prank:
    addr: Any # prank address
    keep: bool # start / stop prank

    def __init__(self, addr: Any = None, keep: bool = False) -> None:
        if addr is not None: assert_address(addr)
        self.addr = addr
        self.keep = keep

    def __str__(self) -> str:
        if self.addr:
            if self.keep:
                return f'startPrank({str(addr)})'
            else:
                return f'prank({str(addr)})'
        else:
            return 'None'

    def lookup(self, this: Any, to: Any) -> Any:
        assert_address(this)
        assert_address(to)
        caller = this
        if self.addr is not None and not eq(to, hevm_cheat_code.address):
            caller = self.addr
            if not self.keep:
                self.addr = None
        return caller

    def prank(self, addr: Any) -> bool:
        assert_address(addr)
        if self.addr is not None: return False
        self.addr = addr
        self.keep = False
        return True

    def startPrank(self, addr: Any) -> bool:
        assert_address(addr)
        if self.addr is not None: return False
        self.addr = addr
        self.keep = True
        return True

    def stopPrank(self) -> bool:
        # stopPrank is allowed to call even when no active prank exists
        self.addr = None
        self.keep = False
        return True

class halmos_cheat_code:
    # address constant HALMOS_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('halmos cheat code')))));
    address: BitVecRef = con_addr(0x23059c36bb741986638baf337ff4d70fd1c4ef91)

    # bytes4(keccak256("createSymbolicUint(uint256)"))
    create_symbolic_uint: int = 0xfb6f0a62

    # bytes4(keccak256("createSymbolicBytes(uint256)"))
    create_symbolic_bytes: int = 0x7af8ffa5

    # bytes4(keccak256("createSymbolicUint256()"))
    create_symbolic_uint256: int = 0xcbf11591

    # bytes4(keccak256("createSymbolicBytes32()"))
    create_symbolic_bytes32: int = 0xea2e22e6

    # bytes4(keccak256("createSymbolicAddress()"))
    create_symbolic_address: int = 0xb6933bbe

    # bytes4(keccak256("createSymbolicBool()"))
    create_symbolic_bool: int = 0xa7e9f494

class hevm_cheat_code:
    # https://github.com/dapphub/ds-test/blob/cd98eff28324bfac652e63a239a60632a761790b/src/test.sol

    # address constant HEVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('hevm cheat code')))));
    address: BitVecRef = con_addr(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D)

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

    # bytes4(keccak256("getCode(string)"))
    get_code_sig: int = 0x8d1cc925

    # bytes4(keccak256("prank(address)"))
    prank_sig: int = 0xca669fa7

    # bytes4(keccak256("startPrank(address)"))
    start_prank_sig: int = 0x06447d56

    # bytes4(keccak256("stopPrank()"))
    stop_prank_sig: int = 0x90c5013b

    # bytes4(keccak256("deal(address,uint256)"))
    deal_sig: int = 0xc88a5e6d

    # bytes4(keccak256("store(address,bytes32,bytes32)"))
    store_sig: int = 0x70ca10bb

    # bytes4(keccak256("load(address,bytes32)"))
    load_sig: int = 0x667f9d70

    # bytes4(keccak256("fee(uint256)"))
    fee_sig: int = 0x39b37ab0

    # bytes4(keccak256("chainId(uint256)"))
    chainid_sig: int = 0x4049ddd2

    # bytes4(keccak256("coinbase(address)"))
    coinbase_sig: int = 0xff483c54

    # bytes4(keccak256("difficulty(uint256)"))
    difficulty_sig: int = 0x46cc92d9

    # bytes4(keccak256("roll(uint256)"))
    roll_sig: int = 0x1f7b4f30

    # bytes4(keccak256("warp(uint256)"))
    warp_sig: int = 0xe5d6bf02

    # bytes4(keccak256("etch(address,bytes)"))
    etch_sig: int = 0xb4d6c782
