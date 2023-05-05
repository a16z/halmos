# SPDX-License-Identifier: AGPL-3.0

from typing import List, Dict, Set, Tuple, Any

from z3 import *

class Prank:
    addr: Any # prank address
    keep: bool # start / stop prank

    def __init__(self, addr: Any = None, keep: bool = False) -> None:
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
        caller = this
        if self.addr is not None and not eq(to, BitVecVal(hevm_cheat_code.address, 256)):
            caller = self.addr
            if not self.keep:
                self.addr = None
        return caller

    def prank(self, addr: Any) -> bool:
        if self.addr is not None: return False
        self.addr = addr
        self.keep = False
        return True

    def startPrank(self, addr: Any) -> bool:
        if self.addr is not None: return False
        self.addr = addr
        self.keep = True
        return True

    def stopPrank(self) -> bool:
        # stopPrank is allowed to call even when no active prank exists
        self.addr = None
        self.keep = False
        return True

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
