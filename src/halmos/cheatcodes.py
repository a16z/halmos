# SPDX-License-Identifier: AGPL-3.0

from typing import List, Dict, Set, Tuple, Any

from z3 import *

from .utils import assert_address, con_addr


class Prank:
    addr: Any  # prank address
    keep: bool  # start / stop prank

    def __init__(self, addr: Any = None, keep: bool = False) -> None:
        if addr is not None:
            assert_address(addr)
        self.addr = addr
        self.keep = keep

    def __str__(self) -> str:
        if self.addr:
            if self.keep:
                return f"startPrank({str(addr)})"
            else:
                return f"prank({str(addr)})"
        else:
            return "None"

    def lookup(self, this: Any, to: Any) -> Any:
        assert_address(this)
        assert_address(to)
        caller = this
        if (
            self.addr is not None
            and not eq(to, hevm_cheat_code.address)
            and not eq(to, halmos_cheat_code.address)
        ):
            caller = self.addr
            if not self.keep:
                self.addr = None
        return caller

    def prank(self, addr: Any) -> bool:
        assert_address(addr)
        if self.addr is not None:
            return False
        self.addr = addr
        self.keep = False
        return True

    def startPrank(self, addr: Any) -> bool:
        assert_address(addr)
        if self.addr is not None:
            return False
        self.addr = addr
        self.keep = True
        return True

    def stopPrank(self) -> bool:
        # stopPrank is allowed to call even when no active prank exists
        self.addr = None
        self.keep = False
        return True


class halmos_cheat_code:
    # address constant SVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('svm cheat code')))));
    address: BitVecRef = con_addr(0xF3993A62377BCD56AE39D773740A5390411E8BC9)

    # bytes4(keccak256("createUint(uint256,string)"))
    create_uint: int = 0x66830DFA

    # bytes4(keccak256("createBytes(uint256,string)"))
    create_bytes: int = 0xEEF5311D

    # bytes4(keccak256("createUint256(string)"))
    create_uint256: int = 0xBC7BEEFC

    # bytes4(keccak256("createBytes32(string)"))
    create_bytes32: int = 0xBF72FA66

    # bytes4(keccak256("createAddress(string)"))
    create_address: int = 0x3B0FA01B

    # bytes4(keccak256("createBool(string)"))
    create_bool: int = 0x6E0BB659


class hevm_cheat_code:
    # https://github.com/dapphub/ds-test/blob/cd98eff28324bfac652e63a239a60632a761790b/src/test.sol

    # address constant HEVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('hevm cheat code')))));
    address: BitVecRef = con_addr(0x7109709ECFA91A80626FF3989D68F67F5B1DD12D)

    # abi.encodePacked(
    #     bytes4(keccak256("store(address,bytes32,bytes32)")),
    #     abi.encode(HEVM_ADDRESS, bytes32("failed"), bytes32(uint256(0x01)))
    # )
    fail_payload: int = int(
        "70ca10bb"
        + "0000000000000000000000007109709ecfa91a80626ff3989d68f67f5b1dd12d"
        + "6661696c65640000000000000000000000000000000000000000000000000000"
        + "0000000000000000000000000000000000000000000000000000000000000001",
        16,
    )

    # bytes4(keccak256("assume(bool)"))
    assume_sig: int = 0x4C63E562

    # bytes4(keccak256("getCode(string)"))
    get_code_sig: int = 0x8D1CC925

    # bytes4(keccak256("prank(address)"))
    prank_sig: int = 0xCA669FA7

    # bytes4(keccak256("startPrank(address)"))
    start_prank_sig: int = 0x06447D56

    # bytes4(keccak256("stopPrank()"))
    stop_prank_sig: int = 0x90C5013B

    # bytes4(keccak256("deal(address,uint256)"))
    deal_sig: int = 0xC88A5E6D

    # bytes4(keccak256("store(address,bytes32,bytes32)"))
    store_sig: int = 0x70CA10BB

    # bytes4(keccak256("load(address,bytes32)"))
    load_sig: int = 0x667F9D70

    # bytes4(keccak256("fee(uint256)"))
    fee_sig: int = 0x39B37AB0

    # bytes4(keccak256("chainId(uint256)"))
    chainid_sig: int = 0x4049DDD2

    # bytes4(keccak256("coinbase(address)"))
    coinbase_sig: int = 0xFF483C54

    # bytes4(keccak256("difficulty(uint256)"))
    difficulty_sig: int = 0x46CC92D9

    # bytes4(keccak256("roll(uint256)"))
    roll_sig: int = 0x1F7B4F30

    # bytes4(keccak256("warp(uint256)"))
    warp_sig: int = 0xE5D6BF02

    # bytes4(keccak256("etch(address,bytes)"))
    etch_sig: int = 0xB4D6C782

    # bytes4(keccak256("ffi(string[])"))
    ffi_sig: int = 0x89160467


class console:
    # address constant CONSOLE_ADDRESS = address(0x000000000000000000636F6e736F6c652e6c6f67);
    address: BitVecRef = con_addr(0x000000000000000000636F6E736F6C652E6C6F67)

    log_uint: int = 0xF5B1BBA9  # bytes4(keccak256("log(uint)"))

    log_string: int = 0x41304FAC  # bytes4(keccak256("log(string)"))
