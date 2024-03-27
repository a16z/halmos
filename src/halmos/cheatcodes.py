# SPDX-License-Identifier: AGPL-3.0

import json
import re

from subprocess import Popen, PIPE
from typing import List, Dict, Set, Tuple, Any

from z3 import *

from .exceptions import FailCheatcode, HalmosException
from .utils import *


# f_vmaddr(key) -> address
f_vmaddr = Function("f_vmaddr", BitVecSort256, BitVecSort160)

# f_sign_v(key, digest) -> v
f_sign_v = Function("f_sign_v", BitVecSort256, BitVecSort256, BitVecSort8)

# f_sign_r(key, digest) -> r
f_sign_r = Function("f_sign_r", BitVecSort256, BitVecSort256, BitVecSort256)

# f_sign_s(key, digest) -> s
f_sign_s = Function("f_sign_s", BitVecSort256, BitVecSort256, BitVecSort256)


def name_of(x: str) -> str:
    return re.sub(r"\s+", "_", x)


def extract_string_array_argument(calldata: BitVecRef, arg_idx: int):
    """Extracts idx-th argument of string array from calldata"""

    array_slot = int_of(extract_bytes(calldata, 4 + 32 * arg_idx, 32))
    num_strings = int_of(extract_bytes(calldata, 4 + array_slot, 32))

    string_array = []

    for i in range(num_strings):
        string_offset = int_of(
            extract_bytes(calldata, 4 + array_slot + 32 * (i + 1), 32)
        )
        string_length = int_of(
            extract_bytes(calldata, 4 + array_slot + 32 + string_offset, 32)
        )
        string_value = int_of(
            extract_bytes(
                calldata, 4 + array_slot + 32 + string_offset + 32, string_length
            )
        )
        string_bytes = string_value.to_bytes(string_length, "big")
        string_array.append(string_bytes.decode("utf-8"))

    return string_array


def stringified_bytes_to_bytes(hexstring: str):
    """Converts a string of bytes to a bytes memory type"""

    hexstring = stripped(hexstring)
    hexstring_len = (len(hexstring) + 1) // 2
    hexstring_len_enc = stripped(hex(hexstring_len)).rjust(64, "0")
    hexstring_len_ceil = (hexstring_len + 31) // 32 * 32

    ret_bytes = bytes.fromhex(
        "00" * 31
        + "20"
        + hexstring_len_enc
        + hexstring.ljust(hexstring_len_ceil * 2, "0")
    )
    ret_len = len(ret_bytes)

    return BitVecVal(int.from_bytes(ret_bytes, "big"), ret_len * 8)


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
                return f"startPrank({str(self.addr)})"
            else:
                return f"prank({str(self.addr)})"
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


def create_generic(ex, bits: int, var_name: str, type_name: str) -> BitVecRef:
    label = f"halmos_{var_name}_{type_name}_{ex.new_symbol_id():>02}"
    return BitVec(label, BitVecSorts[bits])


def create_uint(ex, arg):
    bits = int_of(
        extract_bytes(arg, 4, 32), "symbolic bit size for halmos.createUint()"
    )
    if bits > 256:
        raise HalmosException(f"bitsize larger than 256: {bits}")

    name = name_of(extract_string_argument(arg, 1))
    return uint256(create_generic(ex, bits, name, f"uint{bits}"))


def create_uint256(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return create_generic(ex, 256, name, "uint256")


def create_int(ex, arg):
    bits = int_of(
        extract_bytes(arg, 4, 32), "symbolic bit size for halmos.createUint()"
    )
    if bits > 256:
        raise HalmosException(f"bitsize larger than 256: {bits}")

    name = name_of(extract_string_argument(arg, 1))
    return int256(create_generic(ex, bits, name, f"int{bits}"))


def create_int256(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return create_generic(ex, 256, name, "int256")


def create_bytes(ex, arg):
    byte_size = int_of(
        extract_bytes(arg, 4, 32), "symbolic byte size for halmos.createBytes()"
    )
    name = name_of(extract_string_argument(arg, 1))
    symbolic_bytes = create_generic(ex, byte_size * 8, name, "bytes")
    return Concat(con(32), con(byte_size), symbolic_bytes)


def create_string(ex, arg):
    byte_size = int_of(
        extract_bytes(arg, 4, 32), "symbolic byte size for halmos.createString()"
    )
    name = name_of(extract_string_argument(arg, 1))
    symbolic_string = create_generic(ex, byte_size * 8, name, "string")
    return Concat(con(32), con(byte_size), symbolic_string)


def create_bytes4(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return uint256(create_generic(ex, 32, name, "bytes4"))


def create_bytes32(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return create_generic(ex, 256, name, "bytes32")


def create_address(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return uint256(create_generic(ex, 160, name, "address"))


def create_bool(ex, arg):
    name = name_of(extract_string_argument(arg, 0))
    return uint256(create_generic(ex, 1, name, "bool"))


def apply_vmaddr(ex, private_key: Any):
    # check if this private key has an existing address associated with it
    known_keys = ex.known_keys
    addr = known_keys.get(private_key, None)
    if addr is None:
        # if not, create a new address
        addr = f_vmaddr(private_key)

        # mark the addresses as distinct
        for other_key, other_addr in known_keys.items():
            distinct = Implies(private_key != other_key, addr != other_addr)
            ex.path.append(distinct)

        # associate the new address with the private key
        known_keys[private_key] = addr

    return addr


class halmos_cheat_code:
    # address constant SVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('svm cheat code')))));
    address: BitVecRef = con_addr(0xF3993A62377BCD56AE39D773740A5390411E8BC9)

    handlers = {
        0x66830DFA: create_uint,  # createUint(uint256,string)
        0xBC7BEEFC: create_uint256,  # createUint256(string)
        0x49B9C7D4: create_int,  # createInt(uint256,string)
        0xC2CE6AED: create_int256,  # createInt256(string)
        0xEEF5311D: create_bytes,  # createBytes(uint256,string)
        0xCE68656C: create_string,  # createString(uint256,string)
        0xDE143925: create_bytes4,  # createBytes4(string)
        0xBF72FA66: create_bytes32,  # createBytes32(string)
        0x3B0FA01B: create_address,  # createAddress(string)
        0x6E0BB659: create_bool,  # createBool(string)
    }

    @staticmethod
    def handle(ex, arg: BitVecRef) -> BitVecRef:
        funsig = int_of(extract_funsig(arg), "symbolic halmos cheatcode")
        if handler := halmos_cheat_code.handlers.get(funsig):
            return handler(ex, arg)

        error_msg = f"Unknown halmos cheat code: function selector = 0x{funsig:0>8x}, calldata = {hexify(arg)}"
        raise HalmosException(error_msg)


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

    # addr(uint256)
    addr_sig: int = 0xFFA18649

    # sign(uint256,bytes32)
    sign_sig: int = 0xE341EAA4

    # label(address,string)
    label_sig: int = 0xC657C718

    @staticmethod
    def handle(sevm, ex, arg: BitVec) -> BitVec:
        funsig: int = int_of(extract_funsig(arg), "symbolic hevm cheatcode")

        # vm.fail()
        # BitVecVal(hevm_cheat_code.fail_payload, 800)
        if arg == hevm_cheat_code.fail_payload:
            raise FailCheatcode()

        # vm.assume(bool)
        elif (
            eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
            and funsig == hevm_cheat_code.assume_sig
        ):
            assume_cond = simplify(is_non_zero(Extract(255, 0, arg)))
            ex.path.append(assume_cond)

        # vm.getCode(string)
        elif funsig == hevm_cheat_code.get_code_sig:
            calldata = bv_value_to_bytes(arg)
            path_len = int.from_bytes(calldata[36:68], "big")
            path = calldata[68 : 68 + path_len].decode("utf-8")

            if ":" in path:
                [filename, contract_name] = path.split(":")
                path = "out/" + filename + "/" + contract_name + ".json"

            target = sevm.options["target"].rstrip("/")
            path = target + "/" + path

            with open(path) as f:
                artifact = json.loads(f.read())

            if artifact["bytecode"]["object"]:
                bytecode = artifact["bytecode"]["object"].replace("0x", "")
            else:
                bytecode = artifact["bytecode"].replace("0x", "")

            return stringified_bytes_to_bytes(bytecode)

        # vm.prank(address)
        elif funsig == hevm_cheat_code.prank_sig:
            result = ex.prank.prank(uint160(Extract(255, 0, arg)))
            if not result:
                raise HalmosException("You have an active prank already.")

        # vm.startPrank(address)
        elif funsig == hevm_cheat_code.start_prank_sig:
            result = ex.prank.startPrank(uint160(Extract(255, 0, arg)))
            if not result:
                raise HalmosException("You have an active prank already.")

        # vm.stopPrank()
        elif funsig == hevm_cheat_code.stop_prank_sig:
            ex.prank.stopPrank()

        # vm.deal(address,uint256)
        elif funsig == hevm_cheat_code.deal_sig:
            who = uint160(Extract(511, 256, arg))
            amount = simplify(Extract(255, 0, arg))
            ex.balance_update(who, amount)

        # vm.store(address,bytes32,bytes32)
        elif funsig == hevm_cheat_code.store_sig:
            store_account = uint160(Extract(767, 512, arg))
            store_slot = simplify(Extract(511, 256, arg))
            store_value = simplify(Extract(255, 0, arg))
            store_account_addr = sevm.resolve_address_alias(ex, store_account)
            if store_account_addr is not None:
                sevm.sstore(ex, store_account_addr, store_slot, store_value)
            else:
                raise HalmosException(f"uninitialized account: {store_account}")

        # vm.load(address,bytes32)
        elif funsig == hevm_cheat_code.load_sig:
            load_account = uint160(Extract(511, 256, arg))
            load_slot = simplify(Extract(255, 0, arg))
            load_account_addr = sevm.resolve_address_alias(ex, load_account)
            if load_account_addr is not None:
                return sevm.sload(ex, load_account_addr, load_slot)
            else:
                raise HalmosException(f"uninitialized account: {store_account}")

        # vm.fee(uint256)
        elif funsig == hevm_cheat_code.fee_sig:
            ex.block.basefee = simplify(Extract(255, 0, arg))

        # vm.chainId(uint256)
        elif funsig == hevm_cheat_code.chainid_sig:
            ex.block.chainid = simplify(Extract(255, 0, arg))

        # vm.coinbase(address)
        elif funsig == hevm_cheat_code.coinbase_sig:
            ex.block.coinbase = uint160(Extract(255, 0, arg))

        # vm.difficulty(uint256)
        elif funsig == hevm_cheat_code.difficulty_sig:
            ex.block.difficulty = simplify(Extract(255, 0, arg))

        # vm.roll(uint256)
        elif funsig == hevm_cheat_code.roll_sig:
            ex.block.number = simplify(Extract(255, 0, arg))

        # vm.warp(uint256)
        elif funsig == hevm_cheat_code.warp_sig:
            ex.block.timestamp = simplify(Extract(255, 0, arg))

        # vm.etch(address,bytes)
        elif funsig == hevm_cheat_code.etch_sig:
            who = extract_bytes(arg, 4 + 12, 20)

            # who must be concrete
            if not is_bv_value(who):
                error_msg = f"vm.etch(address who, bytes code) must have concrete argument `who` but received {who}"
                raise HalmosException(error_msg)

            # code must be concrete
            try:
                code_offset = int_of(extract_bytes(arg, 4 + 32, 32))
                code_length = int_of(extract_bytes(arg, 4 + code_offset, 32))

                code_bytes = bytes()
                if code_length != 0:
                    code_bv = extract_bytes(arg, 4 + code_offset + 32, code_length)
                    code_bytes = bv_value_to_bytes(code_bv)
                ex.set_code(who, code_bytes)
            except Exception as e:
                error_msg = f"vm.etch(address who, bytes code) must have concrete argument `code` but received calldata {arg}"
                raise HalmosException(error_msg) from e

        # ffi(string[]) returns (bytes)
        elif funsig == hevm_cheat_code.ffi_sig:
            if not sevm.options.get("ffi"):
                error_msg = "ffi cheatcode is disabled. Run again with `--ffi` if you want to enable it"
                raise HalmosException(error_msg)

            cmd = extract_string_array_argument(arg, 0)

            debug = sevm.options.get("debug", False)
            verbose = sevm.options.get("verbose", 0)
            if debug or verbose:
                print(f"[vm.ffi] {cmd}")

            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            (stdout, stderr) = process.communicate()

            if stderr:
                stderr_str = stderr.decode("utf-8")
                print(f"[vm.ffi] {cmd}, stderr: {red(stderr_str)}")

            out_str = stdout.decode("utf-8").strip()

            if debug:
                print(f"[vm.ffi] {cmd}, stdout: {green(out_str)}")

            if decode_hex(out_str) is not None:
                # encode hex strings as is for compatibility with foundry's ffi
                pass
            else:
                # encode non-hex strings as hex
                out_str = out_str.encode("utf-8").hex()

            return stringified_bytes_to_bytes(out_str)

        elif funsig == hevm_cheat_code.addr_sig:
            private_key = extract_bytes(arg, 4, 32)

            # TODO: handle concrete private key (return directly the corresponding address)
            # TODO: check (or assume?) private_key is valid
            #  - less than curve order
            #  - not zero
            # TODO: add constraints that the generated addresses are reasonable
            #  - not zero
            #  - not the address of a known contract

            addr = apply_vmaddr(ex, private_key)
            return uint256(addr)

        elif funsig == hevm_cheat_code.sign_sig:
            key = extract_bytes(arg, 4, 32)
            digest = extract_bytes(arg, 4 + 32, 32)

            # TODO: handle concrete private key + digest (generate concrete signature)

            # check for an existing signature
            known_sigs = ex.known_sigs
            (v, r, s) = known_sigs.get((key, digest), (None, None, None))
            if (v, r, s) == (None, None, None):
                # if not, create a new signature
                v, r, s = (f(key, digest) for f in (f_sign_v, f_sign_r, f_sign_s))

                # associate the new signature with the private key and digest
                known_sigs[(key, digest)] = (v, r, s)

                # constrain values to their expected ranges
                in_range = And(
                    Or(v == 27, v == 28),
                    ULT(0, r),
                    ULT(r, secp256k1n),
                    ULT(0, s),
                    ULT(s, secp256k1n),
                )
                ex.path.append(in_range)

                # explicitly model malleability
                recover = f_ecrecover(digest, v, r, s)
                recover_malleable = f_ecrecover(digest, v ^ 1, r, secp256k1n - s)

                addr = apply_vmaddr(ex, key)
                ex.path.append(recover == addr)
                ex.path.append(recover_malleable == addr)

                # mark signatures as distinct if key or digest are distinct
                # NOTE: the condition `And(r != _r, s != _s)` is stronger than `Or(v != _v, r != _r, s != _s)` which is sound
                # TODO: we need to figure out whether this stronger condition is necessary and whether it could lead to unsound results in practical cases
                for (_key, _digest), (_v, _r, _s) in known_sigs.items():
                    distinct = Implies(
                        Or(key != _key, digest != _digest),
                        Or(v != _v, r != _r, s != _s),
                    )
                    ex.path.append(distinct)

            return Concat(uint256(v), r, s)

        elif funsig == hevm_cheat_code.label_sig:
            addr = extract_bytes(arg, 4, 32)
            label = extract_string_argument(arg, 1)

            # TODO: no-op for now
            pass

        else:
            # TODO: support other cheat codes
            msg = f"Unsupported cheat code: calldata = {hexify(arg)}"
            raise HalmosException(msg)
