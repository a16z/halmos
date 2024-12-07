# SPDX-License-Identifier: AGPL-3.0

import json
import re
from dataclasses import dataclass
from subprocess import PIPE, Popen

from z3 import (
    ULT,
    And,
    BitVec,
    BitVecRef,
    Concat,
    Function,
    Implies,
    Not,
    Or,
    eq,
    is_bv,
    is_bv_value,
    is_false,
    simplify,
    unsat,
)

from .assertions import assert_cheatcode_handler
from .bytevec import ByteVec
from .calldata import (
    FunctionInfo,
    get_abi,
    mk_calldata,
)
from .exceptions import FailCheatcode, HalmosException, InfeasiblePath, NotConcreteError
from .logs import debug
from .mapper import BuildOut
from .utils import (
    Address,
    BitVecSort8,
    BitVecSort160,
    BitVecSort256,
    BitVecSorts,
    Word,
    assert_address,
    con,
    con_addr,
    decode_hex,
    extract_bytes,
    extract_funsig,
    extract_string_argument,
    f_ecrecover,
    green,
    hexify,
    int256,
    int_of,
    is_non_zero,
    red,
    secp256k1n,
    stripped,
    uid,
    uint160,
    uint256,
)

# f_vmaddr(key) -> address
f_vmaddr = Function("f_vmaddr", BitVecSort256, BitVecSort160)

# f_sign_v(key, digest) -> v
f_sign_v = Function("f_sign_v", BitVecSort256, BitVecSort256, BitVecSort8)

# f_sign_r(key, digest) -> r
f_sign_r = Function("f_sign_r", BitVecSort256, BitVecSort256, BitVecSort256)

# f_sign_s(key, digest) -> s
f_sign_s = Function("f_sign_s", BitVecSort256, BitVecSort256, BitVecSort256)


def name_of(x: str) -> str:
    if not isinstance(x, str):
        raise NotConcreteError(f"expected concrete string but got: {x}")

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


def stringified_bytes_to_bytes(hexstring: str) -> ByteVec:
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

    return ByteVec(ret_bytes)


@dataclass(frozen=True)
class PrankResult:
    sender: Address | None = None
    origin: Address | None = None

    def __bool__(self) -> bool:
        """
        True iff either sender or origin is set.
        """
        return self.sender is not None or self.origin is not None

    def __str__(self) -> str:
        return f"{hexify(self.sender)}, {hexify(self.origin)}"


NO_PRANK = PrankResult()


@dataclass
class Prank:
    """
    A mutable object to store the current prank context.

    Because it's mutable, it must be copied across contexts.

    Can test for the existence of an active prank with `if prank: ...`

    A prank is active if either sender or origin is set.

    - prank(address) sets sender
    - prank(address, address) sets both sender and origin
    """

    active: PrankResult = NO_PRANK  # active prank context
    keep: bool = False  # start / stop prank

    def __bool__(self) -> bool:
        """
        True iff either sender or origin is set.
        """
        return bool(self.active)

    def __str__(self) -> str:
        if not self:
            return "no active prank"

        fn_name = "startPrank" if self.keep else "prank"
        return f"{fn_name}({str(self.active)})"

    def lookup(self, to: Address) -> PrankResult:
        """
        If `to` is an eligible prank destination, return the active prank context.

        If `keep` is False, this resets the prank context.
        """

        assert_address(to)
        if (
            self
            and not eq(to, hevm_cheat_code.address)
            and not eq(to, halmos_cheat_code.address)
        ):
            result = self.active
            if not self.keep:
                self.stopPrank()
            return result

        return NO_PRANK

    def prank(
        self, sender: Address, origin: Address | None = None, _keep: bool = False
    ) -> bool:
        assert_address(sender)
        if self.active:
            return False

        self.active = PrankResult(sender=sender, origin=origin)
        self.keep = _keep
        return True

    def startPrank(self, sender: Address, origin: Address | None = None) -> bool:
        return self.prank(sender, origin, _keep=True)

    def stopPrank(self) -> bool:
        # stopPrank calls are allowed even when no active prank exists
        self.active = NO_PRANK
        self.keep = False
        return True


def symbolic_storage(ex, arg, sevm, stack, step_id):
    account = uint160(arg.get_word(4))
    account_alias = sevm.resolve_address_alias(
        ex, account, stack, step_id, allow_branching=False
    )

    if account_alias is None:
        error_msg = f"enableSymbolicStorage() is not allowed for a nonexistent account: {hexify(account)}"
        raise HalmosException(error_msg)

    ex.storage[account_alias].symbolic = True

    return ByteVec()  # empty return data


def create_calldata_contract(ex, arg, sevm, stack, step_id):
    contract_name = name_of(extract_string_argument(arg, 0))
    return create_calldata_generic(ex, sevm, contract_name)


def create_calldata_contract_bool(ex, arg, sevm, stack, step_id):
    contract_name = name_of(extract_string_argument(arg, 0))
    include_view = int_of(
        extract_bytes(arg, 4 + 32 * 1, 32),
        "symbolic boolean flag for SVM.createCalldata()",
    )
    return create_calldata_generic(
        ex, sevm, contract_name, include_view=bool(include_view)
    )


def create_calldata_file_contract(ex, arg, sevm, stack, step_id):
    filename = name_of(extract_string_argument(arg, 0))
    contract_name = name_of(extract_string_argument(arg, 1))
    return create_calldata_generic(ex, sevm, contract_name, filename)


def create_calldata_file_contract_bool(ex, arg, sevm, stack, step_id):
    filename = name_of(extract_string_argument(arg, 0))
    contract_name = name_of(extract_string_argument(arg, 1))
    include_view = int_of(
        extract_bytes(arg, 4 + 32 * 2, 32),
        "symbolic boolean flag for SVM.createCalldata()",
    )
    return create_calldata_generic(
        ex, sevm, contract_name, filename, bool(include_view)
    )


def encode_tuple_bytes(data: BitVecRef | ByteVec | bytes) -> ByteVec:
    """
    Return ABI encoding of a tuple containing a single bytes element.

    encoding of a tuple (bytes): 32 (offset) + length + data
    """

    length = data.size() // 8 if is_bv(data) else len(data)
    result = ByteVec((32).to_bytes(32) + int(length).to_bytes(32))
    result.append(data)
    return result


def create_calldata_generic(ex, sevm, contract_name, filename=None, include_view=False):
    """
    Generate arbitrary symbolic calldata for the given contract.

    Dynamic-array arguments are sized in the same way of regular test functions.

    The contract is identified by its contract name and optional filename.
    TODO: provide variants that require only the contract address.
    """
    contract_json = BuildOut().get_by_name(contract_name, filename)[0]

    abi = get_abi(contract_json)
    methodIdentifiers = contract_json["methodIdentifiers"]

    results = []

    # empty calldata for receive() and fallback()
    results.append(encode_tuple_bytes(b""))

    # nonempty calldata for fallback()
    fallback_selector = BitVec(
        f"fallback_selector_{uid()}_{ex.new_symbol_id():>02}", 4 * 8
    )
    fallback_input_length = 1024  # TODO: configurable
    fallback_input = BitVec(
        f"fallback_input_{uid()}_{ex.new_symbol_id():>02}", fallback_input_length * 8
    )
    results.append(encode_tuple_bytes(Concat(fallback_selector, fallback_input)))

    for funsig in methodIdentifiers:
        funname = funsig.split("(")[0]
        funselector = methodIdentifiers[funsig]
        funinfo = FunctionInfo(funname, funsig, funselector)

        # assume fallback_selector differs from all existing selectors
        ex.path.append(fallback_selector != con(int(funselector, 16), 32))

        if not include_view:
            fun_abi = abi[funinfo.sig]
            if fun_abi["stateMutability"] in ["pure", "view"]:
                continue

        calldata, dyn_params = mk_calldata(
            abi,
            funinfo,
            sevm.options,
            new_symbol_id=ex.new_symbol_id,
        )
        # TODO: this may accumulate dynamic size candidates from multiple calldata into a single path object,
        # which is not optimal, as unnecessary size candidates will need to be copied during path branching for each calldata.
        ex.path.process_dyn_params(dyn_params)

        results.append(encode_tuple_bytes(calldata))

    return results


def create_generic(ex, bits: int, var_name: str, type_name: str) -> BitVecRef:
    label = f"halmos_{var_name}_{type_name}_{uid()}_{ex.new_symbol_id():>02}"
    return BitVec(label, BitVecSorts[bits])


def create_uint(ex, arg, **kwargs):
    bits = int_of(
        extract_bytes(arg, 4, 32), "symbolic bit size for halmos.createUint()"
    )
    if bits > 256:
        raise HalmosException(f"bitsize larger than 256: {bits}")

    name = name_of(extract_string_argument(arg, 1))
    return ByteVec(uint256(create_generic(ex, bits, name, f"uint{bits}")))


def create_uint256(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    return ByteVec(create_generic(ex, 256, name, "uint256"))


def create_int(ex, arg, **kwargs):
    bits = int_of(
        extract_bytes(arg, 4, 32), "symbolic bit size for halmos.createUint()"
    )
    if bits > 256:
        raise HalmosException(f"bitsize larger than 256: {bits}")

    name = name_of(extract_string_argument(arg, 1))
    return ByteVec(int256(create_generic(ex, bits, name, f"int{bits}")))


def create_int256(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    return ByteVec(create_generic(ex, 256, name, "int256"))


def create_bytes(ex, arg, **kwargs):
    byte_size = int_of(
        extract_bytes(arg, 4, 32), "symbolic byte size for halmos.createBytes()"
    )
    name = name_of(extract_string_argument(arg, 1))
    symbolic_bytes = create_generic(ex, byte_size * 8, name, "bytes")
    return encode_tuple_bytes(symbolic_bytes)


def create_string(ex, arg, **kwargs):
    byte_size = int_of(
        extract_bytes(arg, 4, 32), "symbolic byte size for halmos.createString()"
    )
    name = name_of(extract_string_argument(arg, 1))
    symbolic_string = create_generic(ex, byte_size * 8, name, "string")
    return encode_tuple_bytes(symbolic_string)


def create_bytes4(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    result = ByteVec(create_generic(ex, 32, name, "bytes4"))
    result.append((0).to_bytes(28))  # pad right
    return result


def create_bytes32(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    return ByteVec(create_generic(ex, 256, name, "bytes32"))


def create_address(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    return ByteVec(uint256(create_generic(ex, 160, name, "address")))


def create_bool(ex, arg, **kwargs):
    name = name_of(extract_string_argument(arg, 0))
    return ByteVec(uint256(create_generic(ex, 1, name, "bool")))


def apply_vmaddr(ex, private_key: Word):
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
        0xDC00BA4D: symbolic_storage,  # enableSymbolicStorage(address)
        0xBE92D5A2: create_calldata_contract,  # createCalldata(string)
        0xDEEF391B: create_calldata_contract_bool,  # createCalldata(string,bool)
        0x88298B32: create_calldata_file_contract,  # createCalldata(string,string)
        0x607C5C90: create_calldata_file_contract_bool,  # createCalldata(string,string,bool)
    }

    @staticmethod
    def handle(sevm, ex, arg: BitVecRef, stack, step_id) -> list[BitVecRef]:
        funsig = int_of(extract_funsig(arg), "symbolic halmos cheatcode")
        if handler := halmos_cheat_code.handlers.get(funsig):
            result = handler(ex, arg, sevm=sevm, stack=stack, step_id=step_id)
            return result if isinstance(result, list) else [result]

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
    fail_payload = ByteVec(
        bytes.fromhex(
            "70ca10bb"
            + "0000000000000000000000007109709ecfa91a80626ff3989d68f67f5b1dd12d"
            + "6661696c65640000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )

    # bytes4(keccak256("assume(bool)"))
    assume_sig: int = 0x4C63E562

    # bytes4(keccak256("getCode(string)"))
    get_code_sig: int = 0x8D1CC925

    # bytes4(keccak256("prank(address)"))
    prank_sig: int = 0xCA669FA7

    # bytes4(keccak256("prank(address,address)"))
    prank_addr_addr_sig: int = 0x47E50CCE

    # bytes4(keccak256("startPrank(address)"))
    start_prank_sig: int = 0x06447D56

    # bytes4(keccak256("startPrank(address,address)"))
    start_prank_addr_addr_sig: int = 0x45B56078

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

    # bytes4(keccak256("getBlockNumber()"))
    get_block_number_sig: int = 0x42CBB15C

    @staticmethod
    def handle(sevm, ex, arg: ByteVec, stack, step_id) -> ByteVec | None:
        funsig: int = int_of(arg[:4].unwrap(), "symbolic hevm cheatcode")
        ret = ByteVec()

        # vm.assert*
        if funsig in assert_cheatcode_handler:
            vm_assert = assert_cheatcode_handler[funsig](arg)
            not_cond = simplify(Not(vm_assert.cond))

            if ex.check(not_cond) != unsat:
                new_ex = sevm.create_branch(ex, not_cond, ex.pc)
                new_ex.halt(data=ByteVec(), error=FailCheatcode(f"{vm_assert}"))
                stack.push(new_ex, step_id)

            return ret

        # vm.assume(bool)
        elif funsig == hevm_cheat_code.assume_sig:
            assume_cond = simplify(is_non_zero(arg.get_word(4)))
            if is_false(assume_cond):
                raise InfeasiblePath("vm.assume(false)")
            ex.path.append(assume_cond, branching=True)
            return ret

        # vm.getCode(string)
        elif funsig == hevm_cheat_code.get_code_sig:
            path_len = arg.get_word(36)
            path = arg[68 : 68 + path_len].unwrap().decode("utf-8")

            if ":" in path:
                [filename, contract_name] = path.split(":")
                path = "out/" + filename + "/" + contract_name + ".json"

            target = sevm.options.root.rstrip("/")
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
            sender = uint160(arg.get_word(4))
            result = ex.context.prank.prank(sender)
            if not result:
                raise HalmosException("You have an active prank already.")
            return ret

        # vm.prank(address sender, address origin)
        elif funsig == hevm_cheat_code.prank_addr_addr_sig:
            sender = uint160(arg.get_word(4))
            origin = uint160(arg.get_word(36))
            result = ex.context.prank.prank(sender, origin)
            if not result:
                raise HalmosException("You have an active prank already.")
            return ret

        # vm.startPrank(address)
        elif funsig == hevm_cheat_code.start_prank_sig:
            address = uint160(arg.get_word(4))
            result = ex.context.prank.startPrank(address)
            if not result:
                raise HalmosException("You have an active prank already.")
            return ret

        # vm.startPrank(address sender, address origin)
        elif funsig == hevm_cheat_code.start_prank_addr_addr_sig:
            sender = uint160(arg.get_word(4))
            origin = uint160(arg.get_word(36))
            result = ex.context.prank.startPrank(sender, origin)
            if not result:
                raise HalmosException("You have an active prank already.")
            return ret

        # vm.stopPrank()
        elif funsig == hevm_cheat_code.stop_prank_sig:
            ex.context.prank.stopPrank()
            return ret

        # vm.deal(address,uint256)
        elif funsig == hevm_cheat_code.deal_sig:
            who = uint160(arg.get_word(4))
            amount = uint256(arg.get_word(36))
            ex.balance_update(who, amount)
            return ret

        # vm.store(address,bytes32,bytes32)
        elif funsig == hevm_cheat_code.store_sig:
            if arg == hevm_cheat_code.fail_payload:
                # there isn't really a vm.fail() cheatcode, calling DSTest.fail()
                # really triggers vm.store(HEVM_ADDRESS, "failed", 1)
                # let's intercept it and raise an exception instead of actually storing
                # since HEVM_ADDRESS is an uninitialized account
                raise FailCheatcode()

            store_account = uint160(arg.get_word(4))
            store_slot = uint256(arg.get_word(36))
            store_value = uint256(arg.get_word(68))
            store_account_alias = sevm.resolve_address_alias(
                ex, store_account, stack, step_id, allow_branching=False
            )

            if store_account_alias is None:
                error_msg = f"vm.store() is not allowed for a nonexistent account: {hexify(store_account)}"
                raise HalmosException(error_msg)

            sevm.sstore(ex, store_account_alias, store_slot, store_value)
            return ret

        # vm.load(address,bytes32)
        elif funsig == hevm_cheat_code.load_sig:
            load_account = uint160(arg.get_word(4))
            load_slot = uint256(arg.get_word(36))
            load_account_alias = sevm.resolve_address_alias(
                ex, load_account, stack, step_id, allow_branching=False
            )

            if load_account_alias is None:
                # since load_account doesn't exist, its storage is empty.
                # note: the storage cannot be symbolic, as the symbolic storage cheatcode fails for nonexistent addresses.
                return ByteVec(con(0))

            return ByteVec(sevm.sload(ex, load_account_alias, load_slot))

        # vm.fee(uint256)
        elif funsig == hevm_cheat_code.fee_sig:
            ex.block.basefee = arg.get_word(4)
            return ret

        # vm.chainId(uint256)
        elif funsig == hevm_cheat_code.chainid_sig:
            ex.block.chainid = arg.get_word(4)
            return ret

        # vm.coinbase(address)
        elif funsig == hevm_cheat_code.coinbase_sig:
            ex.block.coinbase = uint160(arg.get_word(4))
            return ret

        # vm.difficulty(uint256)
        elif funsig == hevm_cheat_code.difficulty_sig:
            ex.block.difficulty = arg.get_word(4)
            return ret

        # vm.roll(uint256)
        elif funsig == hevm_cheat_code.roll_sig:
            ex.block.number = arg.get_word(4)
            return ret

        # vm.warp(uint256)
        elif funsig == hevm_cheat_code.warp_sig:
            ex.block.timestamp = arg.get_word(4)
            return ret

        # vm.etch(address,bytes)
        elif funsig == hevm_cheat_code.etch_sig:
            who = uint160(arg.get_word(4))

            # who must be concrete
            if not is_bv_value(who):
                error_msg = f"vm.etch(address who, bytes code) must have concrete argument `who` but received {who}"
                raise HalmosException(error_msg)

            # code must be concrete
            code_offset = int_of(arg.get_word(36), "symbolic code offset")
            code_length = int_of(arg.get_word(4 + code_offset), "symbolic code length")

            code_loc = 4 + code_offset + 32
            code_bytes = arg[code_loc : code_loc + code_length]
            ex.set_code(who, code_bytes)

            # vm.etch() initializes but does not clear storage
            ex.storage.setdefault(who, sevm.mk_storagedata())

            return ret

        # vm.ffi(string[]) returns (bytes)
        elif funsig == hevm_cheat_code.ffi_sig:
            if not sevm.options.ffi:
                error_msg = "ffi cheatcode is disabled. Run again with `--ffi` if you want to enable it"
                raise HalmosException(error_msg)

            cmd = extract_string_array_argument(arg, 0)

            if sevm.options.debug or sevm.options.verbose:
                print(f"[vm.ffi] {cmd}")

            process = Popen(cmd, stdout=PIPE, stderr=PIPE)
            (stdout, stderr) = process.communicate()

            if stderr:
                stderr_str = stderr.decode("utf-8")
                print(f"[vm.ffi] {cmd}, stderr: {red(stderr_str)}")

            out_str = stdout.decode("utf-8").strip()

            debug(f"[vm.ffi] {cmd}, stdout: {green(out_str)}")

            if decode_hex(out_str) is not None:
                # encode hex strings as is for compatibility with foundry's ffi
                pass
            else:
                # encode non-hex strings as hex
                out_str = out_str.encode("utf-8").hex()

            return stringified_bytes_to_bytes(out_str)

        # vm.addr(uint256 privateKey) returns (address keyAddr)
        elif funsig == hevm_cheat_code.addr_sig:
            private_key = uint256(extract_bytes(arg, 4, 32))

            # TODO: handle concrete private key (return directly the corresponding address)
            # TODO: check (or assume?) private_key is valid
            #  - less than curve order
            #  - not zero
            # TODO: add constraints that the generated addresses are reasonable
            #  - not zero
            #  - not the address of a known contract

            addr = apply_vmaddr(ex, private_key)
            ret.append(uint256(addr))
            return ret

        # vm.sign(uint256 privateKey, bytes32 digest) returns (uint8 v, bytes32 r, bytes32 s)
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

            ret.append(uint256(v))
            ret.append(r)
            ret.append(s)
            return ret

        # vm.label(address account, string calldata newLabel)
        elif funsig == hevm_cheat_code.label_sig:
            addr = extract_bytes(arg, 4, 32)

            # TODO: no-op for now
            # label = extract_string_argument(arg, 1)

            return ret

        # vm.getBlockNumber() return (uint256)
        elif funsig == hevm_cheat_code.get_block_number_sig:
            ret.append(uint256(ex.block.number))
            return ret

        else:
            # TODO: support other cheat codes
            msg = f"Unsupported cheat code: calldata = {hexify(arg)}"
            raise HalmosException(msg)
