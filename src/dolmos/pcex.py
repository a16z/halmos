# SPDX-License-Identifier: AGPL-3.0

"""
Pretty counterexamples, enabled with --pretty-counterexamples (-pcex).

The raw output of a counterexample is the solver model: one line per symbol, with the full
hex value of every word, e.g. 1024 bytes for a `bytes` argument whose length is 65. This module
turns the model into something that can be acted upon:

- the arguments of the test are decoded with its ABI: the lengths of dynamic arguments are
  applied, and values are rendered by type (decimal amounts, checksummed addresses, strings);
- `bytes` values that hold calldata are decoded with the ABIs of the compiled contracts,
  e.g. `Token.transfer(to: 0x…, amount: 2)` (halmos#369);
- `bytes4` values are rendered as function selectors, including the empty selector 0x00000000
  of plain ether transfers (halmos#419);
- invariant call sequences are rendered with their concrete senders, values and arguments;
- a forge test that replays the counterexample is generated;
- duplicate counterexamples are hidden (halmos#398).

Potentially invalid counterexamples are checked against the real EXP by the solver loop of
solve.py (see refine_exp, halmos#280).

Threading: rendering runs in the callbacks of the solver threads, so nothing here may touch
z3 objects, except the collect_* functions, which run on the main thread when a potential
assertion violation is found, and return plain Python data.
"""

import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from eth_hash.auto import keccak

# a raw model variable has .value (int) and .size_bits (int); see solve.ModelVariable
Model = dict

WORD_BITS = 256
WORD_MODULUS = 2**256

# selector of plain ether transfers and of calls with empty calldata
EMPTY_SELECTOR = b"\x00\x00\x00\x00"

# limits, to keep the output readable
MAX_INLINE_ITEMS = 8
MAX_HEX_BYTES = 160
MAX_DECODE_DEPTH = 2
MAX_ARRAY_LENGTH = 4096


#
# symbol names
#

# p_<path>_<abi type>_<uid>_<n>, created for ABI encoded arguments (see calldata.py);
# p_<path>_length_<uid>_<n> for the length of a dynamic array, bytes or string
p_symbol_pattern = re.compile(
    r"^p_(?P<path>.*)_(?P<typ>[a-z]+[0-9]*)_(?P<uid>[0-9a-f]{7})_(?P<n>\d+)$"
)

# dolmos_<label>_<type>_<uid>_<n>, created by svm.create* cheatcodes
svm_symbol_pattern = re.compile(
    r"^dolmos_(?P<label>.*)_(?P<typ>[a-z]+[0-9]*)_(?P<uid>[0-9a-f]{7})_(?P<n>\d+)$"
)

# transaction context of the calls of invariant testing
tx_symbol_pattern = re.compile(
    r"^dolmos_(?P<kind>msg_sender|msg_value|tx_origin)_(?P<addr>0x[0-9a-fA-F]+)_"
    r"(?P<uid>[0-9a-f]{7})_(?P<n>\d+)$"
)

timestamp_symbol_pattern = re.compile(
    r"^dolmos_block_timestamp_depth(?P<depth>\d+)_(?P<uid>[0-9a-f]{7})$"
)


def index_symbols(names: Iterable[str]) -> dict[tuple[str, str], list[str]]:
    """Maps (path, abi type or "length") to the p_ symbols with that path, in order"""
    index: dict[tuple[str, str], list[str]] = {}
    for name in names:
        if match := p_symbol_pattern.match(name):
            index.setdefault((match["path"], match["typ"]), []).append(name)
    return index


#
# ABI types
#


class UnsupportedType(Exception):
    pass


@dataclass(frozen=True)
class AbiType:
    # "base" (static types: uintN, intN, address, bool, bytesN), "bytes", "string",
    # "array" (T[]), "fixed" (T[k]), or "tuple"
    kind: str

    # canonical ABI type, e.g. "uint256", "bytes[]" or "(uint256,int8)"
    abi: str

    # element type of arrays
    elem: "AbiType | None" = None

    # length of fixed arrays
    length: int = 0

    # components of tuples, and their names
    components: tuple["AbiType", ...] = ()
    names: tuple[str, ...] = ()

    # solidity type from the compiler (internalType), e.g. "struct Foo.Bar[]"
    internal: str = ""

    @property
    def is_dynamic(self) -> bool:
        match self.kind:
            case "bytes" | "string" | "array":
                return True
            case "fixed":
                return self.elem.is_dynamic
            case "tuple":
                return any(c.is_dynamic for c in self.components)
            case _:
                return False

    @property
    def static_size(self) -> int:
        match self.kind:
            case "fixed":
                return self.length * self.elem.static_size
            case "tuple":
                return sum(c.head_size for c in self.components)
            case _:
                return 32

    @property
    def head_size(self) -> int:
        return 32 if self.is_dynamic else self.static_size

    @property
    def bits(self) -> int:
        """bit size of uintN/intN/bytesN"""
        digits = re.sub(r"^[a-z]+", "", self.abi)
        if self.abi.startswith("bytes"):
            return 8 * int(digits)
        return int(digits) if digits else WORD_BITS


def parse_abi_type(item: dict) -> AbiType:
    """Parses an ABI parameter, e.g. {"name": "x", "type": "uint256", "internalType": ...}"""
    return _parse_abi_type(
        item["type"], item.get("components"), item.get("internalType") or ""
    )


def params_type(inputs: list[dict]) -> AbiType:
    """The tuple of the parameters of a function"""
    components = tuple(parse_abi_type(item) for item in inputs)
    return AbiType(
        "tuple",
        "(" + ",".join(c.abi for c in components) + ")",
        components=components,
        names=tuple(item.get("name", "") for item in inputs),
    )


def _parse_abi_type(typ: str, components: list | None, internal: str) -> AbiType:
    if match := re.fullmatch(r"(.*)\[(\d*)\]", typ):
        inner, size = match.group(1), match.group(2)
        inner_internal = re.sub(r"\[\d*\]$", "", internal)
        elem = _parse_abi_type(inner, components, inner_internal)
        if size == "":
            return AbiType("array", f"{elem.abi}[]", elem=elem, internal=internal)
        return AbiType(
            "fixed",
            f"{elem.abi}[{size}]",
            elem=elem,
            length=int(size),
            internal=internal,
        )

    if typ == "tuple":
        parsed = tuple(parse_abi_type(c) for c in components or [])
        return AbiType(
            "tuple",
            "(" + ",".join(c.abi for c in parsed) + ")",
            components=parsed,
            names=tuple(c.get("name", "") for c in components or []),
            internal=internal,
        )

    if typ in ("bytes", "string"):
        return AbiType(typ, typ, internal=internal)

    if typ == "function":
        # address + selector, encoded as bytes24
        return AbiType("base", "bytes24", internal=internal)

    if match := re.fullmatch(r"(u?int)(\d*)", typ):
        return AbiType(
            "base", f"{match.group(1)}{match.group(2) or 256}", internal=internal
        )

    if re.fullmatch(r"address|bool|bytes([1-9]|[12][0-9]|3[0-2])", typ):
        return AbiType("base", typ, internal=internal)

    raise UnsupportedType(typ)


#
# values
#


@dataclass
class Val:
    t: AbiType

    # static types: the ABI encoded word
    word: int = 0

    # bytes, string
    data: bytes = b""

    # arrays, tuples
    items: list["Val"] = field(default_factory=list)

    # the value is absent from the model: any value works
    free: bool = False

    def is_clean(self) -> bool:
        """whether the value is a valid ABI encoding of its type"""
        t = self.t
        if t.kind == "base":
            return is_clean_word(t, self.word)
        return all(item.is_clean() for item in self.items)


def is_clean_word(t: AbiType, word: int) -> bool:
    abi = t.abi
    if abi.startswith("uint"):
        return word < 2**t.bits
    if abi.startswith("int"):
        value = signed(word)
        return -(2 ** (t.bits - 1)) <= value < 2 ** (t.bits - 1)
    if abi == "address":
        return word < 2**160
    if abi == "bool":
        return word in (0, 1)
    if abi.startswith("bytes"):
        return word % 2 ** (WORD_BITS - t.bits) == 0
    return True


def signed(word: int, bits: int = WORD_BITS) -> int:
    word %= 2**bits
    return word - 2**bits if word >= 2 ** (bits - 1) else word


class ModelReader:
    """Reads ABI values from the symbols of a call and the model"""

    def __init__(self, model: Model, symbols: dict[tuple[str, str], list[str]]):
        self.model = model
        self.symbols = {key: list(names) for key, names in symbols.items()}
        self.used: set[str] = set()

    def take(self, path: str, typ: str):
        """returns (symbol name or None, model variable or None)"""
        names = self.symbols.get((path, typ))
        if not names:
            return None, None
        name = names.pop(0)
        self.used.add(name)
        return name, self.model.get(name)

    def read(self, t: AbiType, path: str) -> Val:
        match t.kind:
            case "tuple":
                prefix = f"{path}." if path else ""
                items = [
                    self.read(c, prefix + name)
                    for c, name in zip(t.components, t.names, strict=True)
                ]
                return Val(t, items=items)

            case "fixed":
                items = [self.read(t.elem, f"{path}[{i}]") for i in range(t.length)]
                return Val(t, items=items)

            case "array":
                length, free = self.read_length(path)
                items = [self.read(t.elem, f"{path}[{i}]") for i in range(length)]
                return Val(t, items=items, free=free)

            case "bytes" | "string":
                length, free = self.read_length(path)
                name, var = self.take(path, t.kind)
                raw = var.value.to_bytes(var.size_bits // 8, "big") if var else b""
                data = raw[:length] + bytes(max(0, length - len(raw)))
                return Val(t, data=data, free=free)

            case _:
                name, var = self.take(path, t.abi)
                return Val(t, word=var.value if var else 0, free=var is None)

    def read_length(self, path: str) -> tuple[int, bool]:
        name, var = self.take(path, "length")
        if var is None:
            return 0, True
        return min(var.value, MAX_ARRAY_LENGTH), False


#
# ABI decoding and encoding of concrete values
#


class AbiDecodeError(Exception):
    pass


def _word_at(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 32 > len(data):
        raise AbiDecodeError(f"out of bounds read at {pos}")
    return int.from_bytes(data[pos : pos + 32], "big")


def abi_decode(t: AbiType, data: bytes, pos: int = 0) -> Val:
    """Decodes the value of type t encoded at data[pos:] (strict, raises AbiDecodeError)"""
    match t.kind:
        case "base":
            return Val(t, word=_word_at(data, pos))

        case "bytes" | "string":
            length = _word_at(data, pos)
            if pos + 32 + length > len(data):
                raise AbiDecodeError(f"{t.abi} of length {length} out of bounds")
            return Val(t, data=data[pos + 32 : pos + 32 + length])

        case "array":
            length = _word_at(data, pos)
            if length > (len(data) - pos - 32) // 32 or length > MAX_ARRAY_LENGTH:
                raise AbiDecodeError(f"array of length {length} out of bounds")
            return Val(t, items=_decode_tuple([t.elem] * length, data, pos + 32))

        case "fixed":
            return Val(t, items=_decode_tuple([t.elem] * t.length, data, pos))

        case "tuple":
            return Val(t, items=_decode_tuple(list(t.components), data, pos))

    raise AbiDecodeError(t.kind)


def _decode_tuple(types: list[AbiType], data: bytes, base: int) -> list[Val]:
    items = []
    head = base
    for t in types:
        if t.is_dynamic:
            offset = _word_at(data, head)
            if offset >= len(data):
                raise AbiDecodeError(f"offset {offset} out of bounds")
            items.append(abi_decode(t, data, base + offset))
        else:
            items.append(abi_decode(t, data, head))
        head += t.head_size
    return items


def abi_encode(v: Val) -> bytes:
    t = v.t
    match t.kind:
        case "base":
            return (v.word % WORD_MODULUS).to_bytes(32, "big")
        case "bytes" | "string":
            padding = bytes(-len(v.data) % 32)
            return len(v.data).to_bytes(32, "big") + v.data + padding
        case "array":
            return len(v.items).to_bytes(32, "big") + _encode_tuple(v.items)
        case _:
            return _encode_tuple(v.items)


def _encode_tuple(items: list[Val]) -> bytes:
    head_size = sum(item.t.head_size for item in items)
    heads, tails = [], []
    tail_size = 0
    for item in items:
        if item.t.is_dynamic:
            heads.append((head_size + tail_size).to_bytes(32, "big"))
            encoded = abi_encode(item)
            tails.append(encoded)
            tail_size += len(encoded)
        else:
            heads.append(abi_encode(item))
    return b"".join(heads + tails)


#
# function selectors of the compiled contracts
#


def selector_of(signature: str) -> bytes:
    return keccak(signature.encode())[:4]


def function_signature(item: dict) -> str:
    """e.g. "transfer(address,uint256)", with tuples expanded"""

    def type_str(arg: dict) -> str:
        typ = arg["type"]
        if typ.startswith("tuple"):
            return (
                "(" + ",".join(type_str(c) for c in arg["components"]) + ")" + typ[5:]
            )
        return typ

    return item["name"] + "(" + ",".join(type_str(arg) for arg in item["inputs"]) + ")"


@dataclass(frozen=True)
class FunctionEntry:
    contract: str
    name: str
    sig: str
    inputs_json: str  # the ABI inputs, as json text
    payable: bool
    has_code: bool

    @property
    def params(self) -> AbiType:
        return params_type(json.loads(self.inputs_json))


class SelectorIndex:
    """Functions of the compiled contracts, by selector"""

    def __init__(self, contracts: Iterable[tuple[str, dict]] = ()):
        self.by_selector: dict[bytes, list[FunctionEntry]] = {}
        self.functions_by_contract: dict[str, list[FunctionEntry]] = {}
        for contract_name, contract_json in contracts:
            self.add_contract(contract_name, contract_json)

    def add_contract(self, contract_name: str, contract_json: dict) -> None:
        deployed = contract_json.get("deployedBytecode") or {}
        has_code = len(deployed.get("object", "0x") or "0x") > 2
        entries = self.functions_by_contract.setdefault(contract_name, [])
        for item in contract_json.get("abi") or []:
            if item.get("type") != "function":
                continue
            try:
                sig = function_signature(item)
            except (KeyError, TypeError):
                continue
            entry = FunctionEntry(
                contract=contract_name,
                name=item["name"],
                sig=sig,
                inputs_json=json.dumps(item.get("inputs", [])),
                payable=item.get("stateMutability") == "payable",
                has_code=has_code,
            )
            entries.append(entry)
            self.by_selector.setdefault(selector_of(sig), []).append(entry)

    def lookup(
        self, selector: bytes, preferred: Iterable[str] = ()
    ) -> list[FunctionEntry]:
        """Candidates for the selector: contracts of the test first, then deployable contracts"""
        preferred = set(preferred)
        candidates = self.by_selector.get(bytes(selector), [])
        return sorted(
            candidates,
            key=lambda e: (e.contract not in preferred, not e.has_code, e.contract),
        )

    def is_overloaded(self, contract_name: str, name: str) -> bool:
        functions = self.functions_by_contract.get(contract_name, [])
        return sum(1 for f in functions if f.name == name) > 1

    def function(self, contract_name: str, sig: str) -> FunctionEntry | None:
        for entry in self.functions_by_contract.get(contract_name, []):
            if entry.sig == sig:
                return entry
        return None


_index_cache: dict[int, tuple[object, SelectorIndex]] = {}
_index_lock = threading.Lock()


def selector_index(build_out_map: dict | None) -> SelectorIndex:
    """The SelectorIndex of a build output map ({filename: {contract: (json, type, natspec)}})"""
    if not build_out_map:
        return SelectorIndex()

    with _index_lock:
        cached = _index_cache.get(id(build_out_map))
        if cached and cached[0] is build_out_map:
            return cached[1]

        contracts = []
        for file_map in build_out_map.values():
            for contract_name, entry in file_map.items():
                contract_json = entry[0] if isinstance(entry, tuple | list) else entry
                if isinstance(contract_json, dict):
                    contracts.append((contract_name, contract_json))

        index = SelectorIndex(contracts)
        _index_cache[id(build_out_map)] = (build_out_map, index)
        return index


#
# rendering of values
#


def checksum_address(value: int) -> str:
    """EIP-55 checksummed address"""
    hex_addr = f"{value % 2**160:040x}"
    digest = keccak(hex_addr.encode()).hex()
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
        for i, c in enumerate(hex_addr)
    )


def uint_hint(value: int, bits: int = WORD_BITS) -> str | None:
    """A readable form of remarkable unsigned values"""
    max_value = 2**bits - 1
    if value == max_value and bits >= 8:
        return f"type(uint{bits}).max"
    if bits >= 64 and max_value - value < 2**16:
        return f"type(uint{bits}).max - {max_value - value}"
    if value >= 2**32 and value & (value - 1) == 0:
        return f"2**{value.bit_length() - 1}"
    if value >= 10**9:
        digits = str(value)
        stripped = digits.rstrip("0")
        zeros = len(digits) - len(stripped)
        if zeros >= 6 and len(stripped) <= 6:
            mantissa = (
                stripped if len(stripped) == 1 else f"{stripped[0]}.{stripped[1:]}"
            )
            return f"{mantissa}e{len(digits) - 1}"
    if value >= 2**64:
        return hex(value)
    return None


def int_hint(value: int, bits: int = WORD_BITS) -> str | None:
    if value == -(2 ** (bits - 1)):
        return f"type(int{bits}).min"
    if value == 2 ** (bits - 1) - 1:
        return f"type(int{bits}).max"
    if value >= 0:
        return uint_hint(value, bits) if value < 2 ** (bits - 1) - 1 else None
    hint = uint_hint(-value, bits)
    return f"-{hint}" if hint and not hint.startswith(("type", "0x")) else None


def with_hint(text: str, hint: str | None) -> str:
    return f"{text} ({hint})" if hint else text


def compact_hex(data: bytes) -> str:
    """Hex of data, with trailing zeros summarized and long values shortened"""
    if not data:
        return "0x"
    stripped = data.rstrip(b"\x00")
    zeros = len(data) - len(stripped)
    if not stripped and zeros > 32:
        return f"0x00…00 ({zeros} zero bytes)"
    if zeros < 32:
        stripped, zeros = data, 0

    if len(stripped) > MAX_HEX_BYTES:
        head = stripped[: MAX_HEX_BYTES - 32].hex()
        tail = stripped[-16:].hex()
        text = f"0x{head}…{tail}"
    else:
        text = "0x" + stripped.hex()

    if zeros:
        text += f" + {zeros} zero bytes"
    return text


def quoted_string(data: bytes) -> str | None:
    """The data as a quoted string, if it is printable UTF-8"""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():
        return None
    return json.dumps(text, ensure_ascii=False)


@dataclass(frozen=True)
class RenderContext:
    """What is known about the addresses and code of the counterexample"""

    # contract names of deployed addresses
    addr_names: dict = field(default_factory=dict)

    # state variables of the test contract holding addresses: address -> (label, type label)
    test_vars: dict = field(default_factory=dict)

    # contracts deployed in the counterexample, preferred when decoding calldata
    deployed: frozenset = frozenset()

    index: SelectorIndex = field(default_factory=SelectorIndex)

    # labels set by vm.label, in order (halmos#447)
    labels: tuple["AddressLabel", ...] = ()

    # the labels resolved with the values of the counterexample: address -> label
    label_values: dict = field(default_factory=dict)

    def with_model(self, model: Model) -> "RenderContext":
        """the context for rendering a counterexample, with its labels resolved"""
        if not self.labels:
            return self
        return replace(self, label_values=resolve_labels(self.labels, model))

    def address_hint(self, value: int) -> str | None:
        hints = []
        if label := self.label_values.get(value):
            hints.append(label)
        if var := self.test_vars.get(value):
            hints.append(var[0])
        if name := self.addr_names.get(value):
            hints.append(name)
        return ", ".join(dict.fromkeys(hints)) or None

    def selector_hint(self, selector: bytes) -> str | None:
        candidates = self.index.lookup(selector, self.deployed)
        if candidates:
            first = candidates[0]
            return f"{first.contract}.{first.sig}"
        if selector == EMPTY_SELECTOR:
            return "no selector: empty calldata, i.e. receive() or fallback(), e.g. a plain ether transfer"
        return None

    def render_base(self, t: AbiType, word: int) -> str:
        """A static value, from its ABI encoded word"""
        if not is_clean_word(t, word):
            return f"0x{word:064x} (not a valid {t.abi})"

        abi = t.abi
        if t.internal.startswith("enum "):
            return f"{word} ({t.internal})"
        if abi.startswith("uint"):
            return with_hint(str(word), uint_hint(word, t.bits))
        if abi.startswith("int"):
            value = signed(word)
            return with_hint(str(value), int_hint(value, t.bits))
        if abi == "address":
            return with_hint(checksum_address(word), self.address_hint(word))
        if abi == "bool":
            return "true" if word else "false"
        if abi.startswith("bytes"):
            size = t.bits // 8
            data = (word >> (WORD_BITS - t.bits)).to_bytes(size, "big")
            text = "0x" + data.hex()
            if size == 4:
                return with_hint(text, self.selector_hint(data))
            return text
        return hex(word)

    def render_bytes(self, data: bytes, depth: int = 0) -> str:
        if not data:
            return "0x (empty)"
        text = compact_hex(data)
        if not text.endswith("zero bytes)"):
            text += f" ({len(data)} bytes)"
        if call := self.decode_call(data, depth):
            return f"{call}\n{text}"
        return text

    def render_string(self, data: bytes) -> str:
        if (quoted := quoted_string(data)) is not None:
            return quoted
        text = compact_hex(data)
        if not text.endswith("zero bytes)"):
            text += f" ({len(data)} bytes)"
        return f"{text}, not printable as a string"

    def decode_call(self, data: bytes, depth: int = 0) -> str | None:
        """Renders calldata as a function call, if its selector is known"""
        if len(data) < 4 or depth >= MAX_DECODE_DEPTH:
            return None

        candidates = self.index.lookup(data[:4], self.deployed)
        if not candidates:
            return None

        entry = candidates[0]
        try:
            params = entry.params
            decoded = abi_decode(params, data, 4)
        except (AbiDecodeError, UnsupportedType, ValueError):
            return f"{entry.contract}.{entry.sig} (arguments not ABI encoded)"

        args = ", ".join(
            f"{name or f'arg{i}'}: {self.inline(item, depth + 1)}"
            for i, (name, item) in enumerate(
                zip(params.names, decoded.items, strict=True)
            )
        )
        text = f"{entry.contract}.{entry.name}({args})"

        encoded = abi_encode(decoded)
        if data[4 : 4 + len(encoded)] != encoded:
            text += " (non-standard encoding)"
        elif trailing := len(data) - 4 - len(encoded):
            zeros = data[4 + len(encoded) :].count(0) == trailing
            text += f" + {trailing} trailing {'zero ' if zeros else ''}bytes"
        return text

    def inline(self, v: Val, depth: int = 0) -> str:
        """A value on a single line"""
        t = v.t
        match t.kind:
            case "base":
                return self.render_base(t, v.word)
            case "string":
                quoted = quoted_string(v.data)
                return quoted if quoted is not None else compact_hex(v.data)
            case "bytes":
                if call := self.decode_call(v.data, depth):
                    return call
                return compact_hex(v.data)
            case "array" | "fixed":
                items = [
                    self.inline(item, depth) for item in v.items[:MAX_INLINE_ITEMS]
                ]
                if len(v.items) > MAX_INLINE_ITEMS:
                    items.append(f"… {len(v.items) - MAX_INLINE_ITEMS} more")
                return "[" + ", ".join(items) + "]"
            case _:
                fields = [
                    f"{name or i}: {self.inline(item, depth)}"
                    for i, (name, item) in enumerate(zip(t.names, v.items, strict=True))
                ]
                return "(" + ", ".join(fields) + ")"

    def leaves(self, path: str, v: Val) -> list[tuple[str, str]]:
        """(path, rendered value) for each leaf of a value"""
        t = v.t
        free = " (any value)" if v.free else ""
        match t.kind:
            case "base":
                return [(path, self.render_base(t, v.word) + free)]
            case "bytes":
                return [(path, self.render_bytes(v.data) + free)]
            case "string":
                return [(path, self.render_string(v.data) + free)]
            case "array":
                result = [(f"{path}.length", f"{len(v.items)}{free}")]
                for i, item in enumerate(v.items):
                    result.extend(self.leaves(f"{path}[{i}]", item))
                return result
            case "fixed":
                result = []
                for i, item in enumerate(v.items):
                    result.extend(self.leaves(f"{path}[{i}]", item))
                return result
            case _:
                result = []
                for i, (name, item) in enumerate(zip(t.names, v.items, strict=True)):
                    result.extend(self.leaves(f"{path}.{name or i}", item))
                return result


def format_leaves(leaves: list[tuple[str, str]], indent: str) -> list[str]:
    lines = []
    for path, value in leaves:
        first, *rest = value.split("\n")
        lines.append(f"{indent}{path} = {first}")
        pad = indent + " " * (len(path) + 3)
        lines.extend(f"{pad}{line}" for line in rest)
    return lines


#
# symbols outside of ABI encoded calls (svm.create* cheatcodes, transaction context)
#


def svm_value(var, typ: str) -> tuple[AbiType, int, bytes] | None:
    """The ABI type and value of a symbol created by an svm.create* cheatcode"""
    size = var.size_bits
    value = var.value
    try:
        if typ in ("bytes", "string"):
            return AbiType(typ, typ), 0, value.to_bytes(size // 8, "big")
        t = _parse_abi_type(typ, None, "")
    except (UnsupportedType, ValueError, OverflowError):
        return None

    abi = t.abi
    if abi.startswith("int"):
        word = signed(value, size) % WORD_MODULUS
    elif abi.startswith("bytes"):
        word = value << (WORD_BITS - size) if size <= WORD_BITS else value
    else:
        word = value
    return t, word, b""


def svm_cheatcode(label: str, typ: str, size_bits: int) -> str:
    """the cheatcode that creates a symbol of this type, for the reproduction comments"""
    quoted = json.dumps(label)
    match typ:
        case (
            "uint256"
            | "int256"
            | "address"
            | "bool"
            | "bytes32"
            | "bytes4"
            | "bytes8"
        ):
            name = {"uint256": "Uint256", "int256": "Int256", "address": "Address"}.get(
                typ, typ.capitalize()
            )
            return f"svm.create{name}({quoted})"
        case "bytes" | "string":
            return f"svm.create{typ.capitalize()}({size_bits // 8}, {quoted})"
    if typ.startswith("uint"):
        return f"svm.createUint({typ[4:]}, {quoted})"
    if typ.startswith("int"):
        return f"svm.createInt({typ[3:]}, {quoted})"
    return f"svm.create…({quoted})"


#
# layout of a counterexample, collected on the main thread
#


@dataclass(frozen=True)
class Ref:
    """A value of the execution: a constant, or a symbol of the model"""

    const: int | None = None
    symbol: str | None = None

    def resolve(self, model: Model, used: set | None = None) -> int | None:
        if self.const is not None:
            return self.const
        if self.symbol is None:
            return None
        if used is not None:
            used.add(self.symbol)
        var = model.get(self.symbol)
        # absent from the model: any value works
        return var.value if var is not None else 0


@dataclass(frozen=True)
class CallLayout:
    contract: str | None
    fun_name: str | None
    fun_sig: str | None

    # ABI inputs as json text, so that the layout is plain data
    inputs_json: str
    payable: bool
    target: int | None
    sender: Ref
    origin: Ref
    value: Ref

    # p_ symbols of the calldata: (path, type) -> names
    symbols: dict

    @property
    def params(self) -> AbiType:
        return params_type(json.loads(self.inputs_json))


@dataclass(frozen=True)
class CexLayout:
    test_contract: str
    test_source: str | None
    fun_name: str
    fun_sig: str
    is_invariant: bool
    is_probe: bool

    # the call to the test function (None for probes)
    test_call: CallLayout | None

    # the transactions of an invariant test, in order
    sequence: tuple[CallLayout, ...]

    render_ctx: RenderContext

    # whether the test function is overloaded in the test contract
    test_overloaded: bool = False

    # calls made by the test with calldata built from symbols that are not arguments of the
    # test, e.g. by svm.createCalldata()
    trace_calls: tuple["TraceCall", ...] = ()


@dataclass(frozen=True)
class Segment:
    """A part of calldata: constant bytes, or (some bits of) a symbol"""

    const: int | None = None
    symbol: str | None = None

    # bit size of the segment
    size: int = 0

    # bits of the symbol (Extract)
    hi: int | None = None
    lo: int | None = None

    def value(self, model: Model) -> int:
        if self.const is not None:
            return self.const
        var = model.get(self.symbol)
        value = var.value if var is not None else 0
        if self.hi is not None:
            value = (value >> self.lo) % 2 ** (self.hi - self.lo + 1)
        return value


@dataclass(frozen=True)
class AddressLabel:
    """A label set by vm.label, on an address made of constants and (bits of) symbols"""

    segments: tuple[Segment, ...]
    label: str

    def address(self, model: Model) -> int:
        result = 0
        for segment in self.segments:
            result = (result << segment.size) | segment.value(model)
        return result % 2**160


def resolve_labels(labels: tuple[AddressLabel, ...], model: Model) -> dict[int, str]:
    """address -> label, with the values of the model; the latest label wins"""
    result = {}
    for label in labels:
        result[label.address(model)] = label.label
    return result


def collect_labels(ex) -> tuple[AddressLabel, ...]:
    """
    The labels of the given execution, as plain data: labels on addresses that are not
    made of constants and symbols (e.g. a hash) are dropped.
    """
    from z3 import simplify

    result = []
    for addr, label in getattr(ex, "labels", ()):
        try:
            segments = segments_of(simplify(addr))
        except Exception:
            segments = None
        if segments:
            result.append(AddressLabel(segments=tuple(segments), label=label))
    return tuple(result)


def collect_addr_names(ex, test_contract: str) -> dict[int, str]:
    """contract names of the addresses where code is deployed"""
    from dolmos.sevm import FOUNDRY_TEST

    addr_names = {}
    for addr, code in ex.code.items():
        value = concrete_int(addr)
        name = getattr(code, "contract_name", None)
        if value is not None and name:
            addr_names[value] = name
    addr_names[concrete_int(FOUNDRY_TEST)] = test_contract
    return addr_names


def address_hints(
    addr_names: dict[int, str], labels: tuple[AddressLabel, ...], model: Model
) -> dict[int, str]:
    """address -> what is known about it: its label and the contract deployed there"""
    result = {}
    label_values = resolve_labels(labels, model)
    for value in set(addr_names) | set(label_values):
        hints = [label_values.get(value), addr_names.get(value)]
        result[value] = ", ".join(dict.fromkeys(h for h in hints if h))
    return result


@dataclass(frozen=True)
class TraceCall:
    target: int | None
    value: Ref
    segments: tuple[Segment, ...]

    @property
    def symbols(self) -> set[str]:
        return {s.symbol for s in self.segments if s.symbol is not None}

    def calldata(self, model: Model) -> bytes:
        result, bits = 0, 0
        for segment in self.segments:
            result = (result << segment.size) | segment.value(model)
            bits += segment.size
        return result.to_bytes(bits // 8, "big")


#
# rendering of a counterexample
#


@dataclass(frozen=True)
class RenderedCex:
    # the values of the counterexample, used to detect duplicates
    body: list[str]

    # body of a forge test replaying the counterexample (see repro_function)
    repro: list[str]


def render_counterexample(layout: CexLayout, model: Model) -> RenderedCex:
    ctx = layout.render_ctx.with_model(model)
    body: list[str] = []
    used: set[str] = set()
    indent = " " * 4

    # 1. arguments of the test
    args_val = None
    if layout.test_call is not None:
        call = layout.test_call
        reader = ModelReader(model, call.symbols)
        try:
            params = call.params
            args_val = reader.read(params, "")
            for i, (name, item) in enumerate(
                zip(params.names, args_val.items, strict=True)
            ):
                body.extend(format_leaves(ctx.leaves(name or f"arg{i}", item), indent))
        except (UnsupportedType, ValueError, KeyError) as e:
            body.append(f"{indent}(arguments not decoded: {e})")
            args_val = None
        used |= reader.used

    # calls made with calldata built from other symbols, e.g. by svm.createCalldata()
    trace_lines = []
    for trace_call in layout.trace_calls:
        data = trace_call.calldata(model)
        used |= trace_call.symbols
        target = render_target(ctx, trace_call.target, None)
        decoded = ctx.decode_call(data) or compact_hex(data)
        value = trace_call.value.resolve(model, used)
        value_str = f" {{value: {value}}}" if value else ""
        trace_lines.append((target, f"{decoded}{value_str}", data))
    if trace_lines:
        body.append(f"{indent}Calls made with symbolic calldata:")
        body.extend(
            f"{indent * 2}{target} ← {decoded}" for target, decoded, _ in trace_lines
        )

    # 2. call sequence of invariant testing
    timestamps = {}
    for name in model:
        if match := timestamp_symbol_pattern.match(name):
            timestamps[int(match["depth"])] = model[name].value
            used.add(name)

    seq_vals = []
    if layout.sequence:
        body.append(f"{indent}Sequence:")
        for i, call in enumerate(layout.sequence, start=1):
            reader = ModelReader(model, call.symbols)
            try:
                val = reader.read(call.params, "")
            except (UnsupportedType, ValueError, KeyError):
                val = None
            used |= reader.used
            seq_vals.append(val)

            sender = call.sender.resolve(model, used)
            origin = call.origin.resolve(model, used)
            value = call.value.resolve(model, used)

            body.append(f"{indent * 2}[{i}] {render_call(ctx, call, val)}")
            context = [f"msg.sender: {render_address(ctx, sender)}"]
            if value:
                context.append(f"msg.value: {with_hint(str(value), uint_hint(value))}")
            if origin is not None and origin != sender:
                context.append(f"tx.origin: {render_address(ctx, origin)}")
            if i > 1 and (ts := timestamps.get(i - 1)) is not None:
                context.append(f"block.timestamp: {ts}")
            body.append(f"{indent * 2}    {', '.join(context)}")

        ts = timestamps.get(len(layout.sequence))
        if ts is not None and not layout.is_probe:
            body.append(
                f"{indent * 2}then {layout.fun_name}() at block.timestamp: {ts}"
            )

    # 3. other symbols: svm.create* cheatcodes, calldata created by svm.createCalldata, ...
    svm_symbols = []
    other_lines = []
    rest = sorted(name for name in model if name not in used)
    labels: dict[str, int] = {}
    for name in rest:
        if match := svm_symbol_pattern.match(name):
            labels[match["label"]] = labels.get(match["label"], 0) + 1

    # sorted names: the data of bytes/string comes before its length, and the elements of
    # an array before its length, so that lengths are consumed with their data
    p_reader = ModelReader(model, index_symbols(rest))
    for name in rest:
        if name in p_reader.used:
            continue
        var = model[name]
        if match := tx_symbol_pattern.match(name):
            what = {
                "msg_sender": "msg.sender",
                "msg_value": "msg.value",
                "tx_origin": "tx.origin",
            }
            rendered = (
                str(var.value)
                if match["kind"] == "msg_value"
                else render_address(ctx, var.value)
            )
            other_lines.append(
                (f"{what[match['kind']]} (call to {match['addr']})", rendered)
            )
        elif match := svm_symbol_pattern.match(name):
            label, typ = match["label"], match["typ"]
            shown = label if labels[label] == 1 else f"{label}#{int(match['n'])}"
            decoded = svm_value(var, typ)
            if decoded is None:
                rendered = hex(var.value)
            else:
                t, word, data = decoded
                rendered = (
                    ctx.render_bytes(data)
                    if t.kind == "bytes"
                    else ctx.render_string(data)
                    if t.kind == "string"
                    else ctx.render_base(t, word)
                )
            other_lines.append((f"{shown} ({typ})", rendered))
            svm_symbols.append((svm_cheatcode(label, typ, var.size_bits), rendered))
        elif match := p_symbol_pattern.match(name):
            path, typ = match["path"], match["typ"]
            if typ == "length":
                p_reader.take(path, typ)
                other_lines.append((f"{path or 'arg'}.length", str(var.value)))
                continue
            try:
                val = p_reader.read(_parse_abi_type(typ, None, ""), path)
                other_lines.extend(ctx.leaves(path or "arg", val))
            except (UnsupportedType, ValueError):
                p_reader.used.add(name)
                other_lines.append((path or "arg", hex(var.value)))
        else:
            other_lines.append((name, hex(var.value)))

    if other_lines:
        body.append(f"{indent}Other symbols:")
        body.extend(format_leaves(other_lines, indent * 2))

    if not body:
        body.append(f"{indent}∅")

    for target, decoded, data in trace_lines:
        svm_symbols.append(
            (f"calldata sent to {target}", f"{decoded}, i.e. {bytes_literal(data)}")
        )

    repro = render_reproduction(
        layout, args_val, seq_vals, model, timestamps, svm_symbols
    )
    return RenderedCex(body=body, repro=repro)


def render_address(ctx: RenderContext, value: int | None) -> str:
    if value is None:
        return "?"
    return with_hint(checksum_address(value), ctx.address_hint(value % 2**160))


def render_target(ctx: RenderContext, target: int | None, contract: str | None) -> str:
    """e.g. Vault(vault), with the state variable of the test holding the target if any"""
    if target is None:
        return "?"
    contract = contract or ctx.addr_names.get(target)
    if var := ctx.test_vars.get(target):
        return f"{contract}({var[0]})" if contract else var[0]
    return f"{contract or 'address'}@{checksum_address(target)}"


def render_call(ctx: RenderContext, call: CallLayout, val: Val | None) -> str:
    target = render_target(ctx, call.target, call.contract)

    if val is None:
        return f"{target}.{call.fun_sig}"

    params = call.params
    args = ", ".join(
        f"{name or f'arg{i}'}: {ctx.inline(item)}"
        for i, (name, item) in enumerate(zip(params.names, val.items, strict=True))
    )
    return f"{target}.{call.fun_name}({args})"


#
# reproduction
#

SOLIDITY_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def solidity_type(t: AbiType) -> str | None:
    """The solidity type for a declaration, from the internalType of the ABI"""
    internal = t.internal
    if not internal:
        if t.kind == "tuple":
            return None
        if t.kind in ("array", "fixed"):
            elem = solidity_type(t.elem)
            if elem is None:
                return None
            return f"{elem}[]" if t.kind == "array" else f"{elem}[{t.length}]"
        return t.abi
    return re.sub(r"^(struct|enum|contract) ", "", internal)


def bytes_literal(data: bytes) -> str:
    if not data:
        return '""'
    stripped = data.rstrip(b"\x00")
    zeros = len(data) - len(stripped)
    if zeros >= 64:
        if not stripped:
            return f"new bytes({zeros})"
        return f'abi.encodePacked(hex"{stripped.hex()}", new bytes({zeros}))'
    return f'hex"{data.hex()}"'


def string_literal(data: bytes) -> str:
    try:
        text = data.decode("ascii")
        if text.isprintable() and '"' not in text and "\\" not in text:
            return json.dumps(text)
    except UnicodeDecodeError:
        pass
    return f"string({bytes_literal(data)})"


def base_literal(t: AbiType, word: int) -> str | None:
    """A solidity expression for a static value, None if it cannot be expressed"""
    if not is_clean_word(t, word):
        return None

    abi, internal = t.abi, t.internal
    if abi.startswith("uint"):
        literal = str(word) if word < 2**64 else hex(word)
    elif abi.startswith("int"):
        value = signed(word)
        literal = (
            f"type(int{t.bits}).min" if value == -(2 ** (t.bits - 1)) else str(value)
        )
    elif abi == "address":
        literal = "address(0)" if word == 0 else checksum_address(word)
    elif abi == "bool":
        literal = "true" if word else "false"
    elif abi.startswith("bytes"):
        size = t.bits // 8
        literal = f"bytes{size}(0x{(word >> (WORD_BITS - t.bits)):0{2 * size}x})"
    else:
        return None

    if not internal or internal == abi:
        return literal
    if internal.startswith("contract "):
        return f"{internal[9:]}(payable({literal}))"
    if internal.startswith("enum "):
        return f"{internal[5:]}({literal})"
    if internal == "address payable":
        return f"payable({literal})"
    if SOLIDITY_IDENTIFIER.match(internal.replace(".", "_")):
        # user defined value type
        return f"{internal}.wrap({literal})"
    return literal


class CodeGen:
    """Solidity statements and expressions for values"""

    def __init__(self):
        self.lines: list[str] = []
        self.ok = True

    def expr(self, v: Val, local: str) -> str:
        """an expression for v, possibly declaring a local variable for reference types"""
        t = v.t
        match t.kind:
            case "base":
                literal = base_literal(t, v.word)
                if literal is None:
                    self.ok = False
                    return "0"
                return literal
            case "bytes":
                return bytes_literal(v.data)
            case "string":
                return string_literal(v.data)

        decl = solidity_type(t)
        if decl is None:
            self.ok = False
            return local

        if t.kind == "array":
            self.lines.append(f"{decl} memory {local} = new {decl}({len(v.items)});")
        else:
            self.lines.append(f"{decl} memory {local};")
        self.assign_items(local, v)
        return local

    def assign_items(self, lhs: str, v: Val) -> None:
        t = v.t
        if t.kind in ("array", "fixed"):
            for i, item in enumerate(v.items):
                self.assign(f"{lhs}[{i}]", item)
        else:
            for name, item in zip(t.names, v.items, strict=True):
                if not name:
                    self.ok = False
                    return
                self.assign(f"{lhs}.{name}", item)

    def assign(self, lhs: str, v: Val) -> None:
        t = v.t
        match t.kind:
            case "base":
                if v.word == 0:
                    return  # memory is zero-initialized
                literal = base_literal(t, v.word)
                if literal is None:
                    self.ok = False
                    return
                self.lines.append(f"{lhs} = {literal};")
            case "bytes" | "string":
                if v.data:
                    literal = (
                        bytes_literal(v.data)
                        if t.kind == "bytes"
                        else string_literal(v.data)
                    )
                    self.lines.append(f"{lhs} = {literal};")
            case "array":
                if v.items:
                    decl = solidity_type(t)
                    if decl is None:
                        self.ok = False
                        return
                    self.lines.append(f"{lhs} = new {decl}({len(v.items)});")
                    self.assign_items(lhs, v)
            case _:
                self.assign_items(lhs, v)

    def args(self, params: AbiType, val: Val, prefix: str = "") -> list[str]:
        result = []
        for i, (name, item) in enumerate(zip(params.names, val.items, strict=True)):
            local = name if name and SOLIDITY_IDENTIFIER.match(name) else f"arg{i}"
            result.append(self.expr(item, f"{prefix}{local}"))
        return result


def calldata_of(sig: str, val: Val) -> bytes:
    return selector_of(sig) + abi_encode(val)


def render_reproduction(
    layout: CexLayout,
    args_val: Val | None,
    seq_vals: list,
    model: Model,
    timestamps: dict,
    svm_symbols: list,
) -> list[str]:
    """Body of a forge test replaying the counterexample (without the function header)"""
    ctx = layout.render_ctx.with_model(model)
    lines: list[str] = []
    notes: list[str] = []

    if svm_symbols:
        lines.append(
            "// values chosen for the symbols created by the test (replace the svm cheatcodes):"
        )
        lines.extend(
            f"//   {cheatcode} = {value.splitlines()[0]}"
            for cheatcode, value in svm_symbols
        )

    for i, (call, val) in enumerate(
        zip(layout.sequence, seq_vals, strict=True), start=1
    ):
        sender = call.sender.resolve(model)
        origin = call.origin.resolve(model)
        value = call.value.resolve(model) or 0

        if i > 1 and (ts := timestamps.get(i - 1)) is not None:
            lines.append(f"vm.warp({ts});")
        if value:
            lines.append(f"vm.deal({address_literal(sender)}, {value});")
        if origin is not None and origin != sender:
            lines.append(
                f"vm.prank({address_literal(sender)}, {address_literal(origin)});"
            )
        else:
            lines.append(f"vm.prank({address_literal(sender)});")

        target_var = ctx.test_vars.get(call.target) if call.target is not None else None
        if target_var:
            target_expr = f"address({target_var[0]})"
        else:
            target_expr = address_literal(call.target or 0)
            notes.append(
                f"call {i}: {target_expr} is the address of {call.contract or 'the target'} in dolmos; "
                "replace it with the deployed instance"
            )

        value_opt = f"{{value: {value}}}" if value else ""
        typed = None
        if (
            val is not None
            and target_var
            and target_var[1] == f"contract {call.contract}"
            and call.fun_name
            and not ctx.index.is_overloaded(call.contract, call.fun_name)
            and (call.payable or not value)
        ):
            gen = CodeGen()
            args = gen.args(call.params, val, prefix=f"c{i}_")
            if gen.ok:
                lines.extend(gen.lines)
                typed = (
                    f"{target_var[0]}.{call.fun_name}{value_opt}({', '.join(args)});"
                )

        if typed:
            lines.append(typed)
        elif val is not None:
            data = calldata_of(call.fun_sig, val)
            lines.append(
                f"(bool ok{i},) = {target_expr}.call{value_opt}({bytes_literal(data)});"
            )
            lines.append(f'require(ok{i}, "call {i} reverted");')
        else:
            notes.append(f"call {i} ({call.fun_sig}) could not be decoded")

    if layout.sequence and (ts := timestamps.get(len(layout.sequence))) is not None:
        lines.append(f"vm.warp({ts});")

    if layout.test_call is not None:
        call = layout.test_call
        if args_val is None:
            notes.append(f"the arguments of {layout.fun_sig} could not be decoded")
        else:
            gen = CodeGen()
            args = gen.args(call.params, args_val)
            if gen.ok and not layout.test_overloaded:
                lines.extend(gen.lines)
                lines.append(f"this.{layout.fun_name}({', '.join(args)});")
            else:
                data = calldata_of(layout.fun_sig, args_val)
                lines.append(f"(bool ok,) = address(this).call({bytes_literal(data)});")
                lines.append(f'require(ok, "{layout.fun_name} failed");')

    return [f"// note: {note}" for note in notes] + lines


def address_literal(value: int | None) -> str:
    if not value:
        return "address(0)"
    return checksum_address(value)


def repro_function(layout: CexLayout, rendered: RenderedCex, number: int) -> list[str]:
    name = f"test_pcex_{layout.fun_name}_{number}"
    if layout.test_overloaded:
        name = (
            f"test_pcex_{layout.fun_name}_{selector_of(layout.fun_sig).hex()}_{number}"
        )
    where = layout.test_contract
    if layout.test_source:
        where += f" ({layout.test_source})"
    return [
        f"Reproduce: add to {where}, then `forge test --mt {name} -vvvv` (the test fails if the counterexample is real)",
        f"    function {name}() public {{",
        *(f"        {line}" for line in rendered.repro),
        "    }",
    ]


#
# duplicates
#


@dataclass
class PcexState:
    """Per-function state of pretty counterexamples, shared by the solver threads"""

    lock: threading.Lock = field(default_factory=threading.Lock)

    # fingerprint -> whether a valid counterexample with these values was shown
    seen: dict = field(default_factory=dict)

    # number of duplicates that were not shown
    hidden: int = 0

    # number of counterexamples shown
    shown: int = 0

    def admit(self, fingerprint: str, is_valid: bool) -> bool:
        """Records a counterexample; returns whether it should be shown (call with the lock held)"""
        shown_valid = self.seen.get(fingerprint)
        if shown_valid is None or (is_valid and not shown_valid):
            self.seen[fingerprint] = is_valid or bool(shown_valid)
            self.shown += 1
            return True
        self.hidden += 1
        return False


#
# collection of the layout, on the main thread
#


def collect_symbol_names(expr) -> list[str]:
    """p_ and dolmos_ symbols of a z3 expression, in order of first occurrence"""
    from z3 import Z3_OP_UNINTERPRETED, is_app

    names: list[str] = []
    seen_names: set[str] = set()
    visited: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        if not is_app(e):
            continue
        eid = e.get_id()
        if eid in visited:
            continue
        visited.add(eid)
        if e.num_args() == 0:
            decl = e.decl()
            if decl.kind() == Z3_OP_UNINTERPRETED:
                name = decl.name()
                if name.startswith(("p_", "dolmos_")) and name not in seen_names:
                    seen_names.add(name)
                    names.append(name)
            continue
        stack.extend(reversed(e.children()))
    return names


def ref_of(x) -> Ref:
    """A Ref for a value of the execution (int, bytes, BV, ByteVec or z3 term)"""
    from z3 import Z3_OP_UNINTERPRETED, Z3_OP_ZERO_EXT, is_app, is_bv_value

    if isinstance(x, int):
        return Ref(const=x)
    if hasattr(x, "as_z3"):
        x = x.as_z3()
    if hasattr(x, "unwrap"):
        x = x.unwrap()
    if isinstance(x, bytes):
        return Ref(const=int.from_bytes(x, "big"))
    if is_bv_value(x):
        return Ref(const=x.as_long())
    while is_app(x) and x.decl().kind() == Z3_OP_ZERO_EXT:
        x = x.arg(0)
    if is_app(x) and x.num_args() == 0 and x.decl().kind() == Z3_OP_UNINTERPRETED:
        return Ref(symbol=x.decl().name())
    return Ref()


def concrete_int(x) -> int | None:
    ref = ref_of(x)
    return ref.const


def call_layout(
    message, abi_item: dict | None, contract_name: str | None
) -> CallLayout:
    fun_info = message.fun_info
    data = message.data
    try:
        raw = data.unwrap() if hasattr(data, "unwrap") else data
        names = [] if isinstance(raw, bytes) else collect_symbol_names(raw)
    except Exception:
        names = []

    return CallLayout(
        contract=contract_name or (fun_info.contract_name if fun_info else None),
        fun_name=fun_info.name if fun_info else None,
        fun_sig=fun_info.sig if fun_info else None,
        inputs_json=json.dumps((abi_item or {}).get("inputs", [])),
        payable=(abi_item or {}).get("stateMutability") == "payable",
        target=concrete_int(message.target),
        sender=ref_of(message.caller),
        origin=ref_of(message.origin),
        value=ref_of(message.value),
        symbols=index_symbols(names),
    )


MAX_TRACE_CALLS = 8

# cheatcode addresses: hevm, svm, console
CHEATCODE_ADDRESSES = frozenset(
    {
        0x7109709ECFA91A80626FF3989D68F67F5B1DD12D,
        0xF3993A62377BCD56AE39D773740A5390411E8BC9,
        0x000000000000000000636F6E736F6C652E6C6F67,
    }
)


def segments_of(expr) -> list[Segment] | None:
    """The calldata as constant bytes and (bits of) symbols, None if it is more complex"""
    from z3 import (
        Z3_OP_CONCAT,
        Z3_OP_EXTRACT,
        Z3_OP_UNINTERPRETED,
        Z3_OP_ZERO_EXT,
        is_app,
        is_bv_value,
    )

    if isinstance(expr, bytes):
        return [Segment(const=int.from_bytes(expr, "big"), size=8 * len(expr))]

    if is_bv_value(expr):
        return [Segment(const=expr.as_long(), size=expr.size())]

    if not is_app(expr):
        return None

    kind = expr.decl().kind()
    if kind == Z3_OP_CONCAT:
        result = []
        for child in expr.children():
            segments = segments_of(child)
            if segments is None:
                return None
            result.extend(segments)
        return result

    if kind == Z3_OP_UNINTERPRETED and expr.num_args() == 0:
        return [Segment(symbol=expr.decl().name(), size=expr.size())]

    if kind == Z3_OP_EXTRACT:
        hi, lo = expr.params()
        child = expr.arg(0)
        if child.decl().kind() == Z3_OP_UNINTERPRETED and child.num_args() == 0:
            return [Segment(symbol=child.decl().name(), size=hi - lo + 1, hi=hi, lo=lo)]
        return None

    if kind == Z3_OP_ZERO_EXT:
        (bits,) = expr.params()
        inner = segments_of(expr.arg(0))
        if inner is None:
            return None
        return [Segment(const=0, size=bits), *inner]

    return None


def collect_trace_calls(context, exclude: set[str]) -> tuple[TraceCall, ...]:
    """
    Calls of the trace whose calldata depends on symbols that are not in `exclude` (the
    arguments of the test), e.g. calldata created by svm.createCalldata()
    """
    from dolmos.sevm import CallContext

    result = []
    stack = [context]
    while stack and len(result) < MAX_TRACE_CALLS:
        current = stack.pop()
        subcalls = [e for e in current.trace if isinstance(e, CallContext)]
        stack.extend(reversed(subcalls))
        if current is context:
            continue

        message = current.message
        if message.is_create():
            continue
        target = concrete_int(message.target)
        if target in CHEATCODE_ADDRESSES:
            continue

        try:
            data = message.data
            raw = data.unwrap() if hasattr(data, "unwrap") else data
            if isinstance(raw, bytes):
                continue
            segments = segments_of(raw)
        except Exception:
            continue

        if not segments:
            continue
        symbols = {s.symbol for s in segments if s.symbol is not None}
        if not symbols or symbols <= exclude:
            continue
        if sum(s.size for s in segments) % 8:
            continue

        result.append(TraceCall(target, ref_of(message.value), tuple(segments)))

    return tuple(result)


def collect_test_vars(contract_json: dict, storage_data) -> dict:
    """address -> (label, type label) of the address and contract state variables of the test"""
    result = {}
    if storage_data is None:
        return result

    layout = contract_json.get("storageLayout") or {}
    types = layout.get("types") or {}
    for var in layout.get("storage") or []:
        type_label = (types.get(var.get("type")) or {}).get("label", "")
        if not (
            type_label.startswith("contract ")
            or type_label in ("address", "address payable")
        ):
            continue
        try:
            slot, offset = int(var["slot"]), int(var["offset"])
            key = (slot, 0, 0)
            if key not in storage_data:
                continue
            word = concrete_int(storage_data[key])
        except Exception:
            continue
        if word is None:
            continue
        address = (word >> (8 * offset)) % 2**160
        if address and address not in result:
            result[address] = (var["label"], type_label)
    return result


def collect_layout(fn_ctx, ex, is_invariant: bool, is_probe: bool) -> CexLayout:
    """
    Collects what is needed to render a counterexample of the given execution.

    Runs on the main thread, when a potential assertion violation is found. The result is
    plain Python data, as it is used later by the solver callbacks.
    """
    from dolmos.build import get_source_path
    from dolmos.calldata import get_abi
    from dolmos.mapper import BuildOut
    from dolmos.sevm import FOUNDRY_TEST

    contract_ctx = fn_ctx.contract_ctx
    args = fn_ctx.args
    index = selector_index(contract_ctx.build_out_map)

    # contract names of the deployed addresses
    addr_names = collect_addr_names(ex, contract_ctx.name)

    # state variables of the test contract that hold the deployed contracts
    test_vars = {}
    if args.storage_layout == "solidity":
        state = fn_ctx.setup_ex or ex
        try:
            storage = state.storage.get(FOUNDRY_TEST)
            test_vars = collect_test_vars(contract_ctx.contract_json, storage)
        except Exception:
            test_vars = {}

    def abi_item_of(addr, fun_info) -> dict | None:
        if fun_info is None or not fun_info.contract_name or not fun_info.sig:
            return None
        try:
            code = ex.code.get(addr)
            filename = getattr(code, "filename", None)
            contract_json = BuildOut().get_by_name(fun_info.contract_name, filename)
            return get_abi(contract_json).get(fun_info.sig)
        except Exception:
            return None

    sequence = []
    if is_invariant:
        for call_ctx in ex.call_sequence:
            message = call_ctx.message
            item = abi_item_of(message.target, message.fun_info)
            sequence.append(call_layout(message, item, None))

    message = ex.context.message
    if is_probe:
        # the failing call is the last call of the sequence
        fun_info = message.fun_info
        fun_name = fun_info.name if fun_info and fun_info.name else "probe"
        fun_sig = fun_info.sig if fun_info and fun_info.sig else fun_name
        test_call = None
        test_overloaded = False
    else:
        fun_info = fn_ctx.info
        fun_name, fun_sig = fun_info.name, fun_info.sig
        test_call = call_layout(
            message, contract_ctx.abi.get(fun_sig), contract_ctx.name
        )
        test_overloaded = index.is_overloaded(contract_ctx.name, fun_name)

    trace_calls = ()
    if test_call is not None:
        params = {name for names in test_call.symbols.values() for name in names}
        try:
            trace_calls = collect_trace_calls(ex.context, params)
        except Exception:
            trace_calls = ()

    try:
        test_source = get_source_path(contract_ctx.contract_json)
    except Exception:
        test_source = None

    return CexLayout(
        test_contract=contract_ctx.name,
        test_source=test_source,
        fun_name=fun_name,
        fun_sig=fun_sig,
        is_invariant=is_invariant,
        is_probe=is_probe,
        test_call=test_call,
        sequence=tuple(sequence),
        render_ctx=RenderContext(
            addr_names=addr_names,
            test_vars=test_vars,
            deployed=frozenset(addr_names.values()),
            index=index,
            labels=collect_labels(ex),
        ),
        test_overloaded=test_overloaded,
        trace_calls=trace_calls,
    )
