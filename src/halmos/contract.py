# SPDX-License-Identifier: AGPL-3.0

from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar

from halmos.bitvec import HalmosBitVec as BV
from halmos.bytevec import ByteVec, ConcreteChunk
from halmos.constants import MAX_MEMORY_SIZE
from halmos.exceptions import (
    NotConcreteError,
    OutOfGasError,
)
from halmos.logs import (
    LIBRARY_PLACEHOLDER,
    warn_code,
)
from halmos.mapper import SingletonMeta, SourceFileMap
from halmos.utils import (
    Address,
    Byte,
    con_addr,
    hexify,
    int_of,
    is_concrete,
    str_opcode,
    stripped,
    uint256,
)

OP_STOP = 0x00
OP_ADD = 0x01
OP_MUL = 0x02
OP_SUB = 0x03
OP_DIV = 0x04
OP_SDIV = 0x05
OP_MOD = 0x06
OP_SMOD = 0x07
OP_ADDMOD = 0x08
OP_MULMOD = 0x09
OP_EXP = 0x0A
OP_SIGNEXTEND = 0x0B
OP_LT = 0x10
OP_GT = 0x11
OP_SLT = 0x12
OP_SGT = 0x13
OP_EQ = 0x14
OP_ISZERO = 0x15
OP_AND = 0x16
OP_OR = 0x17
OP_XOR = 0x18
OP_NOT = 0x19
OP_BYTE = 0x1A
OP_SHL = 0x1B
OP_SHR = 0x1C
OP_SAR = 0x1D
OP_SHA3 = 0x20
OP_ADDRESS = 0x30
OP_BALANCE = 0x31
OP_ORIGIN = 0x32
OP_CALLER = 0x33
OP_CALLVALUE = 0x34
OP_CALLDATALOAD = 0x35
OP_CALLDATASIZE = 0x36
OP_CALLDATACOPY = 0x37
OP_CODESIZE = 0x38
OP_CODECOPY = 0x39
OP_GASPRICE = 0x3A
OP_EXTCODESIZE = 0x3B
OP_EXTCODECOPY = 0x3C
OP_RETURNDATASIZE = 0x3D
OP_RETURNDATACOPY = 0x3E
OP_EXTCODEHASH = 0x3F
OP_BLOCKHASH = 0x40
OP_COINBASE = 0x41
OP_TIMESTAMP = 0x42
OP_NUMBER = 0x43
OP_DIFFICULTY = 0x44
OP_GASLIMIT = 0x45
OP_CHAINID = 0x46
OP_SELFBALANCE = 0x47
OP_BASEFEE = 0x48
OP_POP = 0x50
OP_MLOAD = 0x51
OP_MSTORE = 0x52
OP_MSTORE8 = 0x53
OP_SLOAD = 0x54
OP_SSTORE = 0x55
OP_JUMP = 0x56
OP_JUMPI = 0x57
OP_PC = 0x58
OP_MSIZE = 0x59
OP_GAS = 0x5A
OP_JUMPDEST = 0x5B
OP_TLOAD = 0x5C
OP_TSTORE = 0x5D
OP_MCOPY = 0x5E
OP_PUSH0 = 0x5F
OP_PUSH1 = 0x60
OP_PUSH2 = 0x61
OP_PUSH3 = 0x62
OP_PUSH4 = 0x63
OP_PUSH5 = 0x64
OP_PUSH6 = 0x65
OP_PUSH7 = 0x66
OP_PUSH8 = 0x67
OP_PUSH9 = 0x68
OP_PUSH10 = 0x69
OP_PUSH11 = 0x6A
OP_PUSH12 = 0x6B
OP_PUSH13 = 0x6C
OP_PUSH14 = 0x6D
OP_PUSH15 = 0x6E
OP_PUSH16 = 0x6F
OP_PUSH17 = 0x70
OP_PUSH18 = 0x71
OP_PUSH19 = 0x72
OP_PUSH20 = 0x73
OP_PUSH21 = 0x74
OP_PUSH22 = 0x75
OP_PUSH23 = 0x76
OP_PUSH24 = 0x77
OP_PUSH25 = 0x78
OP_PUSH26 = 0x79
OP_PUSH27 = 0x7A
OP_PUSH28 = 0x7B
OP_PUSH29 = 0x7C
OP_PUSH30 = 0x7D
OP_PUSH31 = 0x7E
OP_PUSH32 = 0x7F
OP_DUP1 = 0x80
OP_DUP2 = 0x81
OP_DUP3 = 0x82
OP_DUP4 = 0x83
OP_DUP5 = 0x84
OP_DUP6 = 0x85
OP_DUP7 = 0x86
OP_DUP8 = 0x87
OP_DUP9 = 0x88
OP_DUP10 = 0x89
OP_DUP11 = 0x8A
OP_DUP12 = 0x8B
OP_DUP13 = 0x8C
OP_DUP14 = 0x8D
OP_DUP15 = 0x8E
OP_DUP16 = 0x8F
OP_SWAP1 = 0x90
OP_SWAP2 = 0x91
OP_SWAP3 = 0x92
OP_SWAP4 = 0x93
OP_SWAP5 = 0x94
OP_SWAP6 = 0x95
OP_SWAP7 = 0x96
OP_SWAP8 = 0x97
OP_SWAP9 = 0x98
OP_SWAP10 = 0x99
OP_SWAP11 = 0x9A
OP_SWAP12 = 0x9B
OP_SWAP13 = 0x9C
OP_SWAP14 = 0x9D
OP_SWAP15 = 0x9E
OP_SWAP16 = 0x9F
OP_LOG0 = 0xA0
OP_LOG1 = 0xA1
OP_LOG2 = 0xA2
OP_LOG3 = 0xA3
OP_LOG4 = 0xA4
OP_CREATE = 0xF0
OP_CALL = 0xF1
OP_CALLCODE = 0xF2
OP_RETURN = 0xF3
OP_DELEGATECALL = 0xF4
OP_CREATE2 = 0xF5
OP_STATICCALL = 0xFA
OP_REVERT = 0xFD
OP_INVALID = 0xFE
OP_SELFDESTRUCT = 0xFF

CALL_OPCODES = (
    OP_CALL,
    OP_CALLCODE,
    OP_DELEGATECALL,
    OP_STATICCALL,
)

CREATE_OPCODES = (
    OP_CREATE,
    OP_CREATE2,
)

TERMINATING_OPCODES = (
    OP_STOP,
    OP_RETURN,
    OP_REVERT,
    OP_INVALID,
)

ERC1167_PREFIX = ByteVec(bytes.fromhex("363d3d373d3d3d363d73"))
ERC1167_SUFFIX = ByteVec(bytes.fromhex("5af43d82803e903d91602b57fd5bf3"))


def insn_len(opcode: int) -> int:
    return 1 + (opcode - OP_PUSH0) * (OP_PUSH1 <= opcode <= OP_PUSH32)


def mnemonic(opcode) -> str:
    if is_concrete(opcode):
        opcode = int_of(opcode)
        return str_opcode.get(opcode, hex(opcode))
    else:
        return str(opcode)


@dataclass(frozen=True, slots=True, eq=False, order=False)
class Instruction:
    opcode: int
    pc: int = -1
    next_pc: int = -1

    # expected to be a BV256, so that it can be pushed on the stack with no conversion
    operand: BV | None = None

    # source mapping
    source_file: str | None = None
    source_line: int | None = None

    STOP: ClassVar["Instruction"] = None

    def __str__(self) -> str:
        operand_str = ""
        if self.operand is not None:
            operand_size_bytes = len(self) - 1
            operand_str = f" {hexify(BV(self.operand, size=operand_size_bytes * 8))}"
        return f"{mnemonic(self.opcode)}{operand_str}"

    def __repr__(self) -> str:
        return f"Instruction({mnemonic(self.opcode)}, pc={self.pc}, operand={repr(self.operand)})"

    def __len__(self) -> int:
        return insn_len(self.opcode)

    def set_srcmap(self, source_file: str | None, source_line: int | None) -> None:
        object.__setattr__(self, "source_file", source_file)
        object.__setattr__(self, "source_line", source_line)


# Initialize the STOP singleton
Instruction.STOP = Instruction(OP_STOP)


class Contract:
    """Abstraction over contract bytecode. Can include concrete and symbolic elements."""

    _code: ByteVec
    _fastcode: bytes | None
    _insn: list[Instruction]
    _jumpdests: tuple[set] | None

    contract_name: str | None
    filename: str | None

    # Source mapping string, formatted as each item is "s:l:f:j:m", with items separated by ";"
    # where s=start, l=length, f=file_id, j=jump_type, m=modifier_depth
    # https://docs.soliditylang.org/en/latest/internals/source_mappings.html
    source_map: str | None

    def __init__(
        self,
        code: ByteVec | None = None,
        *,
        contract_name=None,
        filename=None,
        source_map=None,
    ) -> None:
        if not isinstance(code, ByteVec):
            code = ByteVec(code)

        self._code = code
        self._fastcode = None

        # if the bytecode starts with a concrete prefix, we store it separately for fast access
        # (this is a common case, especially for test contracts that deploy other contracts)
        if code.chunks:
            first_chunk = code.chunks[0]
            if isinstance(first_chunk, ConcreteChunk):
                self._fastcode = first_chunk.unwrap()

        # maps pc to decoded instruction (including operand and next_pc)
        self._insn = [None] * len(code)
        self._jumpdests = None

        self.contract_name = contract_name
        self.filename = filename
        self.source_map = source_map

    def __deepcopy__(self, memo):
        # the class is essentially immutable (the only mutable fields are caches)
        # so we can return the object itself instead of creating a new copy
        return self

    def __get_jumpdests(self):
        # quick scan, does not eagerly decode instructions
        jumpdests = set()
        pc = 0

        # optimistically process fast path first
        for bytecode in (self._fastcode, self._code):
            if not bytecode:
                continue

            N = len(bytecode)
            while pc < N:
                try:
                    opcode = bytecode[pc]
                    if type(opcode) is not int:
                        raise NotConcreteError(f"symbolic opcode at pc={pc}")

                    if opcode == OP_JUMPDEST:
                        jumpdests.add(pc)
                        pc += 1
                    else:
                        pc += insn_len(opcode)
                except NotConcreteError:
                    break

        return jumpdests

    # TODO: ensure this function is executed only once
    def process_source_mapping(self):
        """Add source mapping information to each instruction in the contract."""
        if not (source_map := self.source_map):
            return

        pc = 0
        byte_offset, file_id = 0, 0
        for item in source_map.split(";"):
            # split each mapping into its components
            data = item.split(":")
            # update byte_offset and file_id if they are not empty
            byte_offset_str = data[0]  # split() returns a non-empty list
            file_id_str = data[2] if len(data) > 2 else ""
            byte_offset = int(byte_offset_str) if byte_offset_str != "" else byte_offset
            file_id = int(file_id_str) if file_id_str != "" else file_id

            file_path, line_number = SourceFileMap().get_location(file_id, byte_offset)
            CoverageReporter().record_lines_found(file_path, line_number)

            insn = self.decode_instruction(pc)
            insn.set_srcmap(file_path, line_number)

            pc = insn.next_pc

    def from_hexcode(hexcode: str):
        """Create a contract from a hexcode string, e.g. "aabbccdd" """
        if not isinstance(hexcode, str):
            raise ValueError(hexcode)

        if len(hexcode) % 2 != 0:
            raise ValueError(hexcode)

        if "__" in hexcode:
            warn_code(
                LIBRARY_PLACEHOLDER, "contract hexcode contains library placeholder"
            )

        try:
            bytecode = bytes.fromhex(stripped(hexcode))
            return Contract(ByteVec(bytecode))
        except ValueError as e:
            raise ValueError(f"{e} (hexcode={hexcode})") from e

    def _decode_instruction(self, pc: int) -> Instruction:
        opcode = int_of(self[pc], f"symbolic opcode at pc={pc}")
        length = insn_len(opcode)
        next_pc = pc + length

        if length > 1:
            # TODO: consider slicing lazily
            operand = uint256(self.unwrapped_slice(pc + 1, next_pc))
            return Instruction(opcode, pc=pc, operand=operand, next_pc=next_pc)

        return Instruction(opcode, pc=pc, next_pc=next_pc)

    def decode_instruction(self, pc: int) -> Instruction:
        """decode instruction at pc and cache the result"""

        try:
            if (insn := self._insn[pc]) is not None:
                return insn
        except IndexError as e:
            if pc < 0:
                raise ValueError(f"invalid {pc=}") from e

            if pc >= len(self._insn):
                return Instruction.STOP

        insn = self._decode_instruction(pc)
        self._insn[pc] = insn
        return insn

    def next_pc(self, pc) -> int:
        return self.decode_instruction(pc).next_pc

    def slice(self, start, size) -> ByteVec:
        # large start is allowed, but we must check the size
        if size > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"code read {start=} {size=} > MAX_MEMORY_SIZE")

        stop = start + size

        # fast path for offsets in the concrete prefix
        if self._fastcode and stop < len(self._fastcode):
            return ByteVec(self._fastcode[start:stop])

        return self._code.slice(start, stop)

    def unwrapped_slice(self, start, stop) -> BV:
        """
        Returns a BV representing the slice of the bytecode
        """
        # fast path for offsets in the concrete prefix
        if self._fastcode and stop < len(self._fastcode):
            return BV(self._fastcode[start:stop])

        return BV(self._code.slice(start, stop).unwrap())

    def __getitem__(self, key: int) -> Byte:
        """Returns the byte at the given offset."""
        # fast path for offsets in the concrete prefix
        if (_fastcode := self._fastcode) is not None:
            try:
                return _fastcode[key]
            except IndexError:
                # out of bounds, fall back to the slow path
                pass

        return self._code.get_byte(key)

    def __len__(self) -> int:
        """Returns the length of the bytecode in bytes."""
        return len(self._code)

    def valid_jumpdests(self) -> set[int]:
        """Returns the set of valid jump destinations."""
        if self._jumpdests is None:
            self._jumpdests = self.__get_jumpdests()

        return self._jumpdests

    def extract_erc1167_target(self) -> Address | None:
        """
        Extracts the target address from an ERC-1167 minimal proxy contract.

        Returns:
            Address: The target contract address if this is an ERC-1167 proxy
            None: If this is not an ERC-1167 proxy
        """

        # Check if bytecode matches ERC-1167 pattern
        m = len(ERC1167_PREFIX)
        n = len(ERC1167_SUFFIX)
        erc1167_len = m + 20 + n

        if (
            len(self._code) == erc1167_len
            and self.slice(0, m) == ERC1167_PREFIX
            and self.slice(m + 20, n) == ERC1167_SUFFIX
        ):
            # Extract the 20-byte address between prefix and suffix
            target: ByteVec = self.slice(m, 20)
            unwrapped = target.unwrap()
            if isinstance(unwrapped, bytes):
                return con_addr(int.from_bytes(unwrapped, "big"))

        return None


class CoverageReporter(metaclass=SingletonMeta):
    """Singleton class for tracking instruction coverage across all tests and paths.

    This class maintains a record of which lines of code have been executed during contract testing.
    The coverage data is used to generate LCOV format reports.
    """

    def __init__(self) -> None:
        # file_path -> line_number -> count
        self._instruction_coverage_data: dict[str, dict[int, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def record_lines_found(
        self, file_path: str | None, line_number: int | None
    ) -> None:
        """Record that an executable line appears in the source code.

        This method is used to track which lines are executable in the source code,
        regardless of whether they were executed. This information is used to
        calculate the total number of lines (LF) in the LCOV report.
        """
        if not file_path or not line_number:
            return
        # utilize defaultdict to initialize a count of 0 if the line is not yet recorded
        self._instruction_coverage_data[file_path][line_number]

    def record_instruction(self, instruction: Instruction) -> None:
        """Record instruction coverage by file path and line number."""
        if (file := instruction.source_file) and (line := instruction.source_line):
            self._instruction_coverage_data[file][line] += 1

    def generate_lcov_report(self) -> str:
        """Generate an LCOV format coverage report.

        The LCOV format includes:
        - SF: Source file path
        - DA: Line data (line number and execution count)
        - LF: Total number of lines found in the file
        - LH: Number of lines that were executed at least once
        """
        lcov_lines = []

        for file_path, line_coverage in self._instruction_coverage_data.items():
            # SF: Source file
            lcov_lines.append(f"SF:{file_path}")

            # DA: Line data (line number, execution count)
            for line_number, count in sorted(line_coverage.items()):
                lcov_lines.append(f"DA:{line_number},{count}")

            # LF: Lines found
            lcov_lines.append(f"LF:{len(line_coverage)}")

            # LH: Lines hit (lines with count > 0)
            lines_hit = sum(1 for count in line_coverage.values() if count > 0)
            lcov_lines.append(f"LH:{lines_hit}")

            # End of file
            lcov_lines.append("end_of_record")

        return "\n".join(lcov_lines)
