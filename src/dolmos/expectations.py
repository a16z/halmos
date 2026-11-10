# SPDX-License-Identifier: AGPL-3.0

"""
Support for the `vm.expectRevert*` / `vm.expectPartialRevert*` and
`vm.expectEmit*` / `vm.expectEmitAnonymous*` cheatcodes (halmos issue #409).

The semantics follow foundry:

- an expectation is set by a cheatcode call and applies to the *next call* (or
  contract creation) made by the same frame; calls to cheatcode addresses and to
  the console are ignored.
- expectRevert: the next call must revert, with a matching reason and reverter if
  given. When the expectation is met the call is reported as successful to the
  caller, with dummy return data (like foundry). `count = n` requires the next n
  calls to revert, `count = 0` requires the next call not to revert.
- expectEmit: the next event emitted by the frame itself is recorded as the
  expected event. The next call must then emit events matching the expected ones
  (in order, anywhere in its call tree). With a `count`, the expected event must
  be emitted exactly `count` times.
- an expectation that is still pending when the frame returns successfully makes
  the test fail.

Because data may be symbolic, matching produces an SMT condition: the caller
forks a failing path when the condition can be false.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field

from z3 import (
    And,
    BitVecRef,
    BoolRef,
    BoolVal,
    Concat,
    Extract,
    If,
    Or,
    Sum,
    is_bv,
    simplify,
)

from dolmos.bitvec import DolmosBitVec as BV
from dolmos.bytevec import ByteVec
from dolmos.exceptions import DolmosException
from dolmos.utils import (
    bytes_to_bv_value,
    con,
    extract_bytes_argument,
    int_of,
    uint160,
)

# foundry reports a successful call with 8192 zero bytes when a revert was expected
DUMMY_CALL_OUTPUT = ByteVec(bytes(8192))

# bytes4(keccak256("Error(string)"))
ERROR_STRING_SELECTOR = bytes.fromhex("08c379a0")

UnwrappedBytes = bytes | BitVecRef


#
# expectation records
#


@dataclass
class ExpectedRevert:
    reason: UnwrappedBytes | None = None  # None: any revert data
    partial: bool = False  # only compare the first 4 bytes
    reverter: BitVecRef | None = None  # None: any reverter
    count: int = 1  # 0: the next call must not revert

    def __str__(self) -> str:
        parts = []
        if self.reason is not None:
            parts.append(f"reason={_hex(self.reason)}")
        if self.reverter is not None:
            parts.append(f"reverter={self.reverter}")
        if self.count != 1:
            parts.append(f"count={self.count}")
        name = "expectPartialRevert" if self.partial else "expectRevert"
        return f"{name}({', '.join(parts)})"


@dataclass
class ExpectedEmit:
    # checks for topic0 (anonymous events only), topic1, topic2, topic3, data
    checks: tuple[bool, bool, bool, bool, bool]
    anonymous: bool = False
    emitter: BitVecRef | None = None
    count: int | None = None  # None: plain (ordered) expectation
    log: object | None = None  # the expected EventLog, once emitted

    def __str__(self) -> str:
        name = "expectEmitAnonymous" if self.anonymous else "expectEmit"
        emitter = f", emitter={self.emitter}" if self.emitter is not None else ""
        count = f", count={self.count}" if self.count is not None else ""
        return f"{name}(checks={self.checks}{emitter}{count})"


@dataclass
class Expectations:
    """
    Pending expectations of a call frame. Stored in its CallContext.
    """

    revert: ExpectedRevert | None = None
    emits: list[ExpectedEmit] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.revert is not None or bool(self.emits)

    def expect_revert(self, expected: ExpectedRevert) -> None:
        if self.revert is not None:
            raise DolmosException(
                "expectRevert: an expected revert is already pending; "
                "call another function before expecting a second revert"
            )
        self.revert = expected

    def expect_emit(self, expected: ExpectedEmit) -> None:
        self.emits.append(expected)

    def capture_log(self, log) -> None:
        """Records `log` as the expected event of the first unfilled expectEmit."""
        for spec in self.emits:
            if spec.log is None:
                spec.log = log
                return

    def take(self) -> "Expectations | None":
        """
        Returns the expectations that apply to the next call, and clears them.
        """
        if not self:
            return None

        taken = Expectations(revert=self.revert, emits=self.emits)
        self.revert = None
        self.emits = []
        return taken

    def describe(self) -> str:
        items = ([str(self.revert)] if self.revert else []) + [
            str(e) for e in self.emits
        ]
        return ", ".join(items)


#
# cheatcode argument decoding
#


def _word(arg: ByteVec, idx: int):
    return arg.get_word(4 + 32 * idx)


def _bool(arg: ByteVec, idx: int, name: str) -> bool:
    return int_of(_word(arg, idx), f"symbolic {name} argument") != 0


def _address(arg: ByteVec, idx: int) -> BitVecRef:
    return uint160(_word(arg, idx)).as_z3()


def _uint64(arg: ByteVec, idx: int, name: str) -> int:
    return int_of(_word(arg, idx), f"symbolic {name} count") & (2**64 - 1)


def _bytes4(arg: ByteVec, idx: int) -> UnwrappedBytes:
    start = 4 + 32 * idx
    return arg.slice(start, start + 4).unwrap()


# expectRevert variants: signature -> argument layout
REVERT_SIGNATURES: dict[int, tuple[str, tuple[str, ...]]] = {
    0xF4844814: ("expectRevert()", ()),
    0xC31EB0E0: ("expectRevert(bytes4)", ("bytes4",)),
    0xF28DCEB3: ("expectRevert(bytes)", ("bytes",)),
    0xD814F38A: ("expectRevert(address)", ("address",)),
    0x260BC5DE: ("expectRevert(bytes4,address)", ("bytes4", "address")),
    0x61EBCF12: ("expectRevert(bytes,address)", ("bytes", "address")),
    0x4EE38244: ("expectRevert(uint64)", ("count",)),
    0xE45CA72D: ("expectRevert(bytes4,uint64)", ("bytes4", "count")),
    0x4994C273: ("expectRevert(bytes,uint64)", ("bytes", "count")),
    0x1FF5F952: ("expectRevert(address,uint64)", ("address", "count")),
    0xB0762D73: (
        "expectRevert(bytes4,address,uint64)",
        ("bytes4", "address", "count"),
    ),
    0xD345FB1F: (
        "expectRevert(bytes,address,uint64)",
        ("bytes", "address", "count"),
    ),
    0x11FB5B9C: ("expectPartialRevert(bytes4)", ("bytes4",)),
    0x51AA008A: ("expectPartialRevert(bytes4,address)", ("bytes4", "address")),
}

# expectEmit variants: signature -> (anonymous, argument layout)
EMIT_SIGNATURES: dict[int, tuple[str, bool, tuple[str, ...]]] = {
    0x440ED10D: ("expectEmit()", False, ()),
    0x86B9620D: ("expectEmit(address)", False, ("address",)),
    0x491CC7C2: ("expectEmit(bool,bool,bool,bool)", False, ("bool",) * 4),
    0x81BAD6F3: (
        "expectEmit(bool,bool,bool,bool,address)",
        False,
        ("bool",) * 4 + ("address",),
    ),
    0x4C74A335: ("expectEmit(uint64)", False, ("count",)),
    0xB43AECE3: ("expectEmit(address,uint64)", False, ("address", "count")),
    0x5E1D1C33: (
        "expectEmit(bool,bool,bool,bool,uint64)",
        False,
        ("bool",) * 4 + ("count",),
    ),
    0xC339D02C: (
        "expectEmit(bool,bool,bool,bool,address,uint64)",
        False,
        ("bool",) * 4 + ("address", "count"),
    ),
    0x2E5F270C: ("expectEmitAnonymous()", True, ()),
    0x6FC68705: ("expectEmitAnonymous(address)", True, ("address",)),
    0xC948DB5E: (
        "expectEmitAnonymous(bool,bool,bool,bool,bool)",
        True,
        ("bool",) * 5,
    ),
    0x71C95899: (
        "expectEmitAnonymous(bool,bool,bool,bool,bool,address)",
        True,
        ("bool",) * 5 + ("address",),
    ),
}


def parse_expect_revert(funsig: int, arg: ByteVec) -> ExpectedRevert:
    name, layout = REVERT_SIGNATURES[funsig]
    expected = ExpectedRevert(partial=name.startswith("expectPartialRevert"))

    for idx, kind in enumerate(layout):
        match kind:
            case "bytes4":
                expected.reason = _bytes4(arg, idx)
            case "bytes":
                expected.reason = extract_bytes_argument(arg, idx)
            case "address":
                expected.reverter = _address(arg, idx)
            case "count":
                expected.count = _uint64(arg, idx, name)

    return expected


def parse_expect_emit(funsig: int, arg: ByteVec) -> ExpectedEmit:
    name, anonymous, layout = EMIT_SIGNATURES[funsig]

    bools = [_bool(arg, i, name) for i, k in enumerate(layout) if k == "bool"]
    if not bools:
        bools = [True] * (5 if anonymous else 4)

    # normalize to (topic0, topic1, topic2, topic3, data);
    # topic0 (the event selector) is always checked for non-anonymous events
    checks = tuple(bools) if anonymous else (True, *bools)

    expected = ExpectedEmit(checks=checks, anonymous=anonymous)
    for idx, kind in enumerate(layout):
        match kind:
            case "address":
                expected.emitter = _address(arg, idx)
            case "count":
                expected.count = _uint64(arg, idx, name)

    return expected


#
# symbolic matching
#


def _unwrap(x) -> UnwrappedBytes:
    if isinstance(x, ByteVec):
        return x.unwrap()
    return x


def _len(x: UnwrappedBytes) -> int:
    return x.size() // 8 if is_bv(x) else len(x)


def _slice(x: UnwrappedBytes, start: int, stop: int) -> UnwrappedBytes:
    """Byte slice [start:stop), zero-padded if out of bounds."""
    n = _len(x)
    if stop <= start:
        return b""
    if not is_bv(x):
        return (x + bytes(max(0, stop - n)))[start:stop]
    if start >= n:
        return bytes(stop - start)
    hi = (n - start) * 8 - 1
    lo = max(0, (n - stop) * 8)
    part = Extract(hi, lo, x)
    pad = stop - min(stop, n)
    return simplify(Concat(part, con(0, pad * 8))) if pad else simplify(part)


def _to_bv(x: UnwrappedBytes) -> BitVecRef:
    return x if is_bv(x) else bytes_to_bv_value(x)


def eq_bytes(a, b) -> BoolRef:
    a, b = _unwrap(a), _unwrap(b)
    if _len(a) != _len(b):
        return BoolVal(False)
    if _len(a) == 0:
        return BoolVal(True)
    if not is_bv(a) and not is_bv(b):
        return BoolVal(a == b)
    return _to_bv(a) == _to_bv(b)


def as_z3_word(x):
    if isinstance(x, BV):
        return x.as_z3()
    if isinstance(x, int):
        return con(x)
    return x


def revert_reason_matches(expected: ExpectedRevert, data: ByteVec) -> BoolRef:
    """
    Whether revert `data` matches the expected reason:
    - the raw revert data equals the reason, or
    - the data is `Error(string)` and its payload equals the reason, or
    - for partial matches, the first 4 bytes are equal.
    """
    if expected.reason is None:
        return BoolVal(True)

    reason = expected.reason
    raw = _unwrap(data)
    reason_len, data_len = _len(reason), _len(raw)

    conds = [eq_bytes(raw, reason)]

    if expected.partial and reason_len >= 4 and data_len >= 4:
        conds.append(eq_bytes(_slice(raw, 0, 4), _slice(reason, 0, 4)))

    # Error(string) unwrapping: selector | offset (0x20) | length | payload
    payload_end = 68 + reason_len
    if data_len >= payload_end:
        conds.append(
            And(
                eq_bytes(_slice(raw, 0, 4), ERROR_STRING_SELECTOR),
                eq_bytes(_slice(raw, 4, 36), (32).to_bytes(32, "big")),
                eq_bytes(_slice(raw, 36, 68), reason_len.to_bytes(32, "big")),
                eq_bytes(_slice(raw, 68, payload_end), reason),
            )
        )

    return simplify(Or(*conds))


def find_reverter(subcall) -> BitVecRef:
    """
    The address that originally reverted: follow the chain of reverted subcalls
    that bubbled up the same revert data.
    """
    ctx = subcall
    while True:
        child = ctx.last_subcall()
        if (
            child is None
            or child.output.error is None
            or child.output.data is None
            or child.output.data != ctx.output.data
        ):
            return ctx.message.target
        ctx = child


def iter_logs(ctx) -> Iterator:
    """All the logs emitted in a call tree, in execution order."""
    for item in ctx.trace:
        if hasattr(item, "topics"):
            yield item
        elif hasattr(item, "trace"):
            yield from iter_logs(item)


def log_matches(spec: ExpectedEmit, log) -> BoolRef:
    expected = spec.log
    conds = []

    if spec.emitter is not None:
        conds.append(as_z3_word(log.address) == as_z3_word(spec.emitter))

    if len(log.topics) != len(expected.topics):
        return BoolVal(False)

    for i, (actual, wanted) in enumerate(zip(log.topics, expected.topics, strict=True)):
        if spec.checks[i]:
            conds.append(as_z3_word(actual) == as_z3_word(wanted))

    if spec.checks[4]:
        conds.append(eq_bytes(log.data or b"", expected.data or b""))

    return simplify(And(*conds)) if conds else BoolVal(True)


def emits_match(specs: list[ExpectedEmit], subcall) -> tuple[BoolRef, str | None]:
    """
    Returns (condition, error). A non-None error means the expectation can't be met.
    """
    unfilled = [s for s in specs if s.log is None]
    if unfilled:
        return BoolVal(False), (
            f"{unfilled[0]}: no event was emitted between the cheatcode and the next call"
        )

    logs = list(iter_logs(subcall))
    conds = []

    # counted expectations are checked independently
    for spec in (s for s in specs if s.count is not None):
        hits = [If(log_matches(spec, log), con(1), con(0)) for log in logs]
        total = simplify(Sum(hits)) if hits else con(0)
        conds.append(total == con(spec.count))

    # plain expectations must appear as an ordered subsequence of the logs
    ordered = [s for s in specs if s.count is None]
    memo: dict[tuple[int, int], BoolRef] = {}

    def matches_from(i: int, j: int) -> BoolRef:
        if i == len(ordered):
            return BoolVal(True)
        if len(ordered) - i > len(logs) - j:
            return BoolVal(False)
        if (i, j) not in memo:
            memo[i, j] = simplify(
                Or(
                    And(log_matches(ordered[i], logs[j]), matches_from(i + 1, j + 1)),
                    matches_from(i, j + 1),
                )
            )
        return memo[i, j]

    if ordered:
        conds.append(matches_from(0, 0))

    return simplify(And(*conds)) if conds else BoolVal(True), None


def _hex(x: UnwrappedBytes) -> str:
    if is_bv(x):
        return str(x)
    return "0x" + x.hex()
