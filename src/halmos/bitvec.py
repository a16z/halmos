# SPDX-License-Identifier: AGPL-3.0

from typing import Any, TypeAlias

from z3 import (
    UGE,
    UGT,
    ULE,
    ULT,
    And,
    BitVec,
    BitVecRef,
    BitVecVal,
    Bool,
    BoolRef,
    BoolVal,
    Concat,
    Extract,
    FuncDeclRef,
    If,
    LShR,
    Not,
    Or,
    SignExt,
    SRem,
    UDiv,
    URem,
    Xor,
    ZeroExt,
    eq,
    is_bv_value,
    is_false,
    is_true,
    simplify,
)

from halmos.exceptions import NotConcreteError

BV: TypeAlias = "HalmosBitVec"
AnyValue: TypeAlias = "int | bytes | BitVecRef | BV | HalmosBool | str"
BVValue: TypeAlias = int | BitVecRef | BoolRef
MaybeSize: TypeAlias = int | None
AnyBool: TypeAlias = bool | BoolRef


def is_power_of_two(x: int) -> bool:
    return x > 0 and not (x & (x - 1))


def to_signed(x: int, bit_size: int) -> int:
    """
    Interpret x (masked to bit_size bits) as a signed integer in two's complement.
    """
    sign_bit = 1 << (bit_size - 1)
    return x - (1 << bit_size) if (x & sign_bit) else x


def as_int(value: AnyValue) -> tuple[BVValue, MaybeSize]:
    if isinstance(value, int):
        return value, None
    elif isinstance(value, bytes):
        return int.from_bytes(value, "big"), len(value) * 8
    elif is_bv_value(value):
        return value.as_long(), value.size()
    elif isinstance(value, HalmosBitVec):
        return value.unwrap(), value.size
    elif isinstance(value, BitVecRef):
        return value, value.size()
    elif isinstance(value, HalmosBool):
        return value.unwrap(), 1
    elif isinstance(value, BoolRef):
        return value, 1
    else:
        raise TypeError(f"Cannot convert {type(value)} to int")


class HalmosBool:
    """
    Immutable wrapper for concrete or symbolic boolean values.

    Can be constructed with:
    - HalmosBool(42 % 2 == 0) # bool
    - HalmosBool(BitVec(x, 8) != 0) # BoolRef
    - HalmosBool(HalmosBitVec(x, 8)) # HalmosBitVec, same as above

    Conversion to and from HalmosBitVec:
    - HalmosBitVec(halmos_bool) (same as halmos_bool.as_bv())
    - HalmosBool(halmos_bitvec) (same as halmos_bitvec.is_non_zero())

    Wrapping/unwrapping:
    - halmos_bool.as_z3() always converts to a z3 BoolRef
    - bool(halmos_bool) converts to a concrete bool, raises if symbolic
    - halmos_bool.value/unwrap() returns the underlying bool or z3 BoolRef
    """

    __slots__ = ("con_val", "sym_val")
    con_val: bool | None
    sym_val: BoolRef | None

    def __new__(cls, value, *, do_simplify: bool = True):
        type_value = type(value)

        if type_value is bool:
            return TRUE if value else FALSE

        if type_value is HalmosBool:
            return value

        if type_value is HalmosBitVec:
            return value.is_non_zero()

        if type_value is BoolRef:
            if do_simplify:
                value = simplify(value)

            if is_true(value):
                return TRUE

            if is_false(value):
                return FALSE

        return super().__new__(cls)

    def __init__(self, value: AnyBool | str, *, do_simplify: bool = True):
        match value:
            case bool():
                self.con_val = value
                self.sym_val = None

            case BoolRef():
                # TODO: avoid double simplification
                simplified = simplify(value) if do_simplify else value
                self.sym_val = simplified
                self.con_val = None

            case str():
                self.sym_val = Bool(value)
                self.con_val = None

            case HalmosBool():
                return

            case HalmosBitVec():
                return

            case _:
                raise TypeError(f"Cannot create HalmosBool from {type(value)}")

        assert self.con_val is None or self.sym_val is None
        assert self.con_val is not None or self.sym_val is not None

    def __bool__(self) -> bool:
        if self.is_symbolic:
            raise NotConcreteError("Cannot convert symbolic bool to bool")
        return self.con_val

    def __repr__(self) -> str:
        return str(self.con_val) if self.is_concrete else f"⚠️ SYM {self.sym_val}"

    def __str__(self) -> str:
        return str(self.con_val) if self.is_concrete else f"⚠️ SYM {self.sym_val}"

    def __int__(self) -> int:
        return int(bool(self))

    def __deepcopy__(self, memo):
        return self

    def as_z3(self) -> BoolRef:
        return BoolVal(self.con_val) if self.is_concrete else self.sym_val

    def unwrap(self) -> AnyBool:
        return self.value

    @property
    def value(self) -> AnyBool:
        if self is TRUE:
            return True

        if self is FALSE:
            return False

        return self.sym_val

    @property
    def is_symbolic(self) -> bool:
        return self.sym_val is not None

    @property
    def is_concrete(self) -> bool:
        return self.sym_val is None

    @property
    def is_true(self) -> bool:
        """checks if it is the literal True"""

        return self is TRUE

    @property
    def is_false(self) -> bool:
        """checks if it is the literal False"""

        return self is FALSE

    def __eq__(self, other: Any) -> bool:
        """
        tests for structural equality, including size

        note: this is not the same as z3's comparison, which returns a constraint
        """

        if not isinstance(other, HalmosBool):
            return False

        match (self.con_val, other.con_val):
            case (True, True):
                return True

            case (False, False):
                return True

            case (None, None):
                return eq(self.sym_val, other.sym_val)

            case _:
                return False

    def __hash__(self) -> int:
        """
        Hash the boolean based on its value.
        """

        return hash((self.con_val, self.sym_val))

    def is_zero(self) -> "HalmosBool":
        if self is TRUE:
            return FALSE

        if self is FALSE:
            return TRUE

        return HalmosBool(Not(self.sym_val))

    def is_non_zero(self) -> "HalmosBool":
        return self

    def eq(self, other: "HalmosBool") -> "HalmosBool":
        return HalmosBool(self.value == other.value)

    def neg(self) -> "HalmosBool":
        return self.is_zero()

    def bitwise_not(self) -> "HalmosBool":
        return self.is_zero()

    def bitwise_and(self, other: "HalmosBool") -> "HalmosBool":
        if self is TRUE:
            return other

        if self is FALSE:
            return self

        if other is TRUE:
            return self

        if other is FALSE:
            return other

        return HalmosBool(And(self.as_z3(), other.as_z3()))

    def bitwise_or(self, other: "HalmosBool") -> "HalmosBool":
        if self is TRUE:
            return self

        if other is TRUE:
            return other

        if self is FALSE:
            return other

        if other is FALSE:
            return self

        return HalmosBool(Or(self.as_z3(), other.as_z3()))

    def bitwise_xor(self, other: "HalmosBool") -> "HalmosBool":
        if self is TRUE:
            return other.bitwise_not()

        if other is TRUE:
            return self.bitwise_not()

        if self is FALSE:
            return other

        if other is FALSE:
            return self

        return HalmosBool(Xor(self.as_z3(), other.as_z3()))

    def as_bv(self, size: int = 1) -> BV:
        if self is TRUE:
            return ONE if size == 256 else HalmosBitVec(1, size=size)

        if self is FALSE:
            return ZERO if size == 256 else HalmosBitVec(0, size=size)

        expr = If(self.sym_val, BitVecVal(1, size), BitVecVal(0, size))
        return HalmosBitVec(expr, size=size)


class HalmosBitVec:
    """
    Immutable wrapper for concrete or symbolic bitvectors.

    Can be constructed with:
    - HalmosBitVec(42) # int, size is default (256)
    - HalmosBitVec(-1, size=8) # int, 2's complement
    - HalmosBitVec(bytes.fromhex("12345678")) # bytes, size is inherited
    - HalmosBitVec(BitVecVal(42, 8)) # BitVecVal, size is inherited
    - HalmosBitVec(BitVec(x, 8)) # BitVecRef, size is inherited
    - HalmosBitVec(halmos_bool) # HalmosBool, size 1
    - HalmosBitVec("x") # named symbol, size is default (256)

    Conversion to and from HalmosBool:
    - HalmosBitVec(halmos_bool) (same as halmos_bool.as_bv())
    - HalmosBool(halmos_bitvec) (same as halmos_bitvec.is_non_zero())

    Wrapping/unwrapping:
    - halmos_bitvec.as_z3() always converts to a z3 BitVecRef
    - int(halmos_bitvec) converts to a concrete int, raises if symbolic
    - halmos_bitvec.value/unwrap() returns the underlying int or z3 BitVecRef
    """

    __slots__ = ("_value", "_symbolic", "_size")

    def __new__(cls, value, size=None, do_simplify=True):
        # fast path for existing HalmosBitVec of same size
        if isinstance(value, HalmosBitVec):
            size = size or value._size
            if size == value._size:
                return value

        # otherwise, proceed with normal allocation
        return super().__new__(cls)

    def __init__(
        self, value: AnyValue, *, size: MaybeSize = None, do_simplify: bool = True
    ):
        """
        Create a new HalmosBitVec from an integer, bytes, or a z3 BitVecRef.

        If the value is too large for the bit size, it will be truncated.

        If do_simplify is True, z3's simplify function will be applied to the value.
        """

        type_value = type(value)

        if type_value is HalmosBitVec:
            # avoid reinitializing HalmosBitVec because of __new__ shortcut if same size
            if size == value.size:
                return

            # otherwise, create a new HalmosBitVec with the new size
            value = value.unwrap()

        # unwrap HalmosBool
        elif type_value is HalmosBool:
            value = value.unwrap()

        # convenience, wrap a string as a named symbol
        elif type_value is str:
            value = BitVec(value, size or 256)

        # coerce int-like values to int
        value, maybe_size = as_int(value)
        size = size or (maybe_size or 256)
        self._size = size

        # coerce symbolic BoolRef to BitVecRef
        if isinstance(value, BoolRef):
            value = If(value, BitVecVal(1, size), BitVecVal(0, size))

        # at this point, value should either be an int or a BitVecRef
        if isinstance(value, int):
            self._symbolic = False
            self._value = value & ((1 << size) - 1)

        elif isinstance(value, BitVecRef):
            if size < value.size():
                value = Extract(size - 1, 0, value)
            elif size > value.size():
                # ZeroExt will get simplified to Concat
                value = Concat(BitVecVal(0, size - value.size()), value)

            simplified = simplify(value) if do_simplify else value

            if is_bv_value(simplified):
                self._symbolic = False
                self._value = simplified.as_long()
            else:
                self._symbolic = True
                self._value = simplified

        else:
            raise TypeError(f"Cannot create HalmosBitVec from {type(value)}")

    def __deepcopy__(self, memo):
        # yay immutability
        return self

    @property
    def size(self) -> int:
        """
        The size of the bitvector in bits.
        """
        return self._size

    @property
    def is_symbolic(self) -> bool:
        return self._symbolic

    @property
    def is_concrete(self) -> bool:
        return not self._symbolic

    @property
    def value(self) -> int | BitVecRef:
        return self._value

    def as_z3(self) -> BitVecRef:
        return self._value if self._symbolic else BitVecVal(self._value, self._size)

    def unwrap(self) -> int | BitVecRef:
        return self._value

    def __eq__(self, other: Any) -> bool:
        """
        tests for structural equality, including size

        note: this is not the same as z3's comparison, which returns a constraint
        """
        if not isinstance(other, HalmosBitVec):
            return False

        if self._size != other.size:
            return False

        if self.is_symbolic and other.is_symbolic:
            return eq(self.value, other.value)

        if self.is_concrete and other.is_concrete:
            return self.value == other.value

        return False

    def __hash__(self) -> int:
        """
        Hash the bitvector based on its value and size.
        """

        return hash((self.value, self.size))

    def __int__(self) -> int:
        if self._symbolic:
            if is_bv_value(self._value):
                return self._value.as_long()
            raise NotConcreteError("Cannot convert symbolic bitvec to int")

        return self._value

    def __repr__(self) -> str:
        return str(self._value)

    def __str__(self) -> str:
        return str(self._value)

    def is_zero(self) -> HalmosBool:
        # works for both symbolic and concrete
        return HalmosBool(self._value == 0)

    def is_non_zero(self) -> HalmosBool:
        # works for both symbolic and concrete
        return HalmosBool(self._value != 0)

    #
    # operations
    #

    def add(self, other: BV) -> BV:
        size = self._size
        assert size == other._size

        return HalmosBitVec(self._value + other._value, size=size)

    def sub(self, other: BV) -> "HalmosBitVec":
        size = self._size
        assert size == other._size

        return HalmosBitVec(self._value - other._value, size=size)

    def mul(
        self, other: BV, *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value
        match (self.is_concrete, other.is_concrete):
            case (True, True):
                return HalmosBitVec(lhs * rhs, size=size)

            case (True, False):
                if lhs == 0:
                    return self

                if lhs == 1:
                    return other

                if is_power_of_two(lhs):
                    return other.lshl(HalmosBitVec(lhs.bit_length() - 1, size=size))

                return HalmosBitVec(lhs * rhs, size=size)

            case (False, True):
                if rhs == 0:
                    return other

                if rhs == 1:
                    return self

                if is_power_of_two(rhs):
                    return self.lshl(HalmosBitVec(rhs.bit_length() - 1, size=size))

                # simplify(x * 123) -> 123 * x
                return HalmosBitVec(rhs * lhs, size=size)

        return (
            HalmosBitVec(lhs * rhs, size=size)
            if abstraction is None
            else HalmosBitVec(abstraction(lhs, rhs), size=size)
        )

    def div(
        self, other: BV, *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        # TODO: div_xy_y

        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value

        # concrete denominator case
        if other.is_concrete:
            # div by zero is zero
            if rhs == 0:
                return other

            # div by one is identity
            if rhs == 1:
                return self

            # fully concrete case
            if self.is_concrete:
                return HalmosBitVec(lhs // rhs, size=size)

            if is_power_of_two(rhs):
                return self.lshr(HalmosBitVec(rhs.bit_length() - 1, size=size))

        # symbolic case
        if abstraction is None:
            return HalmosBitVec(UDiv(lhs, rhs), size=size)

        return HalmosBitVec(abstraction(lhs, rhs), size=size)

    def sdiv(
        self, other: BV, *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        # TODO: sdiv_xy_y
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value

        if other.is_concrete:
            if rhs == 0:
                return other  # div by zero is zero

            if rhs == 1:
                return self  # div by one is identity

            if self.is_concrete:
                # rely on z3 to handle the signed division
                return HalmosBitVec(
                    BitVecVal(lhs, size) / BitVecVal(rhs, size),
                    size=size,
                    do_simplify=True,
                )

        if abstraction is None:
            return HalmosBitVec(other / self, size=size)

        return HalmosBitVec(abstraction(lhs, rhs), size=size)

    def mod(
        self, other: "HalmosBitVec", *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value

        if other.is_concrete:
            # mod by zero is zero
            if rhs == 0:
                return other

            # mod by one is zero
            if rhs == 1:
                return HalmosBitVec(0, size=size)

            # fully concrete case
            if self.is_concrete:
                return HalmosBitVec(lhs % rhs, size=size)

            # mod by a power of two only keeps the low bits
            if is_power_of_two(rhs):
                # option 1: use z3 bitwise and
                # 10000 loops, best of 5: 148.215 usec per loop
                # return HalmosBitVec(lhs & (rhs - 1), size=size)

                # option 2: truncate and extend
                # 10000 loops, best of 5: 146.525 usec per loop
                # truncated = HalmosBitVec(lhs, size=rhs.bit_length() - 1)
                # return HalmosBitVec(truncated, size=size)

                # option 3: truncate and extend, skip simplify
                # 10000 loops, best of 5: 130.028 usec per loop
                # truncated = HalmosBitVec(lhs, size=rhs.bit_length() - 1, do_simplify=False)
                # return HalmosBitVec(truncated, size=size)

                # option 4: explicit ZeroExt and Extract
                # on this path, we know that rhs > 1, so bitsize > 1
                # 10000 loops, best of 5: 106.079 usec per loop
                bitsize = rhs.bit_length() - 1
                truncated = Extract(bitsize - 1, 0, lhs)
                extended = ZeroExt(size - bitsize, truncated)
                return HalmosBitVec(extended, size=size)

        # symbolic case
        if abstraction is None:
            return HalmosBitVec(URem(lhs, rhs), size=size)

        return HalmosBitVec(abstraction(lhs, rhs), size=size)

    def smod(
        self, other: "HalmosBitVec", *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value

        if other.is_concrete:
            if rhs == 0:
                return other

            # mod by one is zero
            if rhs == 1:
                return HalmosBitVec(0, size=size)

            # TODO: implement concrete signed remainder
            # (tricky because it truncates towards zero)

            if self.is_concrete:
                # rely on z3 to handle the signed division
                return HalmosBitVec(
                    SRem(BitVecVal(lhs, size), BitVecVal(rhs, size)),
                    size=size,
                    do_simplify=True,
                )

        # lhs and rhs are symbolic
        if abstraction is None:
            return HalmosBitVec(SRem(lhs, rhs), size=size)

        return HalmosBitVec(abstraction(lhs, rhs), size=size)

    def exp(
        self,
        other: "HalmosBitVec",
        *,
        exp_abstraction: FuncDeclRef | None = None,
        mul_abstraction: FuncDeclRef | None = None,
        smt_exp_by_const: int = 0,
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value

        if other.is_concrete:
            if rhs == 0:
                return HalmosBitVec(1, size=size)

            if rhs == 1:
                return self

            if self.is_concrete:
                return HalmosBitVec(lhs**rhs, size=size)

            if rhs <= smt_exp_by_const:
                exp = self
                for _ in range(rhs - 1):
                    exp = self.mul(exp, abstraction=mul_abstraction)
                return exp

        if exp_abstraction is None:
            raise NotImplementedError("missing SMT abstraction for exponentiation")

        return HalmosBitVec(exp_abstraction(lhs, rhs), size=size)

    def addmod(
        self,
        other: "HalmosBitVec",
        modulus: "HalmosBitVec",
        *,
        abstraction: FuncDeclRef | None = None,
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size
        assert size == modulus.size

        if self.is_concrete and other.is_concrete and modulus.is_concrete:
            return HalmosBitVec((self.value + other.value) % modulus.value, size=size)

        # to avoid add overflow; and to be a multiple of 8-bit
        newsize = size + 8

        r1 = HalmosBitVec(self, size=newsize).add(HalmosBitVec(other, size=newsize))
        r2 = r1.mod(HalmosBitVec(modulus, size=newsize), abstraction=abstraction)

        if r1.size != newsize:
            raise ValueError(r1)
        if r2.size != newsize:
            raise ValueError(r2)

        return HalmosBitVec(r2, size=size)

    def mulmod(
        self,
        other: "HalmosBitVec",
        modulus: "HalmosBitVec",
        *,
        mul_abstraction: FuncDeclRef | None = None,
        mod_abstraction: FuncDeclRef | None = None,
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size
        assert size == modulus.size

        if self.is_concrete and other.is_concrete and modulus.is_concrete:
            return HalmosBitVec((self.value * other.value) % modulus.value, size=size)

        # to avoid mul overflow
        newsize = size * 2
        self_ext = HalmosBitVec(self, size=newsize)
        other_ext = HalmosBitVec(other, size=newsize)
        mod_ext = HalmosBitVec(modulus, size=newsize)

        r1 = self_ext.mul(other_ext, abstraction=mul_abstraction)
        r2 = r1.mod(mod_ext, abstraction=mod_abstraction)

        if r1.size != newsize:
            raise ValueError(r1)

        if r2.size != newsize:
            raise ValueError(r2)

        return HalmosBitVec(r2, size=size)

    def signextend(self, size: int) -> "HalmosBitVec":
        # TODO: handle other sizes
        assert self.size == 256

        if size >= 31:
            return self

        # TODO: handle concrete case natively

        bl = (size + 1) * 8
        return HalmosBitVec(
            SignExt(256 - bl, Extract(bl - 1, 0, self.as_z3())), size=256
        )

    def lshl(self, shift: BV) -> "HalmosBitVec":
        """
        Logical left shift
        """

        size = self._size
        shift_amount = shift.value

        if shift.is_concrete:
            if shift_amount == 0:
                return self

            if shift_amount >= size:
                return HalmosBitVec(0, size=size)

        return HalmosBitVec(self._value << shift_amount, size=size)

    def lshr(self, shift: BV) -> "HalmosBitVec":
        """
        Logical right shift
        """

        size = self._size
        shift_amount = shift.value

        if shift.is_concrete:
            if shift_amount == 0:
                return self

            if self.is_concrete:
                return HalmosBitVec(self.value >> shift_amount, size=size)

            if shift_amount >= size:
                return HalmosBitVec(0, size=size)

        return HalmosBitVec(LShR(self.as_z3(), shift.as_z3()), size=size)

    def ashr(self, shift: BV) -> "HalmosBitVec":
        """
        Arithmetic right shift
        """

        # check for no-op
        if shift.is_concrete and shift.value == 0:
            return self

        return HalmosBitVec(self.as_z3() >> shift.value, size=self.size)

    def bitwise_not(self) -> BV:
        if self.is_concrete:
            return HalmosBitVec(~self._value & ((1 << self._size) - 1), size=self._size)

        return HalmosBitVec(~self.as_z3(), size=self.size)

    def bitwise_and(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value & other._value, size=self._size)

    def bitwise_or(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value | other._value, size=self._size)

    def bitwise_xor(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value ^ other._value, size=self._size)

    def ult(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            return HalmosBool(self.value < other.value)

        return HalmosBool(ULT(self.as_z3(), other.as_z3()))

    def ugt(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if not self._symbolic and not other._symbolic:
            return TRUE if self.value > other.value else FALSE

        return HalmosBool(UGT(self.as_z3(), other.as_z3()))

    def slt(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            left = to_signed(self._value, self._size)
            right = to_signed(other._value, other._size)
            return HalmosBool(left < right)

        return HalmosBool(self.as_z3() < other.as_z3())

    def sgt(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            left = to_signed(self._value, self._size)
            right = to_signed(other._value, other._size)
            return HalmosBool(left > right)

        return HalmosBool(self.as_z3() > other.as_z3())

    def ule(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            return HalmosBool(self.value <= other.value)

        return HalmosBool(ULE(self.as_z3(), other.as_z3()))

    def uge(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            return HalmosBool(self.value >= other.value)

        return HalmosBool(UGE(self.as_z3(), other.as_z3()))

    def eq(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value == other._value)

    def byte(self, idx: int, *, output_size: int = 8) -> BV:
        """
        Extract a byte from the bitvector.

        Args:
            idx: the index of the byte to extract, 0 is the most significant byte
            output_size: the size of the output bitvector, default is 8

        Requires:
            - idx >= 0
            - size to be a multiple of 8
        """

        size = self._size
        byte_length = size // 8

        assert size == byte_length * 8
        assert idx >= 0

        if idx >= byte_length:
            return HalmosBitVec(0, size=output_size)

        if self.is_concrete:
            b = self._value.to_bytes(length=byte_length, byteorder="big")
            return HalmosBitVec(b[idx], size=output_size)

        # symbolic case
        lo = (byte_length - 1 - idx) * 8
        hi = lo + 7
        return HalmosBitVec(
            Extract(hi, lo, self._value),
            size=output_size,
        )


# initialize global constants
TRUE = object.__new__(HalmosBool)
FALSE = object.__new__(HalmosBool)
TRUE.con_val = True
TRUE.sym_val = None
FALSE.con_val = False
FALSE.sym_val = None

ZERO = HalmosBitVec(0, size=256)
ONE = HalmosBitVec(1, size=256)
