from typing import TypeAlias

from z3 import (
    ULT,
    And,
    BitVecRef,
    BitVecVal,
    BoolRef,
    BoolVal,
    Extract,
    FuncDeclRef,
    If,
    LShR,
    Not,
    Or,
    UDiv,
    URem,
    ZeroExt,
    eq,
    is_bv_value,
    simplify,
)

from halmos.exceptions import NotConcreteError

BV: TypeAlias = "HalmosBitVec"
AnyValue: TypeAlias = "int | bytes | BitVecRef | BV | HalmosBool"
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


# TODO: HalmosBool.TRUE, HalmosBool.FALSE
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
    - halmos_bool.wrapped() always converts to a z3 BoolRef
    - bool(halmos_bool) converts to a concrete bool, raises if symbolic
    - halmos_bool.value/unwrap() returns the underlying bool or z3 BoolRef
    """

    __slots__ = ("_value", "_symbolic")

    def __new__(cls, value):
        if isinstance(value, HalmosBool):
            return value

        return super().__new__(cls)

    def __init__(self, value: AnyBool):
        # avoid reinitializing HalmosBool because of __new__ shortcut
        if isinstance(value, HalmosBool):
            return

        self._value = value
        if isinstance(value, bool):
            self._symbolic = False
        elif isinstance(value, BoolRef):
            self._symbolic = True
        else:
            raise TypeError(f"Cannot create HalmosBool from {type(value)}")

    def __bool__(self) -> bool:
        if self._symbolic:
            raise NotConcreteError("Cannot convert symbolic bool to bool")
        return self._value

    def __repr__(self) -> str:
        return f"HalmosBool({self._value})"

    def __str__(self) -> str:
        return str(self._value)

    def __int__(self) -> int:
        return int(bool(self))

    def __deepcopy__(self, memo):
        return self

    def wrapped(self) -> BoolRef:
        if self._symbolic:
            return self._value
        return BoolVal(self._value)

    def unwrap(self) -> AnyBool:
        return self._value

    @property
    def is_symbolic(self) -> bool:
        return self._symbolic

    @property
    def is_concrete(self) -> bool:
        return not self._symbolic

    @property
    def value(self) -> AnyBool:
        return self._value

    @property
    def is_true(self) -> bool:
        return self.is_concrete and self._value

    @property
    def is_false(self) -> bool:
        return self.is_concrete and not self._value

    def is_zero(self) -> "HalmosBool":
        return self

    def is_non_zero(self) -> "HalmosBool":
        return self.neg()

    def neg(self) -> "HalmosBool":
        return (
            HalmosBool(Not(self._value))
            if self._symbolic
            else HalmosBool(not self._value)
        )

    def eq(self, other: "HalmosBool") -> "HalmosBool":
        return HalmosBool(self._value == other._value)

    def __and__(self, other: "HalmosBool") -> "HalmosBool":
        if self.is_true and other.is_true:
            return HalmosBool(True)
        elif self.is_false or other.is_false:
            return HalmosBool(False)
        else:
            return HalmosBool(And(self.wrapped(), other.wrapped()))

    def __or__(self, other: AnyValue) -> "HalmosBool":
        if self.is_true or other.is_true:
            return HalmosBool(True)
        elif self.is_false and other.is_false:
            return HalmosBool(False)
        else:
            return HalmosBool(Or(self.wrapped(), other.wrapped()))

    def as_bv(self, size: int = 1) -> BV:
        if self._symbolic:
            expr = If(self._value, BitVecVal(1, size), BitVecVal(0, size))
            return HalmosBitVec(expr, size=size)

        return HalmosBitVec(int(self._value), size)


class HalmosBitVec:
    """
    Immutable wrapper for concrete or symbolic bitvectors.

    Can be constructed with:
    - HalmosBitVec(42) # int
    - HalmosBitVec(bytes.fromhex("12345678")) # bytes
    - HalmosBitVec(BitVecVal(42, 8)) # BitVecVal
    - HalmosBitVec(BitVec(x, 8)) # BitVecRef
    - HalmosBitVec(halmos_bool) # HalmosBool

    Conversion to and from HalmosBool:
    - HalmosBitVec(halmos_bool) (same as halmos_bool.as_bv())
    - HalmosBool(halmos_bitvec) (same as halmos_bitvec.is_non_zero())

    Wrapping/unwrapping:
    - halmos_bitvec.wrapped() always converts to a z3 BitVecRef
    - int(halmos_bitvec) converts to a concrete int, raises if symbolic
    - halmos_bitvec.value/unwrap() returns the underlying int or z3 BitVecRef
    """

    __slots__ = ("_value", "_symbolic", "_size")

    def __new__(cls, value, size=None):
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

        If do_simplify is True, the value will be simplified using z3's simplify function.
        """

        # avoid reinitializing HalmosBitVec because of __new__ shortcut
        if isinstance(value, HalmosBitVec):
            return

        # unwrap HalmosBool
        if isinstance(value, HalmosBool):
            value = value.unwrap()

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
            self._symbolic = True

            if size < value.size():
                value = Extract(size - 1, 0, value)
            elif size > value.size():
                value = ZeroExt(size - value.size(), value)

            self._value = simplify(value) if do_simplify else value
        else:
            raise TypeError(f"Cannot create HalmosBitVec from {type(value)}")

    def __deepcopy__(self, memo):
        # yay immutability
        return self

    @property
    def size(self) -> int:
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

    def wrapped(self) -> BitVecRef:
        if self._symbolic:
            return self._value
        return BitVecVal(self._value, self._size)

    def unwrap(self) -> int | BitVecRef:
        return self._value

    def __int__(self) -> int:
        if self._symbolic:
            if is_bv_value(self._value):
                return self._value.as_long()
            raise NotConcreteError("Cannot convert symbolic bitvec to int")

        return self._value

    def __repr__(self) -> str:
        return (
            f"HalmosBitVec({self._value}, {self._size})"
            if self._size != 256
            else f"{self._value}"
        )

    def __str__(self) -> str:
        return str(self._value)

    def __hex__(self) -> str:
        raise NotImplementedError("Hex representation not implemented")

    def is_zero(self) -> HalmosBool:
        # works for both symbolic and concrete
        return HalmosBool(self._value == 0)

    def is_non_zero(self) -> HalmosBool:
        # works for both symbolic and concrete
        return HalmosBool(self._value != 0)

    #
    # operations
    #

    def __add__(self, other: AnyValue) -> BV:
        size = self._size

        # check the fast path (most common case) first:
        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(self._value + other._value, size=size)

        # otherwise, attempt to convert the other value to an int
        other_value, other_size = as_int(other)

        # if the other value has a known size, it must match the size of self
        assert size == other_size if other_size is not None else True

        # if the other value is zero, we don't need to create a new object
        if isinstance(other_value, int) and other_value == 0:
            return self

        # cases:
        # - concrete + concrete may overflow, will be masked in the constructor
        # - any combination of symbolic and concrete is symbolic, handled by z3 module
        return HalmosBitVec(self._value + other_value, size=size)

    def __radd__(self, other: AnyValue) -> BV:
        return self.__add__(other)

    def __sub__(self, other: AnyValue) -> "HalmosBitVec":
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(self._value - other._value, size=size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        # If other_value == 0, result is just self
        if isinstance(other_value, int) and other_value == 0:
            return self

        return HalmosBitVec(self._value - other_value, size=size)

    def __rsub__(self, other: AnyValue) -> "HalmosBitVec":
        # (other - self)
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(other._value - self._value, size=size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        return HalmosBitVec(other_value - self._value, size=size)

    def __mul__(self, other: BV) -> "HalmosBitVec":
        return self.mul(other)

    def mul(
        self, other: BV, *, abstraction: FuncDeclRef | None = None
    ) -> "HalmosBitVec":
        size = self._size
        assert size == other.size

        lhs, rhs = self.value, other.value
        print(f"{self=}, {other=}")

        match (self.is_concrete, other.is_concrete):
            case (True, True):
                return HalmosBitVec(lhs * rhs, size=size)

            case (True, False):
                if lhs == 0:
                    return self

                if lhs == 1:
                    return other

                if is_power_of_two(lhs):
                    return other << (lhs.bit_length() - 1)

            case (False, True):
                if rhs == 0:
                    return other

                if rhs == 1:
                    return self

                if is_power_of_two(rhs):
                    return self << (rhs.bit_length() - 1)

        return (
            HalmosBitVec(lhs * rhs, size=size)
            if abstraction is None
            else HalmosBitVec(abstraction(lhs, rhs), size=size)
        )

    def __rmul__(self, other: AnyValue) -> "HalmosBitVec":
        # just reuse __mul__
        return self.__mul__(other)

    def __floordiv__(self, other: AnyValue) -> "HalmosBitVec":
        """
        For bitvectors, you might want unsigned or signed division.
        This example uses Python's floor division for concrete, or
        z3's UDiv for symbolic (if you want unsigned).
        Adapt as needed.
        """
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(UDiv(self._value, other._value), size=size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if other_value == 0:
                raise ZeroDivisionError("division by zero")
            return HalmosBitVec(self._value // other_value, size=size)
        else:
            # symbolic
            return HalmosBitVec(UDiv(self._value, other_value), size=size)

    def __rfloordiv__(self, other: AnyValue) -> "HalmosBitVec":
        """
        other // self
        """
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(UDiv(other._value, self._value), size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if self._symbolic:
                # either raise or produce symbolic expression if you like
                pass
            if self._value == 0:
                raise ZeroDivisionError("division by zero")
            return HalmosBitVec(other_value // self._value, size=size)
        else:
            return HalmosBitVec(UDiv(other_value, self._value), size=size)

    # If you also want __truediv__, just do the same pattern
    # or alias it to __floordiv__ as desired.

    def __mod__(self, other: AnyValue) -> "HalmosBitVec":
        """
        same pattern for a remainder operation
        for z3, you'd typically use URem (for unsigned).
        """
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(URem(self._value, other._value), size=size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if other_value == 0:
                raise ZeroDivisionError("mod by zero")
            return HalmosBitVec(self._value % other_value, size=size)
        else:
            return HalmosBitVec(URem(self._value, other_value), size=size)

    def __rmod__(self, other: AnyValue) -> "HalmosBitVec":
        """
        other % self
        """
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(URem(other._value, self._value), size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if self._value == 0:
                raise ZeroDivisionError("mod by zero")
            return HalmosBitVec(other_value % self._value, size=size)
        else:
            return HalmosBitVec(URem(other_value, self._value), size=size)

    # Shifts
    def __lshift__(self, shift: AnyValue) -> "HalmosBitVec":
        """
        Logical left shift
        """
        size = self._size

        if isinstance(shift, HalmosBitVec):
            assert size == shift._size
            # if shift._value == 0 and is concrete => return self
            if not shift._symbolic and shift._value == 0:
                return self
            return HalmosBitVec(self._value << shift._value, size=size)

        shift_value, shift_size = as_int(shift)
        assert shift_size is None or shift_size == size

        if isinstance(shift_value, int) and shift_value == 0:
            return self

        return HalmosBitVec(self._value << shift_value, size=size)

    def __rshift__(self, shift: AnyValue) -> "HalmosBitVec":
        raise NotImplementedError("ambiguous, use lshr or ashr")

    def lshr(self, shift: BV) -> "HalmosBitVec":
        """
        Logical right shift
        """

        size = self._size

        # check for no-op
        if shift.is_concrete:
            if shift.value == 0:
                return self

            if shift.value >= size:
                return HalmosBitVec(0, size=size)

        return HalmosBitVec(LShR(self.wrapped(), shift.wrapped()), size=size)

    def ashr(self, shift: BV) -> "HalmosBitVec":
        """
        Arithmetic right shift
        """

        # check for no-op
        if shift.is_concrete and shift.value == 0:
            return self

        return HalmosBitVec(self.wrapped() >> shift.value, size=self.size)

    def __invert__(self) -> BV:
        # TODO: handle concrete case
        return HalmosBitVec(~self.wrapped(), size=self.size)

    def __eq__(self, other: BV) -> bool:
        if self.is_symbolic and other.is_symbolic:
            return self.size == other.size and eq(self.value, other.value)

        if self.is_concrete and other.is_concrete:
            return self.size == other.size and self.value == other.value

        return False

    def ult(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            return HalmosBool(self.value < other.value)

        return HalmosBool(ULT(self.wrapped(), other.wrapped()))

    def slt(self, other: BV) -> HalmosBool:
        assert self._size == other._size

        if self.is_concrete and other.is_concrete:
            left = to_signed(self._value, self._size)
            right = to_signed(other._value, other._size)
            return HalmosBool(left < right)

        return HalmosBool(self.wrapped() < other.wrapped())

    def ugt(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value > other._value)

    def ule(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value <= other._value)

    def uge(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value >= other._value)

    def eq(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value == other._value)

    def __and__(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value & other._value, size=self._size)

    def __or__(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value | other._value, size=self._size)

    def __xor__(self, other: BV) -> BV:
        assert self._size == other._size
        return HalmosBitVec(self._value ^ other._value, size=self._size)
