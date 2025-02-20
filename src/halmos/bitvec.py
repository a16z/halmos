from typing import TypeAlias, Union

from z3 import (
    And,
    BitVecRef,
    BitVecVal,
    BoolRef,
    BoolVal,
    Extract,
    If,
    Not,
    Or,
    UDiv,
    URem,
    ZeroExt,
    is_bv_value,
    simplify,
)

from halmos.exceptions import NotConcreteError

BV: TypeAlias = "HalmosBitVec"
AnyValue: TypeAlias = Union[int, bytes, BitVecRef, BV, "HalmosBool"]
BVValue: TypeAlias = int | BitVecRef
MaybeSize: TypeAlias = int | None

AnyBool: TypeAlias = bool | BoolRef


def as_int(value: AnyValue) -> tuple[BVValue, MaybeSize]:
    if isinstance(value, int):
        return value, None
    elif isinstance(value, bytes):
        return int.from_bytes(value, "big"), len(value) * 8
    elif is_bv_value(value):
        return value.as_long(), value.size()
    elif isinstance(value, HalmosBitVec):
        return value.value, value.size
    elif isinstance(value, BitVecRef):
        return value, value.size()
    elif isinstance(value, HalmosBool):
        return value.value, 1
    else:
        raise TypeError(f"Cannot convert {type(value)} to int")


class HalmosBool:
    __slots__ = ("_value", "_symbolic")

    def __new__(cls, value):
        if isinstance(value, HalmosBool):
            return value
        return super().__new__(cls)

    def __init__(self, value: AnyBool):
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
    def symbolic(self) -> bool:
        return self._symbolic

    @property
    def value(self) -> AnyBool:
        return self._value

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

    def __and__(self, other: AnyValue) -> "HalmosBool":
        return (
            HalmosBool(And(self._value, other))
            if self._symbolic
            else HalmosBool(self._value and other)
        )

    def __rand__(self, other: AnyValue) -> "HalmosBool":
        return (
            HalmosBool(And(other, self._value))
            if self._symbolic
            else HalmosBool(other and self._value)
        )

    def __or__(self, other: AnyValue) -> "HalmosBool":
        return (
            HalmosBool(Or(self._value, other))
            if self._symbolic
            else HalmosBool(self._value or other)
        )

    def __ror__(self, other: AnyValue) -> "HalmosBool":
        return (
            HalmosBool(Or(other, self._value))
            if self._symbolic
            else HalmosBool(other or self._value)
        )

    def as_bv(self, size: int = 1) -> BV:
        if self._symbolic:
            expr = If(self._value, BitVecVal(1, size), BitVecVal(0, size))
            return HalmosBitVec(expr, size)

        return HalmosBitVec(int(self._value), size)


class HalmosBitVec:
    __slots__ = ("_value", "_symbolic", "_size")

    def __new__(cls, value, size=None):
        # fast path for existing HalmosBitVec of same size
        if isinstance(value, HalmosBitVec):
            size = size or value._size
            if size == value._size:
                return value

        # otherwise, proceed with normal allocation
        instance = super().__new__(cls)
        return instance

    def __init__(
        self, value: AnyValue, size: MaybeSize = None, do_simplify: bool = True
    ):
        """
        Create a new HalmosBitVec from an integer, bytes, or a z3 BitVecRef.

        If the value is too large for the bit size, it will be truncated.

        If do_simplify is True, the value will be simplified using z3's simplify function.
        """

        # first, coerce int-like values to int
        value, maybe_size = as_int(value)
        size = size or (maybe_size or 256)
        self._size = size

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
    def symbolic(self) -> bool:
        return self._symbolic

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
        return f"HalmosBitVec({self._value}, {self._size})"

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
            return HalmosBitVec(self._value + other._value, size)

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
        return HalmosBitVec(self._value + other_value, size)

    def __radd__(self, other: AnyValue) -> BV:
        return self.__add__(other)

    def __sub__(self, other: AnyValue) -> "HalmosBitVec":
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(self._value - other._value, size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        # If other_value == 0, result is just self
        if isinstance(other_value, int) and other_value == 0:
            return self

        return HalmosBitVec(self._value - other_value, size)

    def __rsub__(self, other: AnyValue) -> "HalmosBitVec":
        # (other - self)
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            return HalmosBitVec(other._value - self._value, size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        return HalmosBitVec(other_value - self._value, size)

    def __mul__(self, other: AnyValue) -> "HalmosBitVec":
        size = self._size

        if isinstance(other, HalmosBitVec):
            assert size == other._size
            if not other._symbolic and other._value == 1:
                return self
            return HalmosBitVec(self._value * other._value, size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        # If we multiply by 1, no new object needed
        if isinstance(other_value, int) and other_value == 1:
            return self

        return HalmosBitVec(self._value * other_value, size)

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
            return HalmosBitVec(UDiv(self._value, other._value), size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if other_value == 0:
                raise ZeroDivisionError("division by zero")
            return HalmosBitVec(self._value // other_value, size)
        else:
            # symbolic
            return HalmosBitVec(UDiv(self._value, other_value), size)

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
            return HalmosBitVec(other_value // self._value, size)
        else:
            return HalmosBitVec(UDiv(other_value, self._value), size)

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
            return HalmosBitVec(URem(self._value, other._value), size)

        other_value, other_size = as_int(other)
        assert other_size is None or other_size == size

        if isinstance(other_value, int):
            if other_value == 0:
                raise ZeroDivisionError("mod by zero")
            return HalmosBitVec(self._value % other_value, size)
        else:
            return HalmosBitVec(URem(self._value, other_value), size)

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
            return HalmosBitVec(other_value % self._value, size)
        else:
            return HalmosBitVec(URem(other_value, self._value), size)

    # Shifts
    def __lshift__(self, shift: AnyValue) -> "HalmosBitVec":
        """
        Logical left shift by shift bits.
        Python's << does this for ints,
        for symbolic you might do self._value << shift.
        """
        size = self._size

        if isinstance(shift, HalmosBitVec):
            assert size == shift._size
            # if shift._value == 0 and is concrete => return self
            if not shift._symbolic and shift._value == 0:
                return self
            return HalmosBitVec(self._value << shift._value, size)

        shift_value, shift_size = as_int(shift)
        assert shift_size is None or shift_size == size

        if isinstance(shift_value, int) and shift_value == 0:
            return self

        return HalmosBitVec(self._value << shift_value, size)

    def __rshift__(self, shift: AnyValue) -> "HalmosBitVec":
        """
        Logical right shift by shift bits.
        Python's >> is an arithmetic shift for negative ints,
        but if we're dealing with unsigned logic, mask out as needed.
        For Z3, use LShR if you want a logical shift: LShR(a, b).
        """
        size = self._size

        if isinstance(shift, HalmosBitVec):
            assert size == shift._size
            if not shift._symbolic and shift._value == 0:
                return self
            # for symbolic, might want z3.LShR
            # if you stored it in self._value, do that:
            from z3 import LShR

            return HalmosBitVec(LShR(self._value, shift._value), size)

        shift_value, shift_size = as_int(shift)
        assert shift_size is None or shift_size == size

        if isinstance(shift_value, int) and shift_value == 0:
            return self

        # for concrete
        if isinstance(shift_value, int):
            # plain Python >> does an arithmetic shift if self._value < 0, but presumably we treat as unsigned
            # so do standard python right shift for positives or mask out if needed
            return HalmosBitVec(self._value >> shift_value, size)
        else:
            # symbolic shift
            from z3 import LShR

            return HalmosBitVec(LShR(self._value, shift_value), size)

    def __rlshift__(self, shift: AnyValue) -> "HalmosBitVec":
        """
        shift << self
        """
        # same pattern as other r-operations
        if isinstance(shift, HalmosBitVec):
            assert shift._size == self._size
            return shift.__lshift__(self)
        # fallback
        shift_value, shift_size = as_int(shift)
        # just do shift_value << self._value
        # careful about symbolic
        return HalmosBitVec(shift_value << self._value, self._size)

    def __rrshift__(self, shift: AnyValue) -> "HalmosBitVec":
        """
        shift >> self
        """
        if isinstance(shift, HalmosBitVec):
            assert shift._size == self._size
            return shift.__rshift__(self)
        shift_value, shift_size = as_int(shift)
        # do shift_value >> self._value
        from z3 import LShR

        return HalmosBitVec(LShR(shift_value, self._value), self._size)

    def ult(self, other: BV) -> HalmosBool:
        assert self._size == other._size
        return HalmosBool(self._value < other._value)

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
