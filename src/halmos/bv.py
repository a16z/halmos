# SPDX-License-Identifier: AGPL-3.0

import z3

from enum import Enum
from dataclasses import dataclass, field
from typing import Tuple, Union

Op = Enum(
    "Op",
    [
        "ADD", "SUB", "MUL", "SDIV", "UDIV", "SMOD", "SREM", "UREM",
        "EQ", "NEQ", "BV_AND", "BV_OR", "BV_XOR", "BV_NOT", "SHL", "ASHR", "LSHR",
        "SLE", "ULE", "SLT", "ULT", "SGE", "UGE", "SGT", "UGT",
        "CONCAT", "EXTRACT", "SIGNEXT", "ZEROEXT",
        "SELECT", "STORE",
        "IF", "IMPLIES", "AND", "OR", "XOR", "NOT",
    ]
)

class Term:
    pass

@dataclass(frozen=True)
class Val(Term):
    value: Union[int, bytes]
    size: int

    def __post_init__(self):
        assert_type(self.value, int, bytes)
        assert_type(self.size, int)

#   def as_long(self):
#       if isinstance(self.value, bytes):
#           return int.from_bytes(self.value, "big")
#       return self.value

@dataclass(frozen=True)
class Var(Term):
    name: str
    size: int

    def __post_init__(self):
        assert_type(self.name, str)
        assert_type(self.size, int)

@dataclass(frozen=True)
class Arr(Term):
    name: str
    sig: Tuple[z3.BitVecSortRef]

    def __post_init__(self):
        assert_type(self.name, str)
        assert_type(self.sig, Tuple)

@dataclass(frozen=True)
class Fun(Term):
    name: str
    sig: Tuple[z3.BitVecSortRef]

    def __post_init__(self):
        assert_type(self.name, str)
        assert_type(self.sig, Tuple)

@dataclass(frozen=True)
class Exp(Term):
    op: Op
    args: Tuple[Term]
    size: int

    def __post_init__(self):
        assert_type(self.op, Op)
        assert_type(self.args, Tuple)
        if self.size:
            assert_type(self.size, int)
        elif self.op != Op.STORE:
            raise ValueError(self)


@dataclass(frozen=True)
class App(Term):
    fun: Fun
    args: Tuple[Term]
    size: int

    def __post_init__(self):
        assert_type(self.fun, Fun)
        assert_type(self.args, Tuple)
        assert_type(self.size, int)


def Function(name, *sig):
    return FuncDeclRef(
        term = Fun(name, tuple(sig)),
        smt = z3.Function(name, *sig),
    )

@dataclass(frozen=True)
class FuncDeclRef:
    term: Term
    smt: z3.FuncDeclRef

    def __post_init__(self):
        assert_type(self.term, Term)
        assert_type(self.smt, z3.FuncDeclRef)

    def name(self):
        return self.smt.name()

    def __call__(self, *args):
        return BitVecRef(
            term = App(self.term, tuple(arg.term for arg in args), self.term.sig[-1].size()),
            smt = self.smt.__call__(*[arg.smt for arg in args]),
        )


@dataclass(eq=False, frozen=True)
class ExprRef:
    def sort(self):
        return self.smt.sort()

    def params(self):
        return self.smt.params()

    def decl(self):
        return self.smt.decl()

    def num_args(self):
        return self.smt.num_args()

    def arg(self, idx):
        return self.smt.arg(idx)

    def children(self):
        return self.smt.children()

    def __eq__(self, other):
        return BoolRef(
            term = Exp(Op.EQ, (self.term, other.term), 1),
            smt = self.smt.__eq__(other.smt),
        )

    def __ne__(self, other):
        return BoolRef(
            term = Exp(Op.NEQ, (self.term, other.term), 1),
            smt = self.smt.__ne__(other.smt),
        )

    def __hash__(self):
        return self.smt.hash()


def Array(name, *sorts):
    return ArrayRef(
        term = Arr(name, tuple(sorts)),
        smt = z3.Array(name, *sorts),
    )

@dataclass(eq=False, frozen=True)
class ArrayRef(ExprRef):
    term: Term
    smt: z3.ArrayRef

    def __post_init__(self):
        assert_type(self.term, Term)
        assert_type(self.smt, z3.ArrayRef)

    def sort(self):
        return self.smt.sort()

def Store(a, *args):
    return ArrayRef(
        term = Exp(Op.STORE, (a.term, args[0].term, args[1].term), None),
        smt = z3.Store(a.smt, *[arg.smt for arg in args]),
    )

def Select(a, *args):
    return BitVecRef(
        term = Exp(Op.SELECT, (a.term, args[0].term), a.term.range_size),
        smt = z3.Select(a.smt, *[arg.smt for arg in args]),
    )




@dataclass(eq=False, frozen=True)
class BoolRef(ExprRef):
    term: Term
    smt: z3.BoolRef

    def __post_init__(self):
        assert_type(self.term, Term)
        assert_type(self.smt, z3.BoolRef)

        if self.term.size != 1:
            raise ValueError(self)


def is_bool(a):
    return isinstance(a, BoolRef)

def is_true(a):
    return isinstance(a, BoolRef) and z3.is_true(a.smt)

def is_false(a):
    return isinstance(a, BoolRef) and z3.is_false(a.smt)


def BitVecSort(sz, ctx=None):
    return z3.BitVecSort(sz, ctx)


def BitVec(name, bv, ctx=None):
    if isinstance(bv, int):
        size = bv
    elif isinstance(bv, z3.BitVecSortRef):
        size = bv.size()
    else:
        raise ValueError(bv)

    return BitVecRef(
        term = Var(name, size),
        smt = z3.BitVec(name, size, ctx)
    )

def BitVecVal(val, bv, ctx=None):
    if isinstance(bv, int):
        size = bv
    elif isinstance(bv, z3.BitVecSortRef):
        size = bv.size()
    else:
        raise ValueError(bv)

    return BitVecRef(
        term = Val(val, size),
        smt = z3.BitVecVal(val, size, ctx),
    )

@dataclass(eq=False, frozen=True)
class BitVecRef(ExprRef):
    term: Term
    smt: z3.BitVecRef

    def __post_init__(self):
        assert_type(self.term, Term)
        assert_type(self.smt, z3.BitVecRef)

        if self.term.size != self.smt.size():
            raise ValueError(self)

    def as_long(self):
        return self.smt.as_long()

    def as_signed_long(self):
        return self.smt.as_signed_long()

    def size(self):
        return self.smt.size()

    def __add__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.ADD, (self.term, other.term), size),
            smt = self.smt.__add__(other.smt),
        )

    def __sub__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.SUB, (self.term, other.term), size),
            smt = self.smt.__sub__(other.smt),
        )

    def __mul__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.MUL, (self.term, other.term), size),
            smt = self.smt.__mul__(other.smt),
        )

    def __div__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.SDIV, (self.term, other.term), size),
            smt = self.smt.__div__(other.smt),
        )

    def __truediv__(self, other):
        return self.__div__(other)

    def __mod__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.SMOD, (self.term, other.term), size),
            smt = self.smt.__mod__(other.smt),
        )

    def __and__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.BV_AND, (self.term, other.term), size),
            smt = self.smt.__and__(other.smt),
        )

    def __or__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.BV_OR, (self.term, other.term), size),
            smt = self.smt.__or__(other.smt),
        )

    def __xor__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.BV_XOR, (self.term, other.term), size),
            smt = self.smt.__xor__(other.smt),
        )

    def __invert__(self):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.BV_NOT, (self.term,), size),
            smt = self.smt.__invert__(),
        )

    def __lshift__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.SHL, (self.term, other.term), size),
            smt = self.smt.__lshift__(other.smt),
        )

    def __rshift__(self, other):
        size = self.term.size
        return BitVecRef(
            term = Exp(Op.ASHR, (self.term, other.term), size),
            smt = self.smt.__rshift__(other.smt),
        )

    def __le__(self, other):
        return BoolRef(
            term = Exp(Op.SLE, (self.term, other.term), 1),
            smt = self.smt.__le__(other.smt),
        )

    def __lt__(self, other):
        return BoolRef(
            term = Exp(Op.SLT, (self.term, other.term), 1),
            smt = self.smt.__lt__(other.smt),
        )

    def __ge__(self, other):
        return BoolRef(
            term = Exp(Op.SGE, (self.term, other.term), 1),
            smt = self.smt.__ge__(other.smt),
        )

    def __gt__(self, other):
        return BoolRef(
            term = Exp(Op.SGT, (self.term, other.term), 1),
            smt = self.smt.__gt__(other.smt),
        )

def UDiv(a, b):
    size = a.term.size
    return BitVecRef(
        term = Exp(Op.UDIV, (a.term, b.term), size),
        smt = z3.UDiv(a.smt, b.smt),
    )

def SRem(a, b):
    size = a.term.size
    return BitVecRef(
        term = Exp(Op.SREM, (a.term, b.term), size),
        smt = z3.SRem(a.smt, b.smt),
    )

def URem(a, b):
    size = a.term.size
    return BitVecRef(
        term = Exp(Op.UREM, (a.term, b.term), size),
        smt = z3.URem(a.smt, b.smt),
    )

def LShR(a, b):
    size = a.term.size
    return BitVecRef(
        term = Exp(Op.LSHR, (a.term, b.term), size),
        smt = z3.LShR(a.smt, b.smt),
    )

def ULE(a, b):
    return BoolRef(
        term = Exp(Op.ULE, (a.term, b.term), 1),
        smt = z3.ULE(a.smt, b.smt),
    )

def ULT(a, b):
    return BoolRef(
        term = Exp(Op.ULT, (a.term, b.term), 1),
        smt = z3.ULT(a.smt, b.smt),
    )

def UGE(a, b):
    return BoolRef(
        term = Exp(Op.UGE, (a.term, b.term), 1),
        smt = z3.UGE(a.smt, b.smt),
    )

def UGT(a, b):
    return BoolRef(
        term = Exp(Op.UGT, (a.term, b.term), 1),
        smt = z3.UGT(a.smt, b.smt),
    )

def Concat(*args):
    size = 0
    for arg in args:
        size += arg.term.size

    return BitVecRef(
        term = Exp(Op.CONCAT, tuple(arg.term for arg in args), size),
        smt = z3.Concat(*[arg.smt for arg in args]),
    )

def Extract(high, low, a):
    size = high - low + 1
    return BitVecRef(
        term = Exp(Op.EXTRACT, (high, low, a.term), size),
        smt = z3.Extract(high, low, a.smt),
    )

def is_bv(a):
    return isinstance(a, BitVecRef)

def is_bv_value(a):
    return isinstance(a, BitVecRef) and z3.is_bv_value(a.smt)


def eq(a, b):
    if isinstance(a, BoolRef) or isinstance(a, BitVecRef):
        a = a.smt
    if isinstance(b, BoolRef) or isinstance(b, BitVecRef):
        b = b.smt
    return z3.eq(a, b)

def If(a, b, c, ctx=None):
    size = b.term.size
    return BitVecRef(
        term = Exp(Op.IF, (a.term, b.term, c.term), size),
        smt = z3.If(a.smt, b.smt, c.smt, ctx),
    )

def Implies(a, b, ctx=None):
    return BoolRef(
        term = Exp(Op.IMPLIES, (a.term, b.term), 1),
        smt = z3.Implies(a.smt, b.smt, ctx),
    )

def And(*args):
    return BoolRef(
        term = Exp(Op.AND, tuple(arg.term for arg in args), 1),
        smt = z3.And(*[arg.smt for arg in args]),
    )

def Or(*args):
    return BoolRef(
        term = Exp(Op.OR, tuple(arg.term for arg in args), 1),
        smt = z3.Or(*[arg.smt for arg in args]),
    )

def Xor(a, b, ctx=None):
    return BoolRef(
        term = Exp(Op.XOR, (a.term, b.term), 1),
        smt = z3.Xor(a.smt, b.smt, ctx),
    )

def Not(a, ctx=None):
    return BoolRef(
        term = Exp(Op.NOT, (a.term,), 1),
        smt = z3.Not(a.smt, ctx),
    )

def SignExt(n, a):
    size = n + a.term.size
    return BitVecRef(
        term = Exp(Op.SIGNEXT, (n, a.term), size),
        smt = z3.SignExt(n, a.smt),
    )

def ZeroExt(n, a):
    size = n + a.term.size
    return BitVecRef(
        term = Exp(Op.ZEROEXT, (n, a.term), size),
        smt = z3.ZeroExt(n, a.smt),
    )

def simplify(a, *arguments, **keywords):
    if isinstance(a, BoolRef):
        return BoolRef(
            term = a.term,
            smt = z3.simplify(a.smt, *arguments, **keywords)
        )
    elif isinstance(a, BitVecRef):
        return BitVecRef(
            term = a.term,
            smt = z3.simplify(a.smt, *arguments, **keywords)
        )
    else:
        raise ValueError(a)



def assert_type(exp, *types):
    for typ in types:
        if isinstance(exp, typ):
            return

    raise ValueError(exp, types)

# x = BitVec('x', 32)
# c = BitVecVal(1, 32)
# a = Array('a', BitVecSort(32), BitVecSort(32))
# f = Function('f', BitVecSort(32), BitVecSort(32))
# #print(Store(a, x, c))
# print(f(x))
