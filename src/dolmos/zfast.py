# SPDX-License-Identifier: AGPL-3.0

"""Interned terms: one Python object per z3 term, without the overhead of z3py.

z3py creates a new wrapper object for every term it returns, even when the term already
exists, and every call into the library goes through an argument conversion and an error
check written in Python. Symbolic execution creates and inspects a very large number of
small terms, so that overhead ends up dominating the time spent outside the solver.

This module gives the same API as z3py for the functions used by the engine, with:

- hash-consing: z3 already shares structurally identical terms; `_mk()` maps the address
  of a term to a single Python object. Identical terms are therefore identical objects:
  dictionary lookups succeed on identity, without building an equality term
- cached structure: kind, declaration, arguments, size, numeral value, hash and the
  simplified form of a term are computed once per term rather than once per use
- direct calls: terms are built through plain ctypes prototypes taking integers, with a
  null check instead of an error query after every call
- no reference counting from arbitrary threads: a dead object only queues its address,
  and the references are released from the thread that creates terms

The objects are subclasses of the z3py classes, so every z3py function still accepts
them; functions that are not reimplemented here fall back to z3py and their results are
interned on the way out. Terms of other contexts are left to z3py.

Everything is exported, so that `from dolmos.zfast import X` can replace
`from z3 import X`.
"""

import ctypes
import weakref
from ctypes import c_char_p, c_uint, c_void_p

import z3
from z3 import *  # noqa: F403
from z3 import z3core
from z3.z3types import Ast

_MAIN = z3.main_ctx()
_CTX = _MAIN.ref().value

# The objects of z3py (solvers, models, terms that are not interned) are released by
# whichever thread runs Python's garbage collector, possibly while the main thread is
# inside a z3 call, and z3 contexts are not thread-safe: this crashed with a segmentation
# fault. With this flag, z3 queues the releases instead of applying them immediately.
z3core.Z3_enable_concurrent_dec_ref(_MAIN.ref())


def _proto(name, restype, *argtypes):
    """the library function behind z3core.<name>, with a prototype that takes and returns
    plain integers (z3core doesn't keep a reference to the library itself)"""
    address = ctypes.cast(getattr(z3core, name).__defaults__[0].f, c_void_p).value
    return ctypes.CFUNCTYPE(restype, *argtypes)(address)


_P = c_void_p
_inc_ref = _proto("Z3_inc_ref", None, _P, _P)
_dec_ref = _proto("Z3_dec_ref", None, _P, _P)
_get_ast_kind = _proto("Z3_get_ast_kind", c_uint, _P, _P)
_get_ast_hash = _proto("Z3_get_ast_hash", c_uint, _P, _P)
_get_ast_id = _proto("Z3_get_ast_id", c_uint, _P, _P)
_get_sort = _proto("Z3_get_sort", _P, _P, _P)
_get_sort_kind = _proto("Z3_get_sort_kind", c_uint, _P, _P)
_get_bv_sort_size = _proto("Z3_get_bv_sort_size", c_uint, _P, _P)
_get_app_num_args = _proto("Z3_get_app_num_args", c_uint, _P, _P)
_get_app_arg = _proto("Z3_get_app_arg", _P, _P, _P, c_uint)
_get_app_decl = _proto("Z3_get_app_decl", _P, _P, _P)
_get_decl_kind = _proto("Z3_get_decl_kind", c_uint, _P, _P)
_get_numeral_string = _proto("Z3_get_numeral_string", c_char_p, _P, _P)
_simplify = _proto("Z3_simplify", _P, _P, _P)
_mk_bv_sort = _proto("Z3_mk_bv_sort", _P, _P, c_uint)
_mk_numeral = _proto("Z3_mk_numeral", _P, _P, c_char_p, _P)
_mk_string_symbol = _proto("Z3_mk_string_symbol", _P, _P, c_char_p)
_mk_const = _proto("Z3_mk_const", _P, _P, _P, _P)
_mk_app = _proto("Z3_mk_app", _P, _P, _P, c_uint, _P)
_mk_eq = _proto("Z3_mk_eq", _P, _P, _P, _P)
_mk_not = _proto("Z3_mk_not", _P, _P, _P)
_mk_ite = _proto("Z3_mk_ite", _P, _P, _P, _P, _P)
_mk_and = _proto("Z3_mk_and", _P, _P, c_uint, _P)
_mk_or = _proto("Z3_mk_or", _P, _P, c_uint, _P)
_mk_concat = _proto("Z3_mk_concat", _P, _P, _P, _P)
_mk_extract = _proto("Z3_mk_extract", _P, _P, c_uint, c_uint, _P)
_mk_zero_ext = _proto("Z3_mk_zero_ext", _P, _P, c_uint, _P)
_mk_sign_ext = _proto("Z3_mk_sign_ext", _P, _P, c_uint, _P)
_mk_select = _proto("Z3_mk_select", _P, _P, _P, _P)
_mk_store = _proto("Z3_mk_store", _P, _P, _P, _P, _P)
_mk_bvnot = _proto("Z3_mk_bvnot", _P, _P, _P)
_mk_bvneg = _proto("Z3_mk_bvneg", _P, _P, _P)


def _binary(name):
    return _proto(name, _P, _P, _P, _P)


_mk_bvadd = _binary("Z3_mk_bvadd")
_mk_bvsub = _binary("Z3_mk_bvsub")
_mk_bvmul = _binary("Z3_mk_bvmul")
_mk_bvudiv = _binary("Z3_mk_bvudiv")
_mk_bvurem = _binary("Z3_mk_bvurem")
_mk_bvsdiv = _binary("Z3_mk_bvsdiv")
_mk_bvsrem = _binary("Z3_mk_bvsrem")
_mk_bvsmod = _binary("Z3_mk_bvsmod")
_mk_bvand = _binary("Z3_mk_bvand")
_mk_bvor = _binary("Z3_mk_bvor")
_mk_bvxor = _binary("Z3_mk_bvxor")
_mk_bvshl = _binary("Z3_mk_bvshl")
_mk_bvlshr = _binary("Z3_mk_bvlshr")
_mk_bvashr = _binary("Z3_mk_bvashr")
_mk_bvult = _binary("Z3_mk_bvult")
_mk_bvule = _binary("Z3_mk_bvule")
_mk_bvugt = _binary("Z3_mk_bvugt")
_mk_bvuge = _binary("Z3_mk_bvuge")
_mk_bvslt = _binary("Z3_mk_bvslt")
_mk_bvsle = _binary("Z3_mk_bvsle")
_mk_bvsgt = _binary("Z3_mk_bvsgt")
_mk_bvsge = _binary("Z3_mk_bvsge")
_mk_implies = _binary("Z3_mk_implies")
_NUMERAL_AST = z3.Z3_NUMERAL_AST
_APP_AST = z3.Z3_APP_AST
_BOOL_SORT = z3.Z3_BOOL_SORT
_BV_SORT = z3.Z3_BV_SORT
_ARRAY_SORT = z3.Z3_ARRAY_SORT
_OP_TRUE = z3.Z3_OP_TRUE
_OP_FALSE = z3.Z3_OP_FALSE
_OP_EQ = z3.Z3_OP_EQ
_OP_NOT = z3.Z3_OP_NOT

# address of a term -> weak reference to its object
_table: dict[int, weakref.ref] = {}

# declarations and sorts, by address: z3py objects that are never released, so that no
# reference count changes when the garbage collector runs in another thread
_decls: dict[int, z3.FuncDeclRef] = {}
_sorts: dict[int, z3.SortRef] = {}

# addresses of the terms whose object died, to be released by _drain()
_pending: list[int] = []
_DRAIN_THRESHOLD = 4096

_Z3Exception = z3.Z3Exception
_new_ast = Ast.__new__
_init_void_p = c_void_p.__init__


class _Interned:
    """Behaviour shared by the interned term classes; see the module docstring."""

    def __init__(self, *args, **kwargs):
        raise TypeError("interned terms are created by zfast._mk()")

    def __del__(self):
        p = self._p
        ref = _table.get(p)
        if ref is not None:
            # the entry may already belong to a newer object of the same term
            o = ref()
            if o is self or o is None:
                del _table[p]
        _pending.append(p)

    def __deepcopy__(self, memo=None):
        # terms are immutable
        return self

    def __copy__(self):
        return self

    def __hash__(self):
        return self._h

    def hash(self):
        return self._h

    def get_id(self):
        try:
            return self._id
        except AttributeError:
            self._id = r = _get_ast_id(_CTX, self._p)
            return r

    def eq(self, other):
        if other is self:
            return True
        try:
            return self._p == other._p
        except AttributeError:
            return super().eq(other)

    def __eq__(self, other):
        if other is self:
            # the equality term of a term with itself; __bool__ gives True, as z3py does
            return _mk(_mk_eq(_CTX, self._p, self._p))
        try:
            r = _mk_eq(_CTX, self._p, other._p)
        except AttributeError:
            return _wrap(super().__eq__(other))
        if r is None:
            return _wrap(super().__eq__(other))
        return _mk(r)

    def __ne__(self, other):
        return _wrap(super().__ne__(other))

    def __bool__(self):
        k = self._decl_kind()
        if k == _OP_TRUE:
            return True
        if k == _OP_FALSE:
            return False
        if k == _OP_EQ:
            args = self._arguments()
            if len(args) == 2:
                return args[0] is args[1]
        raise _Z3Exception(
            "Symbolic expressions cannot be cast to concrete Boolean values."
        )

    def _kind(self):
        try:
            return self._k
        except AttributeError:
            self._k = r = _get_ast_kind(_CTX, self._p)
            return r

    def _decl_kind(self):
        try:
            return self._dk
        except AttributeError:
            d = _get_app_decl(_CTX, self._p)
            self._dk = r = _get_decl_kind(_CTX, d)
            return r

    def _arguments(self) -> tuple:
        try:
            return self._args
        except AttributeError:
            p = self._p
            n = _get_app_num_args(_CTX, p)
            self._args = r = tuple(_mk(_get_app_arg(_CTX, p, i)) for i in range(n))
            return r

    def decl(self):
        try:
            return self._decl
        except AttributeError:
            d = _get_app_decl(_CTX, self._p)
            r = _decls.get(d)
            if r is None:
                # declarations are few, and kept for the lifetime of the process
                _decls[d] = r = super().decl()
            self._decl = r
            return r

    def num_args(self):
        return len(self._arguments())

    def arg(self, idx):
        return self._arguments()[idx]

    def children(self):
        return list(self._arguments())

    def sort(self):
        try:
            return self._sort
        except AttributeError:
            q = _get_sort(_CTX, self._p)
            r = _sorts.get(q)
            if r is None:
                # as for declarations
                _sorts[q] = r = super().sort()
            self._sort = r
            return r

    def _simplified(self):
        try:
            r = self._simp
        except AttributeError:
            q = _simplify(_CTX, self._p)
            if q is None:
                return _wrap(z3.simplify(self))
            r = _mk(q)
            # no reference cycle when the term is already simplified
            self._simp = None if r is self else r
            return r
        return self if r is None else r


def _coerce(self, other):
    """the address of `other` as an operand of the bitvector `self`, or None"""
    try:
        return other._p
    except AttributeError:
        if type(other) is int:
            return _numeral(other, self.size())
        return None


def _operator(mk, name, reflected=False):
    fallback = getattr(z3.BitVecRef, name)

    def op(self, other):
        q = _coerce(self, other)
        if q is not None:
            r = mk(_CTX, q, self._p) if reflected else mk(_CTX, self._p, q)
            if r is not None:
                return _mk(r)
        return _wrap(fallback(self, other))

    op.__name__ = name
    return op


class _BV(_Interned):
    def size(self):
        try:
            return self._size
        except AttributeError:
            self._size = r = _get_bv_sort_size(_CTX, _get_sort(_CTX, self._p))
            return r

    __add__ = _operator(_mk_bvadd, "__add__")
    __radd__ = _operator(_mk_bvadd, "__radd__", reflected=True)
    __sub__ = _operator(_mk_bvsub, "__sub__")
    __rsub__ = _operator(_mk_bvsub, "__rsub__", reflected=True)
    __mul__ = _operator(_mk_bvmul, "__mul__")
    __rmul__ = _operator(_mk_bvmul, "__rmul__", reflected=True)
    __and__ = _operator(_mk_bvand, "__and__")
    __rand__ = _operator(_mk_bvand, "__rand__", reflected=True)
    __or__ = _operator(_mk_bvor, "__or__")
    __ror__ = _operator(_mk_bvor, "__ror__", reflected=True)
    __xor__ = _operator(_mk_bvxor, "__xor__")
    __rxor__ = _operator(_mk_bvxor, "__rxor__", reflected=True)
    __lshift__ = _operator(_mk_bvshl, "__lshift__")
    __rshift__ = _operator(_mk_bvashr, "__rshift__")
    __truediv__ = _operator(_mk_bvsdiv, "__truediv__")
    __div__ = __truediv__
    __mod__ = _operator(_mk_bvsmod, "__mod__")
    __lt__ = _operator(_mk_bvslt, "__lt__")
    __le__ = _operator(_mk_bvsle, "__le__")
    __gt__ = _operator(_mk_bvsgt, "__gt__")
    __ge__ = _operator(_mk_bvsge, "__ge__")

    def __invert__(self):
        return _mk(_mk_bvnot(_CTX, self._p))

    def __neg__(self):
        return _mk(_mk_bvneg(_CTX, self._p))

    def __pos__(self):
        return self


class InternedBitVec(_BV, z3.BitVecRef):
    pass


class InternedBitVecNum(_BV, z3.BitVecNumRef):
    def as_long(self):
        try:
            return self._long
        except AttributeError:
            self._long = r = int(_get_numeral_string(_CTX, self._p))
            return r


class InternedBool(_Interned, z3.BoolRef):
    pass


class InternedArray(_Interned, z3.ArrayRef):
    def __getitem__(self, arg):
        return _wrap(super().__getitem__(arg))


def _drain():
    """releases the terms whose object died (see _Interned.__del__)"""
    n = len(_pending)
    for _ in range(n):
        _dec_ref(_CTX, _pending.pop())


def _new(p: int):
    """creates the object of a term that has none"""
    # before anything else: a term without reference only lives until the next term is built
    _inc_ref(_CTX, p)

    k = _get_ast_kind(_CTX, p)
    cls = None
    if k in (_APP_AST, _NUMERAL_AST):
        sk = _get_sort_kind(_CTX, _get_sort(_CTX, p))
        if sk == _BV_SORT:
            cls = InternedBitVecNum if k == _NUMERAL_AST else InternedBitVec
        elif sk == _BOOL_SORT:
            cls = InternedBool
        elif sk == _ARRAY_SORT:
            cls = InternedArray

    if cls is None:
        # quantifiers and other sorts are not built by the engine: left to z3py
        o = z3._to_expr_ref(_as_ast(p), _MAIN)
        _dec_ref(_CTX, p)
        return o

    if len(_pending) > _DRAIN_THRESHOLD:
        _drain()

    o = cls.__new__(cls)
    o.ast = _as_ast(p)
    o.ctx = _MAIN
    o._p = p
    o._k = k
    o._h = _get_ast_hash(_CTX, p)
    _table[p] = weakref.ref(o)
    return o


def _as_ast(p: int) -> Ast:
    a = _new_ast(Ast)
    _init_void_p(a, p)
    return a


def _mk(p: int):
    """the object of the term at address p"""
    ref = _table.get(p)
    if ref is not None:
        o = ref()
        if o is not None:
            return o
    if p is None:
        raise _Z3Exception("z3 returned a null term")
    return _new(p)


def _wrap(x):
    """interns the result of a z3py function"""
    if isinstance(x, z3.ExprRef) and not isinstance(x, _Interned) and x.ctx is _MAIN:
        if isinstance(x, z3.QuantifierRef | z3.PatternRef):
            return x
        return _mk(x.ast.value)
    return x


intern_expr = _wrap

#
# sorts and values
#

_bv_sorts: dict[int, int] = {}


def _bv_sort(size: int) -> int:
    try:
        return _bv_sorts[size]
    except KeyError:
        s = _mk_bv_sort(_CTX, size)
        _inc_ref(_CTX, s)
        _bv_sorts[size] = s
        return s


def _numeral(val: int, size: int) -> int:
    return _mk_numeral(_CTX, b"%d" % (val & ((1 << size) - 1)), _bv_sort(size))


def BitVecVal(val, bv, ctx=None):
    if type(val) is int and type(bv) is int and ctx is None:
        return _mk(_numeral(val, bv))
    return _wrap(z3.BitVecVal(val, bv, ctx))


def BitVec(name, bv, ctx=None):
    if type(name) is str and type(bv) is int and ctx is None:
        sym = _mk_string_symbol(_CTX, name.encode())
        return _mk(_mk_const(_CTX, sym, _bv_sort(bv)))
    return _wrap(z3.BitVec(name, bv, ctx))


_TRUE = _wrap(z3.BoolVal(True))
_FALSE = _wrap(z3.BoolVal(False))


def BoolVal(val, ctx=None):
    if ctx is None:
        if val is True:
            return _TRUE
        if val is False:
            return _FALSE
    return _wrap(z3.BoolVal(val, ctx))


def Bool(name, ctx=None):
    return _wrap(z3.Bool(name, ctx))


def Array(name, *sorts):
    return _wrap(z3.Array(name, *sorts))


class InternedFuncDecl(z3.FuncDeclRef):
    """A function declaration whose applications are interned"""

    def __call__(self, *args):
        n = len(args)
        try:
            ptrs = (c_void_p * n)(*[a._p for a in args])
        except AttributeError:
            return _wrap(super().__call__(*args))
        r = _mk_app(_CTX, self.ast.value, n, ptrs)
        if r is None:
            return _wrap(super().__call__(*args))
        return _mk(r)


_functions: dict[tuple, InternedFuncDecl] = {}


def Function(name, *sig):
    try:
        key = (name, *[s.ast.value for s in sig])
    except AttributeError:
        return z3.Function(name, *sig)
    f = _functions.get(key)
    if f is None:
        f = z3.Function(name, *sig)
        if f.ctx is _MAIN:
            f.__class__ = InternedFuncDecl
            # keeps the sorts alive, so that their addresses are not reused
            f._sig = sig
            _functions[key] = f
    return f


#
# term constructors
#


def simplify(a, *arguments, **keywords):
    if not arguments and not keywords:
        try:
            return a._simplified()
        except AttributeError:
            pass
    return _wrap(z3.simplify(a, *arguments, **keywords))


def substitute(t, *m):
    return _wrap(z3.substitute(t, *m))


def If(a, b, c, ctx=None):
    try:
        r = _mk_ite(_CTX, a._p, b._p, c._p)
    except AttributeError:
        return _wrap(z3.If(a, b, c, ctx))
    if r is None:
        return _wrap(z3.If(a, b, c, ctx))
    return _mk(r)


def Not(a, ctx=None):
    if type(a) is InternedBool:
        return _mk(_mk_not(_CTX, a._p))
    return _wrap(z3.Not(a, ctx))


def _nary(mk, fallback):
    def f(*args):
        n = len(args)
        if n >= 1:
            for a in args:
                if type(a) is not InternedBool:
                    break
            else:
                return _mk(mk(_CTX, n, (c_void_p * n)(*[a._p for a in args])))
        return _wrap(fallback(*args))

    f.__name__ = fallback.__name__
    return f


And = _nary(_mk_and, z3.And)
Or = _nary(_mk_or, z3.Or)


def Xor(a, b, ctx=None):
    return _wrap(z3.Xor(a, b, ctx))


def Implies(a, b, ctx=None):
    if type(a) is InternedBool and type(b) is InternedBool:
        return _mk(_mk_implies(_CTX, a._p, b._p))
    return _wrap(z3.Implies(a, b, ctx))


def Concat(*args):
    if len(args) >= 2:
        for a in args:
            if not isinstance(a, _BV):
                break
        else:
            # each intermediate term is kept alive by the next one
            r = args[0]._p
            for a in args[1:]:
                r = _mk_concat(_CTX, r, a._p)
            return _mk(r)
    return _wrap(z3.Concat(*args))


def Extract(high, low, a):
    if (
        type(high) is int
        and type(low) is int
        and 0 <= low <= high
        and isinstance(a, _BV)
    ):
        r = _mk_extract(_CTX, high, low, a._p)
        if r is not None:
            return _mk(r)
    return _wrap(z3.Extract(high, low, a))


def ZeroExt(n, a):
    if type(n) is int and n >= 0 and isinstance(a, _BV):
        return _mk(_mk_zero_ext(_CTX, n, a._p))
    return _wrap(z3.ZeroExt(n, a))


def SignExt(n, a):
    if type(n) is int and n >= 0 and isinstance(a, _BV):
        return _mk(_mk_sign_ext(_CTX, n, a._p))
    return _wrap(z3.SignExt(n, a))


def _bv_binary(mk, fallback):
    def f(a, b):
        if isinstance(a, _BV) and isinstance(b, _BV):
            r = mk(_CTX, a._p, b._p)
            if r is not None:
                return _mk(r)
        return _wrap(fallback(a, b))

    f.__name__ = fallback.__name__
    return f


ULE = _bv_binary(_mk_bvule, z3.ULE)
ULT = _bv_binary(_mk_bvult, z3.ULT)
UGE = _bv_binary(_mk_bvuge, z3.UGE)
UGT = _bv_binary(_mk_bvugt, z3.UGT)
LShR = _bv_binary(_mk_bvlshr, z3.LShR)
UDiv = _bv_binary(_mk_bvudiv, z3.UDiv)
URem = _bv_binary(_mk_bvurem, z3.URem)
SRem = _bv_binary(_mk_bvsrem, z3.SRem)


def Select(a, *args):
    if len(args) == 1 and type(a) is InternedArray:
        try:
            r = _mk_select(_CTX, a._p, args[0]._p)
        except AttributeError:
            r = None
        if r is not None:
            return _mk(r)
    return _wrap(z3.Select(a, *args))


def Store(a, *args):
    if len(args) == 2 and type(a) is InternedArray:
        try:
            r = _mk_store(_CTX, a._p, args[0]._p, args[1]._p)
        except AttributeError:
            r = None
        if r is not None:
            return _mk(r)
    return _wrap(z3.Store(a, *args))


def Sum(*args):
    return _wrap(z3.Sum(*args))


#
# predicates
#


def is_bv_value(a):
    t = type(a)
    if t is InternedBitVecNum:
        return True
    if t is InternedBitVec:
        return False
    return z3.is_bv_value(a)


def is_true(a):
    return a is _TRUE or (not isinstance(a, _Interned) and z3.is_true(a))


def is_false(a):
    return a is _FALSE or (not isinstance(a, _Interned) and z3.is_false(a))


def is_app(a):
    if isinstance(a, _Interned):
        k = a._kind()
        return k in (_APP_AST, _NUMERAL_AST)
    return z3.is_app(a)


def is_const(a):
    if isinstance(a, _Interned):
        return len(a._arguments()) == 0
    return z3.is_const(a)


def is_app_of(a, k):
    if isinstance(a, _Interned):
        return a._decl_kind() == k
    return z3.is_app_of(a, k)


def is_eq(a):
    return is_app_of(a, _OP_EQ)


def is_not(a):
    return is_app_of(a, _OP_NOT)


def is_expr_var(a):
    """same as z3.z3util.is_expr_var"""
    return is_const(a) and is_app_of(a, z3.Z3_OP_UNINTERPRETED)


def eq(a, b):
    if a is b:
        return True
    return a.eq(b)
