# SPDX-License-Identifier: AGPL-3.0

"""
Models for the hashing and modular exponentiation precompiles.

The precompile input is a ByteVec whose length is in *bytes*, while z3 sorts are
sized in *bits*. Mixing the two up produced sort mismatches for every symbolic
call to SHA256, RIPEMD160 and MODEXP (halmos issue #402).

Concrete inputs are evaluated exactly. Symbolic inputs are modeled with
uninterpreted functions constrained by the properties that always hold.
"""

import hashlib

from z3 import (
    ULT,
    BitVecRef,
    Extract,
    Function,
    If,
    Implies,
    Or,
    ZeroExt,
    is_bv,
)

from dolmos.bytevec import ByteVec
from dolmos.utils import BitVecSorts, bytes_to_bv_value, con

# EIP-7823 (osaka): each length field of a MODEXP input is capped at 1024 bytes;
# larger inputs make the precompile fail
MODEXP_MAX_INPUT_SIZE = 1024

# ripemd160(b"")
EMPTY_RIPEMD160 = bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")


def _as_bv(data: bytes | BitVecRef) -> BitVecRef:
    """Convert non-empty unwrapped bytes to a bitvector."""
    return data if is_bv(data) else bytes_to_bv_value(data)


def _ripemd160(data: bytes) -> bytes | None:
    if not data:
        return EMPTY_RIPEMD160
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        # not available in some OpenSSL 3 builds
        return None


def sha256(arg: ByteVec) -> ByteVec:
    data = arg.unwrap()

    if not is_bv(data):
        return ByteVec(hashlib.sha256(data).digest())

    size_bits = len(arg) * 8
    f_sha256 = Function(
        f"f_sha256_{len(arg)}", BitVecSorts[size_bits], BitVecSorts[256]
    )
    return ByteVec(f_sha256(data))


def ripemd160(arg: ByteVec) -> ByteVec:
    data = arg.unwrap()

    # the 20-byte digest is returned left-padded to 32 bytes
    if not is_bv(data) and (digest := _ripemd160(data)) is not None:
        return ByteVec(bytes(12) + digest)

    size_bits = len(arg) * 8
    f_ripemd160 = Function(
        f"f_ripemd160_{len(arg)}", BitVecSorts[size_bits], BitVecSorts[160]
    )
    return ByteVec(ZeroExt(96, f_ripemd160(_as_bv(data))))


def modexp(ex, arg: ByteVec) -> ByteVec | None:
    """
    Returns the output of MODEXP, or None if the precompile fails.

    Input layout (EIP-198):
        <len(B)> <len(E)> <len(M)> <B> <E> <M>
    each length is a 32-byte word; missing input bytes are read as zeros.
    The output is (B ** E) % M, encoded on len(M) bytes (0 if M == 0).
    """

    b_size = ex.int_of(arg.get_word(0), "symbolic MODEXP base length")
    e_size = ex.int_of(arg.get_word(32), "symbolic MODEXP exponent length")
    m_size = ex.int_of(arg.get_word(64), "symbolic MODEXP modulus length")

    if max(b_size, e_size, m_size) > MODEXP_MAX_INPUT_SIZE:
        return None

    if m_size == 0:
        return ByteVec()

    b_start = 96
    e_start = b_start + b_size
    m_start = e_start + e_size

    b = arg.slice(b_start, e_start).unwrap() if b_size else b""
    e = arg.slice(e_start, m_start).unwrap() if e_size else b""
    m = arg.slice(m_start, m_start + m_size).unwrap()

    # fully concrete: compute the exact result
    if not any(is_bv(x) for x in (b, e, m)):
        m_int = int.from_bytes(m, "big")
        if m_int == 0:
            return ByteVec(bytes(m_size))
        b_int = int.from_bytes(b, "big")
        e_int = int.from_bytes(e, "big")
        return ByteVec(pow(b_int, e_int, m_int).to_bytes(m_size, "big"))

    m_bits = m_size * 8
    m_bv = _as_bv(m)
    zero_m, one_m = con(0, m_bits), con(1, m_bits)

    # x ** 0 == 1, and 1 % 1 == 0
    one_mod_m = If(m_bv == one_m, zero_m, one_m)

    # b % m, computed on a common width.
    # like the MOD opcode, the (nonlinear) remainder is abstracted with an
    # uninterpreted function: z3 rewrites a guarded URem into its internal
    # `bvurem_i` operator, which external solvers don't understand.
    width = max(b_size, m_size) * 8

    def mod_m(x: BitVecRef, x_bits: int) -> BitVecRef:
        x_ext = ZeroExt(width - x_bits, x) if width > x_bits else x
        m_ext = ZeroExt(width - m_bits, m_bv) if width > m_bits else m_bv
        f_rem = Function(
            f"f_evm_bvurem_{width}",
            BitVecSorts[width],
            BitVecSorts[width],
            BitVecSorts[width],
        )
        r = f_rem(x_ext, m_ext)
        ex.path.append(Implies(m_ext != 0, ULT(r, m_ext)))
        return r if width == m_bits else Extract(m_bits - 1, 0, r)

    b_bv = _as_bv(b) if b_size else None
    b_mod_m = mod_m(b_bv, b_size * 8) if b_size else zero_m

    e_is_concrete = not is_bv(e)
    e_int = int.from_bytes(e, "big") if e_is_concrete else None

    if e_is_concrete and e_int == 0:
        result = one_mod_m

    elif e_is_concrete and e_int == 1:
        result = b_mod_m

    elif b_size == 0:
        # 0 ** e == 0 for e > 0
        result = zero_m if e_is_concrete else If(_as_bv(e) == 0, one_mod_m, zero_m)

    else:
        e_bv = con(e_int, e_size * 8) if e_is_concrete else _as_bv(e)
        f_modexp = Function(
            f"f_modexp_{b_size}_{e_size}_{m_size}",
            BitVecSorts[b_size * 8],
            BitVecSorts[e_size * 8],
            BitVecSorts[m_bits],
            BitVecSorts[m_bits],
        )
        f_val = f_modexp(b_bv, e_bv, m_bv)

        # properties of the abstraction:
        #   - the result is reduced modulo m
        #   - base 0 or 1, and exponent 1, are computed exactly
        ex.path.append(Implies(m_bv != zero_m, ULT(f_val, m_bv)))

        result = If(
            e_bv == 0,
            one_mod_m,
            If(
                Or(b_bv == 0, b_bv == 1, e_bv == 1),
                b_mod_m,
                f_val,
            ),
        )

    result = If(m_bv == zero_m, zero_m, result)
    return ByteVec(result)
