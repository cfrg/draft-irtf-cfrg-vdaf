"""Definitions of finite fields used in this spec."""

import random
from typing import Self, TypeVar, cast

from vdaf_poc.common import from_le_bytes, to_le_bytes


class Field:
    """The base class for finite fields."""

    # The prime modulus that defines arithmetic in the field.
    MODULUS: int

    # Number of bytes used to encode each field element.
    ENCODED_SIZE: int

    def __init__(self, val: int):
        assert int(val) >= 0
        assert int(val) < self.MODULUS
        self.val = val

    @classmethod
    def zeros(cls, length: int) -> list[Self]:
        vec = [cls(0) for _ in range(length)]
        return vec

    @classmethod
    def rand_vec(cls, length: int) -> list[Self]:
        """
        Return a random vector of field elements of length `length`.
        """
        vec = [cls(random.randrange(0, cls.MODULUS)) for _ in range(length)]
        return vec

    # NOTE: The encode_vec() and decode_vec() methods are excerpted in
    # the document, de-indented, as the figure {{field-derived-methods}}.
    # Their width should be limited to 69 columns after de-indenting, or
    # 73 columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    @classmethod
    def encode_vec(cls, vec: list[Self]) -> bytes:
        """
        Encode a vector of field elements `vec` as a byte string.
        """
        encoded = bytes()
        for x in vec:
            encoded += to_le_bytes(x.as_unsigned(), cls.ENCODED_SIZE)
        return encoded

    @classmethod
    def decode_vec(cls, encoded: bytes) -> list[Self]:
        """
        Parse a vector of field elements from `encoded`.
        """
        L = cls.ENCODED_SIZE
        if len(encoded) % L != 0:
            raise ValueError(
                'input length must be a multiple of the size of an '
                'encoded field element')

        vec = []
        for i in range(0, len(encoded), L):
            encoded_x = encoded[i:i+L]
            x = from_le_bytes(encoded_x)
            if x >= cls.MODULUS:
                raise ValueError('modulus overflow')
            vec.append(cls(x))
        return vec

    # NOTE: The encode_into_bit_vector() and decode_from_bit_vector()
    # methods are excerpted in the document, de-indented, as the figure
    # {{field-bit-rep}}. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid
    # warnings from xml2rfc.
    # ===================================================================
    @classmethod
    def encode_into_bit_vector(
            cls,
            val: int,
            bits: int) -> list[Self]:
        """
        Encode the bit representation of `val` with at most `bits` number
        of bits, as a vector of field elements.

        Pre-conditions:

            - `val >= 0`
            - `bits >= 0`
        """
        if val >= 2 ** bits:
            # Sanity check we are able to represent `val` with `bits`
            # number of bits.
            raise ValueError("Number of bits is not enough to represent "
                             "the input integer.")
        encoded = []
        for l in range(bits):
            encoded.append(cls((val >> l) & 1))
        return encoded

    @classmethod
    def decode_from_bit_vector(cls, vec: list[Self]) -> Self:
        """
        Decode the field element from the bit representation, expressed
        as a vector of field elements `vec`.
        """
        bits = len(vec)
        if cls.MODULUS >> bits == 0:
            raise ValueError("Number of bits is too large to be "
                             "represented by field modulus.")
        decoded = cls(0)
        for (l, bit) in enumerate(vec):
            decoded += cls(1 << l) * bit
        return decoded

    def __add__(self, other: Self) -> Self:
        return self.__class__((self.val + other.val) % self.MODULUS)

    def __neg__(self) -> Self:
        return self.__class__((-self.val) % self.MODULUS)

    def __mul__(self, other: Self) -> Self:
        return self.__class__((self.val * other.val) % self.MODULUS)

    def inv(self) -> Self:
        return self ** (self.MODULUS - 2)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Field):
            return NotImplemented
        return cast(bool, self.val == other.val)

    def __sub__(self, other: Self) -> Self:
        return self.__class__((self.val - other.val) % self.MODULUS)

    def __div__(self, other: Self) -> Self:
        return self * other.inv()

    def __pow__(self, n: int) -> Self:
        return self.__class__(pow(self.val, n, self.MODULUS))

    def __str__(self) -> str:
        return str(self.val)

    def __repr__(self) -> str:
        return str(self.val)

    def as_unsigned(self) -> int:
        return self.val


class NttField(Field):
    """
    A field that is suitable for use with the NTT ("number theoretic
    transform") algorithm for efficient polynomial interpolation. Such a field
    defines a large multiplicative subgroup whose order is a power of 2.
    """

    # Order of the multiplicative group generated by `Field.gen()`.
    GEN_ORDER: int

    @classmethod
    def gen(cls) -> Self:
        raise NotImplementedError()


class Field2(Field):
    """The finite field GF(2)."""

    MODULUS = 2
    ENCODED_SIZE = 1


class Field64(NttField):
    """The finite field GF(2^32 * 4294967295 + 1)."""

    MODULUS = 2**32 * 4294967295 + 1
    GEN_ORDER = 2**32
    ENCODED_SIZE = 8

    @classmethod
    def gen(cls) -> Self:
        return cls(7)**4294967295


class Field96(NttField):
    """The finite field GF(2^64 * 4294966555 + 1)."""

    MODULUS = 2**64 * 4294966555 + 1
    GEN_ORDER = 2**64
    ENCODED_SIZE = 12

    @classmethod
    def gen(cls) -> Self:
        return cls(3)**4294966555


class Field128(NttField):
    """The finite field GF(2^66 * 4611686018427387897 + 1)."""

    MODULUS = 2**66 * 4611686018427387897 + 1
    GEN_ORDER = 2**66
    ENCODED_SIZE = 16

    @classmethod
    def gen(cls) -> Self:
        return cls(7)**4611686018427387897


class Field255(Field):
    """The finite field GF(2^255 - 19)."""

    MODULUS = 2**255 - 19
    ENCODED_SIZE = 32


##
# POLYNOMIAL ARITHMETIC
#

F = TypeVar("F", bound=Field)


def poly_strip(field: type[F], p: list[F]) -> list[F]:
    """Remove leading zeros from the input polynomial."""
    for i in reversed(range(len(p))):
        if p[i] != field(0):
            return p[:i+1]
    return []


def poly_mul(field: type[F], p: list[F], q: list[F]) -> list[F]:
    """Multiply two polynomials."""
    r = [field(0) for _ in range(len(p) + len(q))]
    for i in range(len(p)):
        for j in range(len(q)):
            r[i + j] += p[i] * q[j]
    return poly_strip(field, r)


def poly_add(field: type[F], p: list[F], q: list[F]) -> list[F]:
    """Add two polynomials."""
    r = field.zeros(max(len(p), len(q)))
    for i, pi in enumerate(p):
        r[i] = pi
    for i, qi in enumerate(q):
        r[i] += qi
    return poly_strip(field, r)


def poly_eval(field: type[F], p: list[F], eval_at: F) -> F:
    """Evaluate a polynomial at a point."""
    if len(p) == 0:
        return field(0)

    p = poly_strip(field, p)
    result = p[-1]
    for c in reversed(p[:-1]):
        result *= eval_at
        result += c

    return result


def poly_interp(field: type[F], xs: list[F], ys: list[F]) -> list[F]:
    """Compute the Lagrange interpolation polynomial for the given points."""

    # This is an inefficient but simple implementation of polynomial
    # interpolation. We compute the Lagrange basis, and then take a linear
    # combination of the basis polynomials.

    assert len(xs) == len(ys)
    n = len(xs)
    output: list[F] = []  # zero

    for i, (xi, yi) in enumerate(zip(xs, ys)):
        # The i-th basis polynomial is the product of (x - xj)/(xi - xj) for
        # all j != i.
        basis: list[F] = [field(1)]
        for j in range(n):
            if i == j:
                continue
            else:
                xj = xs[j]
                denominator = xi - xj
                inverse = denominator.inv()
                linear_coefficient = inverse
                constant_coefficient = inverse * -xj
                basis = poly_mul(
                    field,
                    basis,
                    [constant_coefficient, linear_coefficient],
                )

        # Multiply the basis polynomial by the y-value, and add it to the output.
        output = poly_add(
            field,
            output,
            poly_mul(field, [yi], basis),
        )

    return output
