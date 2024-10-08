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
        assert val >= 0
        assert val < self.MODULUS
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
        return self.__class__(invmod(self.val, self.MODULUS))

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
    r = [field(0)] * (len(p) + len(q) - 1)
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

    # This uses Newton's divided difference interpolation formula.

    assert len(xs) == len(ys)
    n = len(xs)
    one = field(1)

    # We interleave three computations in each iteration of the outermost loop.
    # First, we compute the ith Newton basis polynomial. Second, we compute the
    # all the ith divided differences. Third, we mutliply the ith basis
    # polynomial by the one of the ith divided differences, and add the product
    # to the output accumulator. Computation of both the basis polynomials and
    # the divided differences are done recurrently, depending on values from
    # just the previous iteration. However, we calculate a full triangle of
    # divided difference values, one row per outer loop iteration, and only
    # those along the left side (involving y_0) are directly used in the
    # polynomial interpolation formula. The rest of the triangle is just
    # computed to be used in subsequent rows of the triangle.
    #
    # Newton basis polynomials:
    # n_i(x) = \prod_{j=0}^{i-1} (x - x_j)
    # n_0(x) = 1
    # n_i(x) = n_{i-1}(x) \cdot (x - x_{i - 1})
    #
    # Divided differences:
    # [y_j] = y_j
    # [y_j, y_{j+1}] = ([y_j] - [y_{j+1}]) / (x_j - x_{j+1})
    # [y_j, ..., y_k] = ([y_j, ..., y_k] - [y_j, ..., y_k]) / (x_j - x_k)
    #
    # Newton polynomial interpolation:
    # p(x) = \sum_{i=0}^{n-1} [y_0, ..., y_{i}] \cdot n_i(x)

    # Handle i=0 as a special case via initialization of variables.
    # First basis polynomial: n_0(x) = 1
    previous_basis_polynomial: list[F] = [one]
    # The top row of the triangle of divided differences is just every y-value.
    previous_divided_differences = ys
    # Initialize the output polynomial with the constant y0. (This is equal to
    # [y0]*n_0(x) = y0 * 1)
    output: list[F] = [ys[0]]

    for i in range(1, n):
        next_basis_polynomial = poly_mul(
            field,
            previous_basis_polynomial,
            [-xs[i - 1], one],
        )
        previous_basis_polynomial = next_basis_polynomial

        next_divided_differences: list[F] = []
        for k in range(len(previous_divided_differences) - 1):
            next_divided_differences.append(
                (previous_divided_differences[k]
                 - previous_divided_differences[k + 1])
                * (xs[k] - xs[k + i]).inv()
            )
        previous_divided_differences = next_divided_differences

        output = poly_add(
            field,
            output,
            poly_mul(
                field,
                [next_divided_differences[0]],
                next_basis_polynomial,
            ),
        )

    return output


def xgcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean algorithm.

    Both a and b must be positive integers.
    """
    last_remainder, remainder = a, b
    a, last_a, b, last_b = 0, 1, 1, 0
    while remainder:
        last_remainder, (quotient, remainder) = (
            remainder,
            divmod(last_remainder, remainder),
        )
        a, last_a = last_a - quotient * a, a
        b, last_b = last_b - quotient * b, b
    return last_remainder, last_a, last_b


def invmod(x: int, p: int) -> int:
    """
    Modular multiplicative inverse.

    Both x and p must be positive integers. Raises an exception if
    x and p are coprime.
    """
    gcd, a, _b = xgcd(x, p)
    if gcd != 1:
        raise ValueError("Arguments to invmod were coprime")
    return a % p
