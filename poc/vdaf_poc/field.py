"""Definitions of finite fields used in this spec."""


from __future__ import annotations

import math
import random
from typing import Generic, Self, TypeVar, cast

from vdaf_poc.common import (assert_power_of_2, bitrev, from_le_bytes, front,
                             to_le_bytes)


class Field:
    """The base class for finite fields."""

    # The prime modulus that defines arithmetic in the field.
    MODULUS: int

    # Number of bytes used to encode each field element.
    ENCODED_SIZE: int

    def __init__(self, val: int):
        assert val < self.MODULUS
        assert val > -self.MODULUS
        # Interpret negative integers as additive inverses of field elements.
        self.val = val % self.MODULUS

    @classmethod
    def zeros(cls, length: int) -> list[Self]:
        vec = [cls(0)] * length
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
            encoded += to_le_bytes(x.int(), cls.ENCODED_SIZE)
        return encoded

    @classmethod
    def decode_vec(cls, encoded: bytes) -> list[Self]:
        """
        Parse a vector of field elements from `encoded`.
        """
        if len(encoded) % cls.ENCODED_SIZE != 0:
            raise ValueError(
                'input length must be a multiple of the size of an '
                'encoded field element')

        vec = []
        while len(encoded) > 0:
            (encoded_x, encoded) = front(cls.ENCODED_SIZE, encoded)
            x = from_le_bytes(encoded_x)
            if x >= cls.MODULUS:
                raise ValueError('modulus overflow')
            vec.append(cls(x))
        return vec

    # NOTE: The encode_into_bit_vec() and decode_from_bit_vec()
    # methods are excerpted in the document, de-indented, as the figure
    # {{field-bit-rep}}. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid
    # warnings from xml2rfc.
    # ===================================================================
    @classmethod
    def encode_into_bit_vec(
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
    def decode_from_bit_vec(cls, vec: list[Self]) -> Self:
        """
        Decode the field element from the bit representation, expressed
        as a vector of field elements `vec`.

        This may also be used with secret shares of a bit representation,
        since it is linear.
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
        return self.__class__(pow(self.val, self.MODULUS-2, self.MODULUS))

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

    def int(self) -> int:
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

    @classmethod
    def nth_root(cls, n: int) -> Self:
        """Returns an 2^n-th root of unity."""
        return cls.gen() ** (cls.GEN_ORDER >> n)

    @classmethod
    def nth_root_powers(cls, n: int) -> list[Self]:
        """Returns the first n powers of an n-th root of unity."""
        log_n = assert_power_of_2(n)
        root = cls.nth_root(log_n)
        return [root**i for i in range(n)]

    @classmethod
    def inv_ntt(cls, p: list[Self], n: int) -> list[Self]:
        """
        Inverse NTT converts a polynomial P in the Lagrange basis to the
        monomial basis.
        """
        out = cls.ntt(p, n)
        out.append(out.pop(0))
        out.reverse()
        inv_n = cls(n).inv()
        for i in range(len(out)):
            out[i] *= inv_n
        return out

    @classmethod
    def ntt(cls, p: list[Self], n: int, set_s: bool = False) -> list[Self]:
        """
        Number Theoretic Transform (NTT) over a prime field. It converts
        a polynomial P from the monomial basis to the Lagrange basis.

        Returns `[ P(s*w^i) for i in range(n) ]`, where w is an n-th root
        of unity. When set_s is True, s is a 2n-th root of unity,
        otherwise s=1. See Alg. 4 of [Faz25](https://ia.cr/2025/1727).
        """
        log_n = assert_power_of_2(n)
        p += [cls(0)] * (n-len(p))
        q = [p[bitrev(log_n, i)] for i in range(n)]
        for k in range(1, log_n + 1):
            w = cls.nth_root(k+1) if set_s else cls(1)
            y = 1 << (k - 1)
            r = cls.nth_root(k)
            for i in range(y):
                for j in range(n >> k):
                    x = (j << k) + i
                    u = q[x]
                    v = w * q[x + y]
                    q[x] = u + v
                    q[x + y] = u - v
                w *= r
        return q


class Field64(NttField):
    """The finite field GF(2**32 * 4294967295 + 1)."""

    MODULUS = 2**32 * 4294967295 + 1
    GEN_ORDER = 2**32
    ENCODED_SIZE = 8

    @classmethod
    def gen(cls) -> Self:
        return cls(7)**4294967295


class Field96(NttField):
    """The finite field GF(2**64 * 4294966555 + 1)."""

    MODULUS = 2**64 * 4294966555 + 1
    GEN_ORDER = 2**64
    ENCODED_SIZE = 12

    @classmethod
    def gen(cls) -> Self:
        return cls(3)**4294966555


class Field128(NttField):
    """The finite field GF(2**66 * 4611686018427387897 + 1)."""

    MODULUS = 2**66 * 4611686018427387897 + 1
    GEN_ORDER = 2**66
    ENCODED_SIZE = 16

    @classmethod
    def gen(cls) -> Self:
        return cls(7)**4611686018427387897


class Field255(Field):
    """The finite field GF(2**255 - 19)."""

    MODULUS = 2**255 - 19
    ENCODED_SIZE = 32


##
# POLYNOMIAL ARITHMETIC IN THE MONOMIAL BASIS
#

F = TypeVar("F", bound=Field)


def poly_strip(field: type[F], p: list[F]) -> list[F]:
    """Remove leading zeros from the input polynomial."""
    for i in reversed(range(len(p))):
        if p[i] != field(0):
            return p[:i+1]
    return []


def poly_mul(field: type[F], p: list[F], q: list[F]) -> list[F]:
    """Multiply two polynomials in the monomial basis."""
    r = [field(0)] * (len(p) + len(q) - 1)
    for i in range(len(p)):
        for j in range(len(q)):
            r[i + j] += p[i] * q[j]
    return poly_strip(field, r)


def poly_add(field: type[F], p: list[F], q: list[F]) -> list[F]:
    """Add two polynomials."""
    r = field.zeros(max(len(p), len(q)))
    for i, p_i in enumerate(p):
        r[i] = p_i
    for i, q_i in enumerate(q):
        r[i] += q_i
    return poly_strip(field, r)


def poly_eval(field: type[F], p: list[F], eval_at: F) -> F:
    """Evaluate a polynomial in the monomial basis at a point."""
    if len(p) == 0:
        return field(0)

    p = poly_strip(field, p)
    result = p[-1]
    for c in reversed(p[:-1]):
        result *= eval_at
        result += c

    return result


def poly_interp(field: type[F], xs: list[F], ys: list[F]) -> list[F]:
    """
    Compute the Lagrange interpolation polynomial for the given points.

    This uses Newton's divided difference interpolation formula.

    See https://en.wikipedia.org/wiki/Newton_polynomial and
    https://mathworld.wolfram.com/NewtonsDividedDifferenceInterpolationFormula.html.

    Historical note: this was previously implemented using Sage, with a faster
    version of the same algorithm. The Sage dependency was removed, and
    operations on field elements and polynomials were re-implemented in pure
    Python for portability and ease of use.
    """

    assert len(xs) == len(ys)
    n = len(xs)
    one = field(1)

    # We interleave three computations in each iteration of the outermost loop.
    # First, we compute the `i`th Newton basis polynomial. Second, we compute the
    # all the `i`th divided differences. Third, we mutliply the `i`th basis
    # polynomial by the one of the `i`th divided differences, and add the product
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


T = TypeVar("T", bound=NttField)


class Lagrange(Generic[T]):
    """Polynomial arithmetic in the Lagrange basis."""

    def __init__(self, field: type[T]) -> None:
        self.field = field

    def poly_mul(self, p: list[T], q: list[T]) -> list[T]:
        """
        Multiply two polynomials in the Lagrange basis.

        See Strategy 2 (rhizome) of [Faz25](https://ia.cr/2025/1727).
        """
        n = len(p)
        assert_power_of_2(n)
        assert len(p) == len(q)
        p_2n = self.double_evaluations(p)
        q_2n = self.double_evaluations(q)
        return [pi*qi for pi, qi in zip(p_2n, q_2n)]

    def poly_eval(self, p: list[T], x: T) -> T:
        """Evaluate a polynomial P in the Lagrange basis at x."""
        return self.poly_eval_batched([p], x).pop()

    def poly_eval_batched(self, polys: list[list[T]], x: T) -> list[T]:
        """Evaluate a list of polynomials in the Lagrange basis at x.

        See Alg. 7 of [Faz25](https://ia.cr/2025/1727).
        """
        assert len(set(len(p) for p in polys)) == 1
        n = len(polys[0])
        assert_power_of_2(n)

        nodes = self.field.nth_root_powers(n)
        k = self.field(1)
        u = [p[0] for p in polys]
        d = nodes[0] - x
        for i in range(1, n):
            k *= d
            d = nodes[i] - x
            t = k * nodes[i]
            for j, p in enumerate(polys):
                u[j] *= d
                if i < len(p):
                    u[j] += t * p[i]

        factor = self.field(-1)**(n-1) * self.field(n).inv()
        for i in range(len(u)):
            u[i] *= factor
        return u

    def extend_values_to_power_of_2(self, p: list[T], n: int) -> None:
        """
        Appends evaluations to the polynomial P (in-place) until the
        number of evaluations is N, and N must be a power of two.

        See Eq. (3.2.1) of [Faz25](https://ia.cr/2025/1727).
        """
        assert_power_of_2(n)
        assert len(p) <= n
        x = self.field.nth_root_powers(n)

        w = [self.field(0)]*n
        for i in range(len(p)):
            diff = (x[i] - x[j] for j in range(len(p)) if i != j)
            w[i] = math.prod(diff, start=self.field(1))

        for k in range(len(p), n):
            for i in range(k):
                w[i] *= x[i] - x[k]

            y_num, y_den = self.field(0), self.field(1)
            for i, v in enumerate(p):
                y_num = y_num * w[i] + y_den * v
                y_den *= w[i]

            diff = (x[k] - x[j] for j in range(k))
            w[k] = math.prod(diff, start=self.field(1))
            p.append(-w[k] * y_num * y_den.inv())

    def double_evaluations(self, p: list[T]) -> list[T]:
        """
        Returns 2N evaluations of a polynomial from N Lagrange-basis
        evaluations, such that N=len(p) is a power of 2.

        See Eq. (3.3.4) of [Faz25](https://ia.cr/2025/1727).
        """
        n = len(p)
        assert_power_of_2(n)
        even = p
        odd = self.field.ntt(self.field.inv_ntt(even, n), n, True)
        return [i for pair in zip(even, odd) for i in pair]
