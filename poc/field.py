"""Definitions of finite fields used in this spec."""

from __future__ import annotations

from sage.all import GF, PolynomialRing

from common import ERR_DECODE, Bytes, Unsigned, Vec, from_le_bytes, to_le_bytes


class Field:
    """The base class for finite fields."""

    # The prime modulus that defines arithmetic in the field.
    MODULUS: Unsigned

    # Number of bytes used to encode each field element.
    ENCODED_SIZE: Unsigned

    def __init__(self, val):
        assert int(val) < self.MODULUS
        self.val = self.gf(val)

    @classmethod
    def zeros(cls, length: Unsigned) -> Vec[Field]:
        vec = [cls(cls.gf.zero()) for _ in range(length)]
        return vec

    @classmethod
    def rand_vec(cls, length: Unsigned) -> Vec[Field]:
        vec = [cls(cls.gf.random_element()) for _ in range(length)]
        return vec

    @classmethod
    def encode_vec(Field, data: Vec[Field]) -> Bytes:
        encoded = Bytes()
        for x in data:
            encoded += to_le_bytes(x.as_unsigned(), Field.ENCODED_SIZE)
        return encoded

    @classmethod
    def decode_vec(Field, encoded: Bytes) -> Vec[Field]:
        L = Field.ENCODED_SIZE
        if len(encoded) % L != 0:
            raise ERR_DECODE

        vec = []
        for i in range(0, len(encoded), L):
            encoded_x = encoded[i:i+L]
            x = from_le_bytes(encoded_x)
            if x >= Field.MODULUS:
                raise ERR_DECODE  # Integer is larger than modulus
            vec.append(Field(x))
        return vec

    @classmethod
    def encode_into_bit_vector(Field,
                               val: Unsigned,
                               bits: Unsigned) -> Vec[Field]:
        """
        Encode the bit representation of `val` with at most `bits` number
        of bits, as a vector of field elements.
        """
        if val >= 2 ** bits:
            # Sanity check we are able to represent `val` with `bits`
            # number of bits.
            raise ValueError("Number of bits is not enough to represent "
                             "the input integer.")
        encoded = []
        for l in range(bits):
            encoded.append(Field((val >> l) & 1))
        return encoded

    @classmethod
    def decode_from_bit_vector(Field, vec: Vec[Field]) -> Field:
        """
        Decode the field element from the bit representation, expressed
        as a vector of field elements `vec`.
        """
        bits = len(vec)
        if Field.MODULUS >> bits == 0:
            raise ValueError("Number of bits is too large to be "
                             "represented by field modulus.")
        decoded = Field(0)
        for (l, bit) in enumerate(vec):
            decoded += Field(1 << l) * bit
        return decoded

    def __add__(self, other: Field) -> Field:
        return self.__class__(self.val + other.val)

    def __neg__(self) -> Field:
        return self.__class__(-self.val)

    def __mul__(self, other: Field) -> Field:
        return self.__class__(self.val * other.val)

    def inv(self) -> Field:
        return self.__class__(self.val**-1)

    def __eq__(self, other: Field) -> Field:
        return self.val == other.val

    def __sub__(self, other: Field) -> Field:
        return self + (-other)

    def __div__(self, other: Field) -> Field:
        return self * other.inv()

    def __pow__(self, n: Unsigned) -> Field:
        return self.__class__(self.val ** n)

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return str(self.val)

    def as_unsigned(self) -> Unsigned:
        return int(self.gf(self.val))


class FftField(Field):
    # Order of the multiplicative group generated by `Field.gen()`.
    GEN_ORDER: Unsigned

    @classmethod
    def gen(cls) -> Field:
        raise NotImplementedError()


class Field2(Field):
    """The finite field GF(2)."""

    MODULUS = 2
    ENCODED_SIZE = 1

    # Operational parameters
    gf = GF(MODULUS)

    def conditional_select(self, inp: Bytes) -> Bytes:
        """
        Return `inp` unmodified if `self == 1`; otherwise return the all-zero
        string of the same length.

        Implementation note: To protect the code from timing side channels, it
        is important to implement this algorithm in constant time.
        """

        # Convert the element into a bitmask such that `m == 255` if
        # `self == 1` and `m == 0` otherwise.
        m = 0
        v = self.as_unsigned()
        for i in range(8):
            m |= v << i
        return bytes(map(lambda x: m & x, inp))


class Field64(FftField):
    """The finite field GF(2^32 * 4294967295 + 1)."""

    MODULUS = 2**32 * 4294967295 + 1
    GEN_ORDER = 2**32
    ENCODED_SIZE = 8

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def gen(cls):
        return cls(7)**4294967295


class Field96(FftField):
    """The finite field GF(2^64 * 4294966555 + 1)."""

    MODULUS = 2**64 * 4294966555 + 1
    GEN_ORDER = 2**64
    ENCODED_SIZE = 12

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def gen(cls):
        return cls(3)**4294966555


class Field128(FftField):
    """The finite field GF(2^66 * 4611686018427387897 + 1)."""

    MODULUS = 2**66 * 4611686018427387897 + 1
    GEN_ORDER = 2**66
    ENCODED_SIZE = 16

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def gen(cls):
        return cls(7)**4611686018427387897


class Field255(Field):
    """The finite field GF(2^255 - 19)."""

    MODULUS = 2**255 - 19
    ENCODED_SIZE = 32

    # Operational parameters
    gf = GF(MODULUS)


##
# POLYNOMIAL ARITHMETIC
#


def poly_strip(Field, p):
    """Remove leading zeros from the input polynomial."""
    for i in reversed(range(len(p))):
        if p[i] != Field(0):
            return p[:i+1]
    return []


def poly_mul(Field, p, q):
    """Multiply two polynomials."""
    r = [Field(0) for _ in range(len(p) + len(q))]
    for i in range(len(p)):
        for j in range(len(q)):
            r[i + j] += p[i] * q[j]
    return poly_strip(Field, r)


def poly_eval(Field, p, eval_at):
    """Evaluate a polynomial at a point."""
    if len(p) == 0:
        return Field(0)

    p = poly_strip(Field, p)
    result = p[-1]
    for c in reversed(p[:-1]):
        result *= eval_at
        result += c

    return result


def poly_interp(Field, xs, ys):
    """Compute the Lagrange interpolation polynomial for the given points."""
    R = PolynomialRing(Field.gf, 'x')
    p = R.lagrange_polynomial([(x.val, y.val) for (x, y) in zip(xs, ys)])
    return poly_strip(Field, list(map(lambda x: Field(x), p.coefficients())))
