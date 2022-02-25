# Definitions of finite fields used in this spec.

from __future__ import annotations
from sage.all import GF
from sagelib.common import ERR_DECODE, I2OSP, OS2IP, Bytes, Unsigned, Vec


# The base class for finite fields.
class Field:

    # The prime modulus that defines arithmetic in the field.
    MODULUS: Unsigned

    # Number of bytes used to encode each field element.
    ENCODED_SIZE: Unsigned

    def __init__(self, val):
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
    def encode_vec(cls, data: Vec[Field]) -> Bytes:
        encoded = Bytes()
        for x in data:
            encoded += I2OSP(x.as_unsigned(), cls.ENCODED_SIZE)
        return encoded

    @classmethod
    def decode_vec(cls, encoded: Bytes) -> Vec[Field]:
        L = cls.ENCODED_SIZE
        if len(encoded) % cls.ENCODED_SIZE != 0:
            raise ERR_DECODE

        vec = []
        for i in range(0, len(encoded), L):
            encoded_x = encoded[i:i+L]
            x = cls(OS2IP(encoded_x))
            vec.append(x)
        return vec

    def __add__(self, other: Field) -> Field:
        return self.__class__(self.val + other.val)

    def __neg__(self) -> Field:
        return self.__class__(-self.val)

    def __mul__(self, other: Field) -> Field:
        return self.__class__(self.val * other.val)

    def inv(self) -> Field:
        return self.__class__(self.val^-1)

    def __eq__(self, other: Field) -> Field:
        return self.val == other.val

    def __sub__(self, other: Field) -> Field:
        return self + (-other)

    def __div__(self, other: Field) -> Field:
        return self * other.inv()

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return str(self.val)

    def as_unsigned(self) -> Unsigned:
        return int(self.gf(self.val))


# The finite field GF(2^32 * 4294967295 + 1).
class Field64(Field):
    MODULUS = 2^32 * 4294967295 + 1
    ENCODED_SIZE = 8

    # Operational parameters
    gf = GF(MODULUS)


# The finite field GF(2^64 * 4294966555 + 1).
class Field96(Field):
    MODULUS = 2^64 * 4294966555 + 1
    ENCODED_SIZE = 12

    # Operational parameters
    gf = GF(MODULUS)


# The finite field GF(2^64 * 4611686018427387751 + 1).
class Field128(Field):
    MODULUS = 2^64 * 4611686018427387751 + 1
    ENCODED_SIZE = 16

    # Operational parameters
    gf = GF(MODULUS)


##
# TESTS
#

def test_field(cls):
    # Test constructing a field element from an integer.
    assert cls(1337) == cls(cls.gf(1337))

    # Test generating a zero-vector.
    vec = cls.zeros(23)
    assert len(vec) == 23
    for x in vec:
        assert x == cls(cls.gf.zero())

    # Test generating a random vector.
    vec = cls.rand_vec(23)
    assert len(vec) == 23

    # Test arithmetic.
    x = cls(cls.gf.random_element())
    y = cls(cls.gf.random_element())
    assert x + y == cls(x.val + y.val)
    assert x - y == cls(x.val - y.val)
    assert -x == cls(-x.val)
    assert x * y == cls(x.val * y.val)
    assert x.inv() == cls(x.val^-1)

    # Test serialization.
    want = cls.rand_vec(10)
    got = cls.decode_vec(cls.encode_vec(want))
    assert got == want


if __name__ == "__main__":
    test_field(Field64)
    test_field(Field96)
    test_field(Field128)
