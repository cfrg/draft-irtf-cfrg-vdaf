# Definitions of finite fields used in this spec.

from __future__ import annotations

from functools import reduce
from sage.all import GF

from sagelib.common import ErrInvalidInput, I2OSP, OS2IP, Vec


# The base class for finit fields.
class BaseField:

    ENCODED_SIZE: int

    def __init__(self, val):
        if type(val) == int:
            self.val = self.gf(val)
        self.val = val

    @classmethod
    def zeros(cls, length: int) -> Vec[BaseField]:
        vec = [cls(cls.gf.zero()) for _ in range(length)]
        return vec

    @classmethod
    def rand_vec(cls, length: int) -> Vec[BaseField]:
        vec = [cls(cls.gf.random_element()) for _ in range(length)]
        return vec

    @classmethod
    def encode_vec(cls, data: Vec[BaseField]) -> bytes:
        return reduce(lambda encoded_x, encoded_y: encoded_x + encoded_y,
                      map(lambda x: I2OSP(int(x.val), cls.ENCODED_SIZE), data))

    @classmethod
    def decode_vec(cls, encoded_data: bytes) -> Vec[BaseField]:
        if len(encoded_data) % cls.ENCODED_SIZE != 0:
            raise ErrInvalidInput
        data = []
        for i in range(0, len(encoded_data), cls.ENCODED_SIZE):
            encoded_x = encoded_data[i:i+cls.ENCODED_SIZE]
            x = cls(OS2IP(encoded_x))
            data.append(x)
        return data

    def __add__(self, other: BaseField) -> BaseField:
        return self.__class__(self.val + other.val)

    def __neg__(self) -> BaseField:
        return self.__class__(-self.val)

    def __mul__(self, other: BaseField) -> BaseField:
        return self.__class__(self.val * other.val)

    def inv(self) -> BaseField:
        return self.__class__(self.val^-1)

    def __eq__(self, other: BaseField) -> BaseField:
        return self.val == other.val

    def __sub__(self, other: BaseField) -> BaseField:
        return self + (-other)

    def __div__(self, other: BaseField) -> BaseField:
        return self * other.inv()


# The finite field GF(2^32 * 4294967295 + 1).
class Field64(BaseField):
    gf = GF(2^32 * 4294967295 + 1)
    ENCODED_SIZE = 8


# The finite field GF(2^64 * 4294966555 + 1).
class Field96(BaseField):
    gf = GF(2^64 * 4294966555 + 1)
    ENCODED_SIZE = 12


# The finite field GF(2^64 * 4611686018427387751 + 1).
class Field128(BaseField):
    gf = GF(2^64 * 4611686018427387751 + 1)
    ENCODED_SIZE = 16


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
