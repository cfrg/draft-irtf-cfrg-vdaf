import unittest

from vdaf_poc.field import (FftField, Field, Field2, Field64, Field96,
                            Field128, Field255, poly_eval, poly_interp)


def test_field(cls: type[Field]) -> None:
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
    assert x.inv() == cls(x.val**-1)

    # Test serialization.
    want = cls.rand_vec(10)
    got = cls.decode_vec(cls.encode_vec(want))
    assert got == want

    # Test encoding integer as bit vector.
    vals = [i for i in range(15)]
    bits = 4
    for val in vals:
        encoded = cls.encode_into_bit_vector(val, bits)
        assert cls.decode_from_bit_vector(encoded).as_unsigned() == val


def test_fft_field(cls: type[FftField]) -> None:
    test_field(cls)

    # Test generator.
    assert cls.gen()**cls.GEN_ORDER == cls(1)


class TestFields(unittest.TestCase):
    def test_field64(self) -> None:
        test_fft_field(Field64)

    def test_field96(self) -> None:
        test_fft_field(Field96)

    def test_field128(self) -> None:
        test_fft_field(Field128)

    def test_field255(self) -> None:
        test_field(Field255)

    def test_field2(self) -> None:
        # Test GF(2).
        assert Field2(1).as_unsigned() == 1
        assert Field2(0).as_unsigned() == 0
        assert Field2(1) + Field2(1) == Field2(0)
        assert Field2(1) * Field2(1) == Field2(1)
        assert -Field2(1) == Field2(1)
        assert Field2(1).conditional_select(b'hello') == b'hello'
        assert Field2(0).conditional_select(b'hello') == bytes([0, 0, 0, 0, 0])

    def test_interp(self) -> None:
        # Test polynomial interpolation.
        cls = Field64
        p = cls.rand_vec(10)
        xs = [cls(x) for x in range(10)]
        ys = [poly_eval(cls, p, x) for x in xs]
        q = poly_interp(cls, xs, ys)
        for x in xs:
            a = poly_eval(cls, p, x)
            b = poly_eval(cls, q, x)
            assert a == b
