import unittest

from vdaf_poc.field import (Field, Field2, Field64, Field96, Field128,
                            Field255, NttField, poly_eval, poly_interp)


class TestFields(unittest.TestCase):
    def run_field_test(self, cls: type[Field]) -> None:
        # Test constructing a field element from an integer.
        self.assertTrue(cls(1337) == cls(cls.gf(1337)))

        # Test generating a zero-vector.
        vec = cls.zeros(23)
        self.assertTrue(len(vec) == 23)
        for x in vec:
            self.assertTrue(x == cls(cls.gf.zero()))

        # Test generating a random vector.
        vec = cls.rand_vec(23)
        self.assertTrue(len(vec) == 23)

        # Test arithmetic.
        x = cls(cls.gf.random_element())
        y = cls(cls.gf.random_element())
        self.assertTrue(x + y == cls(x.val + y.val))
        self.assertTrue(x - y == cls(x.val - y.val))
        self.assertTrue(-x == cls(-x.val))
        self.assertTrue(x * y == cls(x.val * y.val))
        self.assertTrue(x.inv() == cls(x.val**-1))

        # Test serialization.
        want = cls.rand_vec(10)
        got = cls.decode_vec(cls.encode_vec(want))
        self.assertTrue(got == want)

        # Test encoding integer as bit vector.
        vals = [i for i in range(15)]
        bits = 4
        for val in vals:
            encoded = cls.encode_into_bit_vector(val, bits)
            self.assertTrue(cls.decode_from_bit_vector(
                encoded).as_unsigned() == val)

    def run_ntt_field_test(self, cls: type[NttField]) -> None:
        self.run_field_test(cls)

        # Test generator.
        self.assertTrue(cls.gen()**cls.GEN_ORDER == cls(1))

    def test_field64(self) -> None:
        self.run_ntt_field_test(Field64)

    def test_field96(self) -> None:
        self.run_ntt_field_test(Field96)

    def test_field128(self) -> None:
        self.run_ntt_field_test(Field128)

    def test_field255(self) -> None:
        self.run_field_test(Field255)

    def test_field2(self) -> None:
        # Test GF(2).
        self.assertEqual(Field2(1).as_unsigned(), 1)
        self.assertEqual(Field2(0).as_unsigned(), 0)
        self.assertEqual(Field2(1) + Field2(1), Field2(0))
        self.assertEqual(Field2(1) * Field2(1), Field2(1))
        self.assertEqual(-Field2(1), Field2(1))
        self.assertEqual(Field2(1).conditional_select(b'hello'), b'hello')
        self.assertEqual(Field2(0).conditional_select(
            b'hello'), bytes([0, 0, 0, 0, 0]))

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
            self.assertEqual(a, b)
