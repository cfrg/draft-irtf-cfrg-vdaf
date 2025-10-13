import random
import unittest

from vdaf_poc.field import (Field, Field64, Field96, Field128, Field255,
                            NttField, poly_eval, poly_eval_lagrange,
                            poly_interp)


class TestFields(unittest.TestCase):
    def run_field_test(self, cls: type[Field]) -> None:
        # Test constructing a field element from an integer.
        self.assertTrue(cls(1337).val == 1337)

        # Test generating a zero-vector.
        vec = cls.zeros(23)
        self.assertTrue(len(vec) == 23)
        for x in vec:
            self.assertTrue(x.val == 0)

        # Test generating a random vector.
        vec = cls.rand_vec(23)
        self.assertTrue(len(vec) == 23)

        # Test arithmetic.
        x = cls(random.randrange(0, cls.MODULUS))
        y = cls(random.randrange(0, cls.MODULUS))
        self.assertEqual(x + y, cls((x.val + y.val) % cls.MODULUS))
        self.assertEqual(x - y, cls((x.val - y.val) % cls.MODULUS))
        self.assertEqual(-x, cls((-x.val) % cls.MODULUS))
        self.assertEqual(x * y, cls((x.val * y.val) % cls.MODULUS))
        self.assertEqual(x.inv() * x, cls(1))

        # Test serialization.
        want = cls.rand_vec(10)
        got = cls.decode_vec(cls.encode_vec(want))
        self.assertTrue(got == want)

        # Test encoding integer as bit vector.
        vals = [i for i in range(15)]
        bits = 4
        for val in vals:
            encoded = cls.encode_into_bit_vec(val, bits)
            self.assertTrue(cls.decode_from_bit_vec(
                encoded).int() == val)

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

    def test_poly_eval_lagrange(self) -> None:
        # Checks that (batched) polynomial evaluation agrees both
        # on the monomial and the Lagrange basis.
        cls = Field64
        N = 16  # must be a power of two.
        nth_root = cls.gen() ** (cls.GEN_ORDER // N)
        xs = [nth_root ** i for i in range(N)]
        polys_mon = []
        polys_lag = []
        for _ in range(4):
            p_mon = cls.rand_vec(N)
            p_lag = [poly_eval(cls, p_mon, x) for x in xs]
            polys_mon.append(p_mon)
            polys_lag.append(p_lag)

        # Evaluating polynomials at the nodes.
        for x in xs:
            a = [poly_eval(cls, p_mon, x) for p_mon in polys_mon]
            b = poly_eval_lagrange(cls, xs, polys_lag, x)
            self.assertEqual(a, b)

        # Evaluating polynomials at random values.
        for r in cls.rand_vec(100):
            a = [poly_eval(cls, p_mon, r) for p_mon in polys_mon]
            b = poly_eval_lagrange(cls, xs, polys_lag, r)
            self.assertEqual(a, b)
