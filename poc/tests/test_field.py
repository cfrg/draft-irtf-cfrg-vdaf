import random
import unittest

from vdaf_poc.field import (Field, Field64, Field96, Field128, Field255,
                            Lagrange, NttField, poly_eval, poly_interp,
                            poly_mul)


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

        for logN in range(1, 8):
            self.run_nth_roots_test(cls, logN)

        for logN in range(8):
            self.run_ntt_test(cls, logN)
            self.run_ntt_star_test(cls, logN)

    def run_nth_roots_test(self, cls: type[NttField], logN: int) -> None:
        N = 1 << logN
        ONE = cls(1)
        self.assertEqual(cls.nth_root(0), ONE)
        self.assertEqual(cls.nth_root(logN)**N, ONE)
        self.assertNotEqual(cls.nth_root(logN)**(N >> 1), ONE)

    def run_ntt_test(self, cls: type[NttField], logN: int) -> None:
        N = 1 << logN
        p_mon = cls.rand_vec(N)
        got = cls.ntt(p_mon, N)

        root = cls.nth_root(logN)
        want = [poly_eval(cls, p_mon, root**i) for i in range(N)]
        self.assertEqual(
            got, want,
            f"logN: {logN} p_mon: {p_mon}"
        )

    def run_ntt_star_test(self, cls: type[NttField], logN: int) -> None:
        N = 1 << logN
        p_mon = cls.rand_vec(N)
        root_N = cls.nth_root(logN)
        root_2N = cls.nth_root(logN+1)
        want = [
            poly_eval(cls, p_mon, root_2N*(root_N**i)) for i in range(N)
        ]
        got = cls.ntt_star(p_mon, N)
        self.assertEqual(got, want, f"logN: {logN} p_mon: {p_mon}")

    def test_field64(self) -> None:
        self.run_ntt_field_test(Field64)

    def test_field96(self) -> None:
        self.run_ntt_field_test(Field96)

    def test_field128(self) -> None:
        self.run_ntt_field_test(Field128)

    def test_field255(self) -> None:
        self.run_field_test(Field255)


class TestPolynomials(unittest.TestCase):
    field = Field64

    def test_interp(self) -> None:
        # Test polynomial interpolation.
        cls = self.field
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
        N = 16
        p_mon_batch = []
        p_lag_batch = []
        for _ in range(4):
            p_mon = self.field.rand_vec(N)
            p_lag = self.field.ntt(p_mon, N)
            p_mon_batch.append(p_mon)
            p_lag_batch.append(p_lag)

        # Evaluating polynomials at the nodes and at random values.
        lag = Lagrange(self.field)
        nodes = self.field.nth_root_powers(N)
        random_values = self.field.rand_vec(100)
        for points in [nodes, random_values]:
            for x in points:
                a = [poly_eval(self.field, p, x) for p in p_mon_batch]
                b = lag.poly_eval_batched(nodes, p_lag_batch, x)
                self.assertEqual(a, b, f"x: {x}")

    def test_poly_change_basis(self) -> None:
        for n in range(8):
            N = 1 << n
            p_mon = self.field.rand_vec(N)
            p_lag = self.field.ntt(p_mon, N)
            got = self.field.inv_ntt(p_lag, N)
            self.assertEqual(got, p_mon, f"n: {n} p_mon: {p_mon}")

    def test_poly_mul_lagrange(self) -> None:
        for n in range(8):
            N = 1 << n
            p_mon = self.field.rand_vec(N)
            q_mon = self.field.rand_vec(N)
            p_lag = self.field.ntt(p_mon, N)
            q_lag = self.field.ntt(q_mon, N)
            got = Lagrange(self.field).poly_mul(p_lag, q_lag)
            r_mon = poly_mul(self.field, p_mon, q_mon)
            want = self.field.ntt(r_mon, 2*N)
            self.assertEqual(
                got, want, f"n: {n} p_mon: {p_mon} q_mon: {q_mon}"
            )
