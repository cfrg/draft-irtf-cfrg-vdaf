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

    def run_ntt_field_test(self, cls: type[NttField]) -> None:
        self.run_field_test(cls)

        # Test generator.
        self.assertTrue(cls.gen()**cls.GEN_ORDER == cls(1))

        for log_n in range(8):
            self.run_nth_roots_test(cls, log_n)
            self.run_ntt_test(cls, log_n)
            self.run_ntt_set_s_test(cls, log_n)

    def run_nth_roots_test(self, cls: type[NttField], log_n: int) -> None:
        one = cls(1)
        # Tests the first root of unity is one.
        self.assertEqual(cls.nth_root(0), one)
        # Tests that the n-th root of unity has the right order.
        self.assertEqual(cls.nth_root(log_n)**(1 << log_n), one)
        # Tests that the n-th root of unity is not of a lower order.
        for log_k in range(log_n):
            self.assertNotEqual(cls.nth_root(log_n)**(1 << log_k), one)

    def run_ntt_test(self, cls: type[NttField], log_n: int) -> None:
        # Tests that NTT(P) is the same as evaluating the polynomial P
        # on the powers of an n-th root of unity.
        n = 1 << log_n
        p_mon = cls.rand_vec(n)  # a random polynomial in the monomial basis.
        got = cls.ntt(p_mon, n)

        root = cls.nth_root(log_n)
        want = [poly_eval(cls, p_mon, root**i) for i in range(n)]
        self.assertEqual(got, want, f"log_n: {log_n} p_mon: {p_mon}")

    def run_ntt_set_s_test(self, cls: type[NttField], log_n: int) -> None:
        # Tests that NTT(set_s=True) is the same as evaluating P on
        # the powers of an n-th root of unity times a 2n-th root of
        # unity.
        n = 1 << log_n
        p_mon = cls.rand_vec(n)  # a random polynomial in the monomial basis.
        root_n = cls.nth_root(log_n)
        root_2n = cls.nth_root(log_n+1)
        want = [
            poly_eval(cls, p_mon, root_2n*(root_n**i)) for i in range(n)
        ]
        got = cls.ntt(p_mon, n, True)
        self.assertEqual(got, want, f"log_n: {log_n} p_mon: {p_mon}")

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
        n = 16
        p_mon_batch = []
        p_lag_batch = []
        for _ in range(4):
            p_mon = self.field.rand_vec(n)
            p_lag = self.field.ntt(p_mon, n)
            p_mon_batch.append(p_mon)
            p_lag_batch.append(p_lag)

        # Evaluating polynomials at the nodes and at random values.
        lag = Lagrange(self.field)
        nodes = self.field.nth_root_powers(n)
        random_values = self.field.rand_vec(100)
        for points in [nodes, random_values]:
            for x in points:
                a = [poly_eval(self.field, p, x) for p in p_mon_batch]
                b = lag.poly_eval_batched(p_lag_batch, x)
                self.assertEqual(a, b, f"x: {x}")

    def test_poly_change_basis(self) -> None:
        for log_n in range(8):
            n = 1 << log_n
            p_mon = self.field.rand_vec(n)
            p_lag = self.field.ntt(p_mon, n)
            got = self.field.inv_ntt(p_lag, n)
            self.assertEqual(got, p_mon, f"log_n: {log_n} p_mon: {p_mon}")

    def test_poly_mul_lagrange(self) -> None:
        for log_n in range(8):
            n = 1 << log_n
            p_mon = self.field.rand_vec(n)
            q_mon = self.field.rand_vec(n)
            p_lag = self.field.ntt(p_mon, n)
            q_lag = self.field.ntt(q_mon, n)
            got = Lagrange(self.field).poly_mul(p_lag, q_lag)
            r_mon = poly_mul(self.field, p_mon, q_mon)
            want = self.field.ntt(r_mon, 2*n)
            self.assertEqual(
                got, want,
                f"log_n: {log_n} p_mon: {p_mon} q_mon: {q_mon}"
            )

    def test_extend_values_to_power_of_2(self) -> None:
        # Given k coefficients of a polynomial, the function
        # must recover all the n Lagrange values, for all 0 ≤ k ≤ n,
        # where n must be a power of two.
        lag = Lagrange(self.field)
        for log_n in range(7):
            n = 1 << log_n
            for k in range(n+1):
                # Generate a random polynomial in monomial basis.
                p_mon = self.field.rand_vec(k) + [self.field(0)]*(n-k)
                # Convert polynomial to Lagrange basis.
                p_lag = self.field.ntt(p_mon, n)
                # Truncate to k values only.
                p_lag_truncated = p_lag[:k]
                # Recover the n original values (in-place).
                lag.extend_values_to_power_of_2(p_lag_truncated, n)
                # Verify that values are fully recovered.
                self.assertEqual(p_lag_truncated, p_lag,
                                 f"n: {n} k: {k} p_mon: {p_mon}")

    def test_double_evaluations(self) -> None:
        # Given n values of a polynomial, the function must recover
        # 2n values, where n must be a power of two.
        lag = Lagrange(self.field)
        for log_n in range(8):
            n = 1 << log_n
            # Generate a random polynomial in monomial basis.
            p_mon = self.field.rand_vec(n)
            # Convert polynomial to Lagrange basis.
            p_lag_n = self.field.ntt(p_mon, n)
            # Double the number of evaluations with rhizomes algorithm.
            got = lag.double_evaluations(p_lag_n)
            # Double the number of evaluations with NTT.
            want = self.field.ntt(p_mon, 2*n)
            # Verify that values are fully recovered.
            self.assertEqual(got, want, f"n: {n}  p_mon: {p_mon}")
