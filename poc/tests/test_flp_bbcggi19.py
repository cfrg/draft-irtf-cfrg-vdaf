from typing import Any, TypeVar

from vdaf_poc.field import Field64, Field96, Field128, NttField
from vdaf_poc.flp_bbcggi19 import (Count, FlpBBCGGI19, Histogram, Mul,
                                   MultihotCountVec, PolyEval, Sum, SumVec,
                                   Valid)
from vdaf_poc.test_utils import TestFlpBBCGGI19

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)


class MultiGadget(Valid[int, int, Field64]):
    # Associated parameters
    field = Field64
    GADGETS = [Mul(), Mul()]
    GADGET_CALLS = [1, 2]
    MEAS_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1
    EVAL_OUTPUT_LEN = 1

    def eval(
            self,
            meas: list[Field64],
            joint_rand: list[Field64],
            _num_shares: int) -> list[Field64]:
        self.check_valid_eval(meas, joint_rand)
        # Not a very useful circuit, obviously. We just want to do something.
        x = self.GADGETS[0].eval(self.field, [meas[0], meas[0]])
        y = self.GADGETS[1].eval(self.field, [meas[0], x])
        z = self.GADGETS[1].eval(self.field, [x, y])
        return [z]

    def encode(self, measurement: int) -> list[Field64]:
        return [self.field(measurement)]

    def truncate(self, meas: list[Field64]) -> list[Field64]:
        return meas

    def decode(self, output: list[Field64], _num_measurements: int) -> int:
        return output[0].int()


class HigherDegree(Valid[list[int], list[int], Field64]):
    """
    A validity circuit for use in tests that includes a gadget with a
    configurable degree.

    Measurements are a vector of integers, and the validity circuit performs
    range checks on each element of the measurement using polynomials of the
    form x * (x - 1) * (x - 2) * ... * (x - (degree - 1)). The validity
    circuit outputs the result of all these polynomial evaluations.
    """
    # Associated parameters
    field = Field64
    JOINT_RAND_LEN = 0

    def __init__(self, degree: int, gadget_calls: int):
        self.degree = degree
        self.gadget_calls = gadget_calls

        polynomial = [1]
        for i in range(degree):
            polynomial = poly_mul_int(polynomial, [-i, 1])

        self.GADGETS = [PolyEval(polynomial)]
        self.GADGET_CALLS = [gadget_calls]
        self.MEAS_LEN = gadget_calls
        self.OUTPUT_LEN = gadget_calls
        self.EVAL_OUTPUT_LEN = gadget_calls

    def eval(
            self,
            meas: list[Field64],
            joint_rand: list[Field64],
            _num_shares: int) -> list[Field64]:
        self.check_valid_eval(meas, joint_rand)
        return [
            self.GADGETS[0].eval(self.field, [x])
            for x in meas
        ]

    def encode(self, measurement: list[int]) -> list[Field64]:
        return [self.field(elem) for elem in measurement]

    def truncate(self, meas: list[Field64]) -> list[Field64]:
        return meas

    def decode(self, output: list[Field64], _num_measurements: int) -> list[int]:
        return [x.int() for x in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['degree'] = self.degree
        test_vec['gadget_calls'] = self.gadget_calls
        return ['degree', 'gadget_calls']


def poly_mul_int(p: list[int], q: list[int]) -> list[int]:
    """
    Computes the product of two polynomials, represented as a list of monomial
    coefficients. This operates over the integers instead of a finite field.
    """
    r = [0] * (len(p) + len(q) - 1)
    for i in range(len(p)):
        for j in range(len(q)):
            r[i + j] += p[i] * q[j]
    return r


class TestAverage(Sum):
    """
    Flp subclass that calculates the average of integers. The result is rounded
    down.
    """

    def decode(self, output: list[Field64], num_measurements: int) -> int:
        total = super().decode(output, num_measurements)
        return total // num_measurements


class TestCount(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(Count(Field64))
        self.run_flp_test(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            ([flp.field(1337)], False),
        ])


class TestSum(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(Sum(Field64, 10_000))
        self.run_flp_test(flp, [
            (flp.encode(0), True),
            (flp.encode(1337), True),
            (flp.encode(9999), True),
            (flp.encode(10000), True),
            (flp.field.zeros(flp.MEAS_LEN), False),
        ])


class TestHistogram(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(Histogram(Field128, 4, 2))
        self.run_flp_test(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            (flp.encode(2), True),
            (flp.encode(3), True),
            ([flp.field(0)] * 4, False),
            ([flp.field(1)] * 4, False),
            (flp.field.rand_vec(4), False),
        ])


class TestMultihotCountVec(TestFlpBBCGGI19):
    def test(self) -> None:
        valid = MultihotCountVec(Field128, 4, 2, 2)
        flp = FlpBBCGGI19(valid)

        # Successful cases:
        cases = [
            (flp.encode([False, False, False, False]), True),
            (flp.encode([False, True, False, False]), True),
            (flp.encode([False, True, True, False]), True),
            (flp.encode([True, True, False, False]), True),
        ]
        # Failure cases: too many number of 1s, should fail weight check.
        cases += [
            (
                [flp.field(1)] * i
                + [flp.field(0)] * (valid.length - i)
                # Try to lie about the offset weight.
                + [flp.field(0)] * valid.bits_for_weight,
                False
            )
            for i in range(valid.max_weight + 1, valid.length + 1)
        ]
        # Failure case: pass count check but fail bit check.
        cases += [
            (
                [
                    flp.field(flp.field.MODULUS - 1),
                    flp.field(1),
                    flp.field(0),
                    flp.field(0),
                ]
                + [flp.field(0)] * valid.bits_for_weight,
                False
            )
        ]
        self.run_flp_test(flp, cases)

    def test_small(self) -> None:
        flp = FlpBBCGGI19(MultihotCountVec(Field128, 1, 1, 1))

        self.run_flp_test(flp, [
            (flp.encode([False]), True),
            (flp.encode([True]), True),
            ([flp.field(0), flp.field(1337)], False),
            ([flp.field(1), flp.field(0)], False),
        ])


class TestSumVec(TestFlpBBCGGI19):
    def run_encode_truncate_decode_with_ntt_fields_test(
            self,
            measurements: list[list[int]],
            length: int,
            bits: int,
            chunk_length: int) -> None:
        for field in [Field64, Field96, Field128]:
            sumvec = SumVec[NttField](field, length, bits, chunk_length)
            self.assertEqual(sumvec.field, field)
            self.assertTrue(isinstance(sumvec, SumVec))
            self.run_encode_truncate_decode_test(
                FlpBBCGGI19(sumvec), measurements)

    def test(self) -> None:
        # SumVec with length 2, bits 4, chunk len 1.
        self.run_encode_truncate_decode_with_ntt_fields_test(
            [[1, 2], [3, 4], [5, 6], [7, 8]],
            2,
            4,
            1,
        )


class TestMultiGadget(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(MultiGadget())
        self.run_flp_test(flp, [
            (flp.encode(0), True),
        ])


class TestHigherDegree(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(HigherDegree(3, 1))
        self.run_flp_test(flp, [
            (flp.encode([0]), True),
            (flp.encode([1]), True),
            (flp.encode([2]), True),
            (flp.encode([3]), False),
        ])

        flp = FlpBBCGGI19(HigherDegree(5, 2))
        self.run_flp_test(flp, [
            (flp.encode([0, 4]), True),
            (flp.encode([0, 5]), False),
            (flp.encode([3, 2]), True),
            (flp.encode([10, 15]), False),
        ])


class TestGadgets(TestFlpBBCGGI19):
    def test_poly_eval_range2(self) -> None:
        self.run_gadget_test(PolyEval([0, -1, 1]), Field128, 10)

    def test_poly_eval(self) -> None:
        self.run_gadget_test(
            PolyEval([0, -23, 1, 3]),
            Field128,
            10,
        )
