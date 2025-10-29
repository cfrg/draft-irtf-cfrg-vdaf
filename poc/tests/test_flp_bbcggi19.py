from typing import TypeVar

from vdaf_poc.common import next_power_of_2
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


class HigherDegree(Valid[int, int, Field64]):
    """
    A validity circuit for use in tests that contains a gadget of degree 3.
    """
    # Associated parameters
    field = Field64
    GADGETS = [PolyEval([0, 2, -3, 1], 1)]  # x * (x - 1) * (x - 2)
    GADGET_CALLS = [1]
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
        return [
            self.GADGETS[0].eval(self.field, [meas[0]]),
        ]

    def encode(self, measurement: int) -> list[Field64]:
        return [self.field(measurement)]

    def truncate(self, meas: list[Field64]) -> list[Field64]:
        return meas

    def decode(self, output: list[Field64], _num_measurements: int) -> int:
        return output[0].int()


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
            (flp.field.zeros(flp.MEAS_LEN), True),
            ([flp.field(2)] * flp.MEAS_LEN, False),
        ])

        self.assertRaises(ValueError, lambda: flp.encode(10001))


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
                # Try to lie about the weight.
                + [flp.field(1)] * valid.bits_for_weight,
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

        self.assertRaises(
            ValueError,
            lambda: flp.encode([True, True, True, False])
        )

    def test_max_6(self) -> None:
        # length=8, max_weight=6
        valid = MultihotCountVec(Field128, 8, 6, 3)
        flp = FlpBBCGGI19(valid)
        # Note that the claimed weight is encoded with three elements, weighted
        # with 1, 2, and 3.

        # Successful cases:
        cases = [
            (
                flp.encode(
                    [True, True, True, True, True, True, False, False],
                ),
                True,
            ),
            (
                flp.encode(
                    [False, True, False, True, True, True, True, True],
                ),
                True,
            ),
            (flp.encode([False] * 8), True),
            (
                flp.encode(
                    [True, True, False, False, False, False, False, False],
                ),
                True,
            ),
            (
                flp.encode(
                    [True, True, True, True, True, False, False, False],
                ),
                True,
            ),
        ]

        # Successful cases: alternate representations of a claimed weight of 3
        cases += [
            (
                [flp.field(x) for x in [1, 1, 1, 0, 0, 0, 0, 0] + [1, 1, 0]],
                True,
            ),
            (
                [flp.field(x) for x in [1, 1, 1, 0, 0, 0, 0, 0] + [0, 0, 1]],
                True,
            ),
        ]

        # Failure cases: too many 1s, should fail weight check.
        cases += [
            (
                [flp.field(1)] * i
                + [flp.field(0)] * (valid.length - i)
                # Try to lie about the weight.
                + [flp.field(1)] * valid.bits_for_weight,
                False,
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
                    flp.field(0),
                    flp.field(0),
                    flp.field(0),
                    flp.field(0),
                ]
                + [flp.field(0)] * valid.bits_for_weight,
                False,
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
            max_measurement: int,
            chunk_length: int) -> None:
        for field in [Field64, Field96, Field128]:
            sumvec = SumVec[NttField](
                field,
                length,
                max_measurement,
                chunk_length,
            )
            self.assertEqual(sumvec.field, field)
            self.assertTrue(isinstance(sumvec, SumVec))
            self.run_encode_truncate_decode_test(
                FlpBBCGGI19(sumvec), measurements)

    def test_afe(self) -> None:
        # SumVec with length 2, max_measurement 15, chunk len 1.
        self.run_encode_truncate_decode_with_ntt_fields_test(
            [[1, 2], [3, 4], [5, 6], [7, 8]],
            2,
            15,
            1,
        )

        # SumVec with length 2, max_measurement 6, chunk len 1.
        self.run_encode_truncate_decode_with_ntt_fields_test(
            [[1, 2], [3, 4], [5, 6]],
            2,
            6,
            1,
        )

        flp = FlpBBCGGI19(SumVec(Field128, 2, 10, 3))
        self.assertEqual(
            flp.truncate([flp.field(1)] * 8),
            [flp.field(10)] * 2
        )

        self.assertRaises(ValueError, lambda: flp.encode([0, 11]))
        self.assertRaises(ValueError, lambda: flp.encode([0, 30]))

    def test_flp(self) -> None:
        flp = FlpBBCGGI19(SumVec(Field128, 2, 10, 3))
        self.run_flp_test(flp, [
            (flp.encode([0, 10]), True),
            (flp.encode([5, 5]), True),
            (flp.field.zeros(8), True),
            ([flp.field(1)] * 8, True),
            ([flp.field(2)] * 8, False),
        ])


class TestMultiGadget(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(MultiGadget())
        self.run_flp_test(flp, [
            (flp.encode(0), True),
        ])


class TestHigherDegree(TestFlpBBCGGI19):
    def test(self) -> None:
        flp = FlpBBCGGI19(HigherDegree())
        self.run_flp_test(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            (flp.encode(2), True),
            (flp.encode(3), False),
        ])


class TestGadgets(TestFlpBBCGGI19):
    def test_poly_eval_range2(self) -> None:
        self.run_gadget_test(
            PolyEval([0, -1, 1], next_power_of_2(10)),
            Field128,
            next_power_of_2(10),
        )

    def test_poly_eval(self) -> None:
        self.run_gadget_test(
            PolyEval([0, -23, 1, 3], next_power_of_2(10)),
            Field128,
            next_power_of_2(10),
        )
