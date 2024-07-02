import unittest
from typing import TypeVar

from common import next_power_of_2
from field import FftField, Field64, Field96, Field128, poly_eval
from flp import Flp, run_flp
from flp_bbcggi19 import (Count, FlpBBCGGI19, Gadget, Histogram, Mul,
                          MultihotCountVec, PolyEval, Range2, Sum,
                          SumOfRangeCheckedInputs, SumVec, Valid)

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=FftField)


class TestMultiGadget(Valid[int, int, Field64]):
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
        return output[0].as_unsigned()


def test_gadget(g: Gadget, field: type[F], test_length: int) -> None:
    """
    Test for equivalence of `Gadget.eval()` and `Gadget.eval_poly()`.
    """
    meas_poly = []
    meas = []
    eval_at = field.rand_vec(1)[0]
    for _ in range(g.ARITY):
        meas_poly.append(field.rand_vec(test_length))
        meas.append(poly_eval(field, meas_poly[-1], eval_at))
    out_poly = g.eval_poly(field, meas_poly)

    want = g.eval(field, meas)
    got = poly_eval(field, out_poly, eval_at)
    assert got == want


def test_flp_bbcggi19(
        flp: FlpBBCGGI19[Measurement, AggResult, F],
        test_cases: list[tuple[list[F], bool]]) -> None:
    for (g, g_calls) in zip(flp.valid.GADGETS, flp.valid.GADGET_CALLS):
        test_gadget(g, flp.field, next_power_of_2(g_calls + 1))

    for (i, (meas, expected_decision)) in enumerate(test_cases):
        assert len(meas) == flp.MEAS_LEN
        assert len(flp.truncate(meas)) == flp.OUTPUT_LEN

        # Evaluate validity circuit.
        joint_rand = flp.field.rand_vec(flp.JOINT_RAND_LEN)
        v = flp.valid.eval(meas, joint_rand, 1)
        if (v == [flp.field(0)] * flp.valid.EVAL_OUTPUT_LEN) != \
                expected_decision:
            print('{}: test {} failed: validity circuit returned {}'.format(
                flp.valid.__class__.__name__, i, v))

        # Run the FLP.
        decision = run_flp(flp, meas, 2)
        if decision != expected_decision:
            print(
                '{}: test {} failed: proof evaluation resulted in {}; want {}'
                .format(
                    flp.valid.__class__.__name__, i, decision,
                    expected_decision,
                )
            )


class TestAverage(Sum):
    """
    Flp subclass that calculates the average of integers. The result is rounded
    down.
    """

    def decode(self, output: list[Field128], num_measurements: int) -> int:
        total = super().decode(output, num_measurements)
        return total // num_measurements


# Test encoding, truncation, then decoding.
def test_encode_truncate_decode(
        flp: Flp[Measurement, AggResult, F],
        measurements: list[Measurement]) -> None:
    for measurement in measurements:
        assert measurement == flp.decode(
            flp.truncate(flp.encode(measurement)), 1)


def test_encode_truncate_decode_with_fft_fields(
        measurements: list[list[int]],
        length: int,
        bits: int,
        chunk_length: int) -> None:
    for field in [Field64, Field96, Field128]:
        sumvec = SumVec[FftField](field, length, bits, chunk_length)
        assert sumvec.field == field
        assert isinstance(sumvec, SumVec)
        test_encode_truncate_decode(FlpBBCGGI19(sumvec), measurements)


class TestFlpBBCGGI19(unittest.TestCase):
    def test_count(self) -> None:
        flp = FlpBBCGGI19(Count(Field64))
        test_flp_bbcggi19(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            ([flp.field(1337)], False),
        ])

    def test_sum(self) -> None:
        flp = FlpBBCGGI19(Sum(Field128, 10))
        test_flp_bbcggi19(flp, [
            (flp.encode(0), True),
            (flp.encode(100), True),
            (flp.encode(2 ** 10 - 1), True),
            (flp.field.rand_vec(10), False),
        ])
        test_encode_truncate_decode(flp, [0, 100, 2 ** 10 - 1])

    def test_sum_of_range_checked_inputs(self) -> None:
        flp = FlpBBCGGI19(SumOfRangeCheckedInputs(Field128, 10_000))
        test_flp_bbcggi19(flp, [
            (flp.encode(0), True),
            (flp.encode(1337), True),
            (flp.encode(9_999), True),
            (flp.field.zeros(flp.MEAS_LEN), False),
        ])

    def test_histogram(self) -> None:
        flp = FlpBBCGGI19(Histogram(Field128, 4, 2))
        test_flp_bbcggi19(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            (flp.encode(2), True),
            (flp.encode(3), True),
            ([flp.field(0)] * 4, False),
            ([flp.field(1)] * 4, False),
            (flp.field.rand_vec(4), False),
        ])

    def test_multihot_count_vec(self) -> None:
        valid = MultihotCountVec(Field128, 4, 2, 2)
        flp = FlpBBCGGI19(valid)

        # Successful cases:
        cases = [
            (flp.encode([0, 0, 0, 0]), True),
            (flp.encode([0, 1, 0, 0]), True),
            (flp.encode([0, 1, 1, 0]), True),
            (flp.encode([1, 1, 0, 0]), True),
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
        cases += [(flp.encode([flp.field.MODULUS - 1, 1, 0, 0]), False)]
        test_flp_bbcggi19(flp, cases)

    def test_multihot_count_vec_small(self) -> None:
        flp = FlpBBCGGI19(MultihotCountVec(Field128, 1, 1, 1))

        test_flp_bbcggi19(flp, [
            (flp.encode([0]), True),
            (flp.encode([1]), True),
            ([flp.field(0), flp.field(1337)], False),
            ([flp.field(1), flp.field(0)], False),
        ])

    def test_sumvec(self) -> None:
        # SumVec with length 2, bits 4, chunk len 1.
        test_encode_truncate_decode_with_fft_fields(
            [[1, 2], [3, 4], [5, 6], [7, 8]],
            2,
            4,
            1,
        )

    def test_multigadget(self) -> None:
        flp = FlpBBCGGI19(TestMultiGadget())
        test_flp_bbcggi19(flp, [
            (flp.encode(0), True),
        ])


class TestGadget(unittest.TestCase):
    def test_range2(self) -> None:
        test_gadget(Range2(), Field128, 10)

    def test_polyeval(self) -> None:
        test_gadget(PolyEval([0, -23, 1, 3]), Field128, 10)
