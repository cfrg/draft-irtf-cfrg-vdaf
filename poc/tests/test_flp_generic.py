import unittest

from common import ERR_INPUT, next_power_of_2
from field import Field64, Field96, Field128, poly_eval
from flp import run_flp
from flp_generic import (Count, FlpGeneric, Histogram, Mul, MultiHotHistogram,
                         PolyEval, Range2, Sum, SumVec, Valid)


class TestMultiGadget(Valid):
    # Associated types
    Field = Field64
    Measurement = int

    # Associated parameters
    GADGETS = [Mul(), Mul()]
    GADGET_CALLS = [1, 2]
    MEAS_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1

    def eval(self, meas, joint_rand, _num_shares):
        self.check_valid_eval(meas, joint_rand)
        # Not a very useful circuit, obviously. We just want to do something.
        x = self.GADGETS[0].eval(self.Field, [meas[0], meas[0]])
        y = self.GADGETS[1].eval(self.Field, [meas[0], x])
        z = self.GADGETS[1].eval(self.Field, [x, y])
        return z

    def encode(self, measurement):
        if measurement not in [0, 1]:
            raise ERR_INPUT
        return [self.Field(measurement)]

    def truncate(self, meas):
        if len(meas) != 1:
            raise ERR_INPUT
        return meas

    def decode(self, output, _num_measurements):
        return output[0].as_unsigned()


def test_gadget(g, Field, test_length):
    """
    Test for equivalence of `Gadget.eval()` and `Gadget.eval_poly()`.
    """
    meas_poly = []
    meas = []
    eval_at = Field.rand_vec(1)[0]
    for _ in range(g.ARITY):
        meas_poly.append(Field.rand_vec(test_length))
        meas.append(poly_eval(Field, meas_poly[-1], eval_at))
    out_poly = g.eval_poly(Field, meas_poly)

    want = g.eval(Field, meas)
    got = poly_eval(Field, out_poly, eval_at)
    assert got == want


def test_flp_generic(flp, test_cases):
    for (g, g_calls) in zip(flp.Valid.GADGETS, flp.Valid.GADGET_CALLS):
        test_gadget(g, flp.Field, next_power_of_2(g_calls + 1))

    for (i, (meas, expected_decision)) in enumerate(test_cases):
        assert len(meas) == flp.MEAS_LEN
        assert len(flp.truncate(meas)) == flp.OUTPUT_LEN

        # Evaluate validity circuit.
        joint_rand = flp.Field.rand_vec(flp.JOINT_RAND_LEN)
        v = flp.Valid.eval(meas, joint_rand, 1)
        if (v == flp.Field(0)) != expected_decision:
            print('{}: test {} failed: validity circuit returned {}'.format(
                flp.Valid.__class__.__name__, i, v))

        # Run the FLP.
        decision = run_flp(flp, meas, 2)
        if decision != expected_decision:
            print(
                '{}: test {} failed: proof evaluation resulted in {}; want {}'
                .format(
                    flp.Valid.__class__.__name__, i, decision,
                    expected_decision,
                )
            )


class TestAverage(Sum):
    """
    Flp subclass that calculates the average of integers. The result is rounded
    down.
    """
    # Associated types
    AggResult = int

    def decode(self, output, num_measurements):
        total = super().decode(output, num_measurements)
        return total // num_measurements


# Test encoding, truncation, then decoding.
def test_encode_truncate_decode(flp, measurements):
    for measurement in measurements:
        assert measurement == flp.decode(
            flp.truncate(flp.encode(measurement)), 1)


def test_encode_truncate_decode_with_fft_fields(cls, measurements, *args):
    for f in [Field64, Field96, Field128]:
        cls_with_field = cls.with_field(f)
        assert cls_with_field.Field == f
        obj = cls_with_field(*args)
        assert isinstance(obj, cls)
        test_encode_truncate_decode(FlpGeneric(obj), measurements)


class TestFlpGeneric(unittest.TestCase):
    def test_count(self):
        flp = FlpGeneric(Count())
        test_flp_generic(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            ([flp.Field(1337)], False),
        ])

    def test_sum(self):
        flp = FlpGeneric(Sum(10))
        test_flp_generic(flp, [
            (flp.encode(0), True),
            (flp.encode(100), True),
            (flp.encode(2 ** 10 - 1), True),
            (flp.Field.rand_vec(10), False),
        ])
        test_encode_truncate_decode(flp, [0, 100, 2 ** 10 - 1])

    def test_histogram(self):
        flp = FlpGeneric(Histogram(4, 2))
        test_flp_generic(flp, [
            (flp.encode(0), True),
            (flp.encode(1), True),
            (flp.encode(2), True),
            (flp.encode(3), True),
            ([flp.Field(0)] * 4, False),
            ([flp.Field(1)] * 4, False),
            (flp.Field.rand_vec(4), False),
        ])

    def test_multi_hot_histogram(self):
        # MultiHotHistogram with length = 4, max_count = 2, chunk_length = 2.
        flp = FlpGeneric(MultiHotHistogram(4, 2, 2))
        # Successful cases:
        cases = [
            (flp.encode([0, 0, 0, 0]), True),
            (flp.encode([0, 1, 0, 0]), True),
            (flp.encode([0, 1, 1, 0]), True),
            (flp.encode([1, 1, 0, 0]), True),
        ]
        # Failure cases: too many number of 1s, should fail count check.
        cases += [
            (
                [flp.Field(1)] * i +
                [flp.Field(0)] * (flp.Valid.length - i) +
                # Try to lie about the encoded count.
                [flp.Field(0)] * flp.Valid.bits_for_count,
                False
            )
            for i in range(flp.Valid.max_count + 1, flp.Valid.length + 1)
        ]
        # Failure case: pass count check but fail bit check.
        cases += [(flp.encode([flp.Field.MODULUS - 1, 1, 0, 0]), False)]
        test_flp_generic(flp, cases)

    def test_sumvec(self):
        # SumVec with length 2, bits 4, chunk len 1.
        test_encode_truncate_decode_with_fft_fields(
            SumVec,
            [[1, 2], [3, 4], [5, 6], [7, 8]],
            2,
            4,
            1,
        )

    def test_multigadget(self):
        flp = FlpGeneric(TestMultiGadget())
        test_flp_generic(flp, [
            (flp.encode(0), True),
        ])


class TestGadget(unittest.TestCase):
    def test_range2(self):
        test_gadget(Range2(), Field128, 10)

    def test_polyeval(self):
        test_gadget(PolyEval([0, -23, 1, 3]), Field128, 10)
