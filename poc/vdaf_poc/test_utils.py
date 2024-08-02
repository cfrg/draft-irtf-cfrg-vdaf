import unittest
from typing import Any, TypeVar

from vdaf_poc.common import gen_rand, next_power_of_2
from vdaf_poc.field import FftField, poly_eval
from vdaf_poc.flp import Flp, run_flp
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19, Gadget
from vdaf_poc.vdaf import Vdaf, run_vdaf

Measurement = TypeVar("Measurement")
AggParam = TypeVar("AggParam")
PublicShare = TypeVar("PublicShare")
InputShare = TypeVar("InputShare")
OutShare = TypeVar("OutShare")
AggShare = TypeVar("AggShare")
AggResult = TypeVar("AggResult")
PrepState = TypeVar("PrepState")
PrepShare = TypeVar("PrepShare")
PrepMessage = TypeVar("PrepMessage")
F = TypeVar("F", bound=FftField)


class TestVdaf(unittest.TestCase):

    """Test harness for instances of `Vdaf`."""

    def run_vdaf_test(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                list[Any],  # OutShare
                AggShare,
                AggResult,
                PrepState,
                PrepShare,
                PrepMessage,
            ],
            agg_param: AggParam,
            measurements: list[Measurement],
            expected_agg_result: AggResult) -> None:
        # Test that the algorithm identifier is in the correct range.
        self.assertTrue(0 <= vdaf.ID and vdaf.ID < 2 ** 32)

        # Run the VDAF on the set of measurmenets.
        nonces = [gen_rand(vdaf.NONCE_SIZE) for _ in range(len(measurements))]
        verify_key = gen_rand(vdaf.VERIFY_KEY_SIZE)
        agg_result = run_vdaf(vdaf,
                              verify_key,
                              agg_param,
                              nonces,
                              measurements)
        self.assertEqual(agg_result, expected_agg_result)


class TestFlpBBCGGI19(unittest.TestCase):

    """Test harness for instances of `FlpBBCGGI19`."""

    def run_gadget_test(self, g: Gadget, field: type[F], test_length: int) -> None:
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
        self.assertEqual(got, want)

    def run_flp_test(self,
                     flp: FlpBBCGGI19[Measurement, AggResult, F],
                     test_cases: list[tuple[list[F], bool]]) -> None:
        """
        Run some generic tests on `flp`.
        """
        for (g, g_calls) in zip(flp.valid.GADGETS, flp.valid.GADGET_CALLS):
            self.run_gadget_test(g, flp.field, next_power_of_2(g_calls + 1))

        for (i, (meas, expected_decision)) in enumerate(test_cases):
            self.assertTrue(len(meas) == flp.MEAS_LEN)
            self.assertTrue(len(flp.truncate(meas)) == flp.OUTPUT_LEN)

            # Evaluate validity circuit.
            joint_rand = flp.field.rand_vec(flp.JOINT_RAND_LEN)
            v = flp.valid.eval(meas, joint_rand, 1)
            self.assertEqual(v == [flp.field(0)] * flp.valid.EVAL_OUTPUT_LEN,
                             expected_decision)

            # Run the FLP.
            decision = run_flp(flp, meas, 2)
            self.assertEqual(decision, expected_decision)

    def run_encode_truncate_decode_test(
            self,
            flp: Flp[Measurement, AggResult, F],
            measurements: list[Measurement]) -> None:
        """Test encoding, truncation, then decoding."""
        for measurement in measurements:
            self.assertEqual(measurement, flp.decode(
                flp.truncate(flp.encode(measurement)), 1))
