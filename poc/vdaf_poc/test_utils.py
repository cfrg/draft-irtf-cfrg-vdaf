import json
import os
import unittest
from typing import Any, Generic, Optional, TypedDict, TypeVar, cast

from vdaf_poc.common import (gen_rand, next_power_of_2, print_wrapped_line,
                             to_le_bytes)
from vdaf_poc.field import NttField, poly_eval
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
F = TypeVar("F", bound=NttField)


def test_vec_gen_rand(length: int) -> bytes:
    """
    A dummy source of randomness intended for creating reproducible test vectors.
    """
    out = []
    for i in range(length):
        out.append(i % 256)
    return bytes(out)


# VDAF

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
                              b"some application context",
                              nonces,
                              measurements)
        self.assertEqual(agg_result, expected_agg_result)


class VdafPrepTestVectorDict(Generic[Measurement], TypedDict):
    measurement: Measurement
    nonce: str
    input_shares: list[str]
    prep_shares: list[list[str]]
    prep_messages: list[str]
    out_shares: list[list[str]]
    rand: str
    public_share: str


class VdafTestVectorDict(Generic[Measurement, AggParam, AggResult], TypedDict):
    shares: int
    verify_key: str
    agg_param: str
    ctx: str
    prep: list[VdafPrepTestVectorDict[Measurement]]
    agg_shares: list[str]
    agg_result: Optional[AggResult]


def gen_test_vec_for_vdaf(
        test_vec_path: str,
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
        ctx: bytes,
        measurements: list[Measurement],
        test_vec_instance: int,
        print_test_vec: bool = True) -> AggResult:
    """
    Generate test vectors for a VDAF.
    """

    nonces = [test_vec_gen_rand(vdaf.NONCE_SIZE)
              for _ in range(len(measurements))]
    verify_key = test_vec_gen_rand(vdaf.VERIFY_KEY_SIZE)

    test_vec: VdafTestVectorDict[Measurement, AggParam, AggResult] = {
        'shares': vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': vdaf.encode_agg_param(agg_param).hex(),
        'ctx': ctx.hex(),
        'prep': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_params = vdaf.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == vdaf.NONCE_SIZE

        # Each Client shards its measurement into input shares.
        rand = test_vec_gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(ctx, measurement, nonce, rand)

        pub_share_hex = vdaf.test_vec_encode_public_share(public_share).hex()
        prep_test_vec: VdafPrepTestVectorDict[Measurement] = {
            'measurement': measurement,
            'nonce': nonce.hex(),
            'rand': rand.hex(),
            'public_share': pub_share_hex,
            'input_shares': [],
            'prep_shares': [[] for _ in range(vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
        }
        for input_share in input_shares:
            prep_test_vec['input_shares'].append(
                vdaf.test_vec_encode_input_share(input_share).hex())

        # Each Aggregator initializes its preparation state.
        prep_states = []
        outbound_prep_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.prep_init(verify_key, ctx, j,
                                            agg_param,
                                            nonce,
                                            public_share,
                                            input_shares[j])
            prep_states.append(state)
            outbound_prep_shares.append(share)

        for prep_share in outbound_prep_shares:
            prep_test_vec['prep_shares'][0].append(
                vdaf.test_vec_encode_prep_share(prep_share).hex())

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS - 1):
            prep_msg = vdaf.prep_shares_to_prep(ctx,
                                                agg_param,
                                                outbound_prep_shares)
            prep_test_vec['prep_messages'].append(
                vdaf.test_vec_encode_prep_msg(prep_msg).hex())

            outbound_prep_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(ctx, prep_states[j], prep_msg)
                assert isinstance(out, tuple)
                (prep_states[j], prep_share) = out
                outbound_prep_shares.append(prep_share)
            # REMOVE ME
            for prep_share in outbound_prep_shares:
                prep_test_vec['prep_shares'][i+1].append(
                    vdaf.test_vec_encode_prep_share(prep_share).hex()
                )

        # The final outputs of the prepare phase are the output
        # shares.
        prep_msg = vdaf.prep_shares_to_prep(ctx,
                                            agg_param,
                                            outbound_prep_shares)
        prep_test_vec['prep_messages'].append(
            vdaf.test_vec_encode_prep_msg(prep_msg).hex())

        outbound_out_shares = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(ctx, prep_states[j], prep_msg)
            assert not isinstance(out_share, tuple)
            outbound_out_shares.append(out_share)

        for out_share in outbound_out_shares:
            prep_test_vec['out_shares'].append([
                to_le_bytes(x.int(), x.ENCODED_SIZE).hex()
                for x in out_share
            ])
        test_vec['prep'].append(prep_test_vec)

        out_shares.append(outbound_out_shares)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.agg_init(agg_param)
        for out_share in out_shares_j:
            agg_share_j = vdaf.agg_update(agg_param, agg_share_j, out_share)
        agg_shares.append(agg_share_j)
        # REMOVE ME
        test_vec['agg_shares'].append(
            vdaf.test_vec_encode_agg_share(agg_share_j).hex())

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    test_vec['agg_result'] = agg_result
    if print_test_vec:
        _pretty_print_vdaf_test_vec(vdaf, test_vec, type_params)

        os.system('mkdir -p {}'.format(test_vec_path))
        filename = '{}/{}_{}.json'.format(
            test_vec_path,
            vdaf.test_vec_name,
            test_vec_instance,
        )
        with open(filename, 'w', encoding="UTF-8") as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def _pretty_print_vdaf_test_vec(
        vdaf: Vdaf[
            Measurement, AggParam, Any, Any, Any, Any, AggResult, Any, Any, Any
        ],
        typed_test_vec: VdafTestVectorDict[Measurement, AggParam, AggResult],
        type_params: list[str]) -> None:
    test_vec = cast(dict[str, Any], typed_test_vec)
    print('---------- {} ---------------'.format(vdaf.test_vec_name))
    for type_param in type_params:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] is not None:
        print('agg_param: {}'.format(test_vec['agg_param']))

    for (n, prep_test_vec) in enumerate(test_vec['prep']):
        print('upload_{}:'.format(n))
        print('  measurement: {}'.format(prep_test_vec['measurement']))
        print('  nonce: "{}"'.format(prep_test_vec['nonce']))
        print('  public_share: >-')
        print_wrapped_line(prep_test_vec['public_share'], tab=4)

        # Shard
        for (i, input_share) in enumerate(prep_test_vec['input_shares']):
            print('  input_share_{}: >-'.format(i))
            print_wrapped_line(input_share, tab=4)

        # Prepare
        for (i, (prep_shares, prep_msg)) in enumerate(
                zip(prep_test_vec['prep_shares'],
                    prep_test_vec['prep_messages'])):
            print('  round_{}:'.format(i))
            for (j, prep_share) in enumerate(prep_shares):
                print('    prep_share_{}: >-'.format(j))
                print_wrapped_line(prep_share, tab=6)
            print('    prep_message: >-')
            print_wrapped_line(prep_msg, tab=6)

        for (j, out_shares) in enumerate(prep_test_vec['out_shares']):
            print('  out_share_{}:'.format(j))
            for out_share in out_shares:
                print('    - {}'.format(out_share))

    # Aggregate
    for (j, agg_share) in enumerate(test_vec['agg_shares']):
        print('agg_share_{}: >-'.format(j))
        print_wrapped_line(agg_share, tab=2)

    # Unshard
    print('agg_result: {}'.format(test_vec['agg_result']))
    print()


# FLP

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
