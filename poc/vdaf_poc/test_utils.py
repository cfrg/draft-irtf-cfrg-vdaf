import json
import os
import unittest
from itertools import zip_longest
from typing import (Any, Generic, Literal, NotRequired, Optional, TypedDict,
                    TypeVar, cast)

from vdaf_poc.common import gen_rand, next_power_of_2, print_wrapped_line
from vdaf_poc.field import Lagrange, NttField
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
VerifyState = TypeVar("VerifyState")
VerifierShare = TypeVar("VerifierShare")
VerifierMessage = TypeVar("VerifierMessage")
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
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            agg_param: AggParam,
            measurements: list[Measurement],
            expected_agg_result: AggResult) -> None:
        # Test that the algorithm identifier is in the correct range.
        self.assertTrue(0 <= vdaf.ID and vdaf.ID < 2 ** 32)

        # Run the VDAF on the set of measurmenets.
        verify_key = gen_rand(vdaf.VERIFY_KEY_SIZE)
        agg_result = run_vdaf(vdaf,
                              verify_key,
                              agg_param,
                              b"some application context",
                              measurements)
        self.assertEqual(agg_result, expected_agg_result)


class VdafTestVectorOperationDict(TypedDict):
    """
    A description of one of the operations that should be performed with this
    test vector.

    Attributes:
        operation: The type of operation to be performed. This is one of
            "shard", "verify_init", "verifier_shares_to_message", "verify_next",
            "aggregate", or "unshard".

            Note that the "aggregate" operation encompasses running
            `agg_init()` and `agg_update()` to combine all output shares into
            an aggregate share.

        round: The round number of the operation to be performed. This
            determines which verifier share or message and which verification
            state to use.

        aggregator_id: The aggregator ID to use when performing this
            operation. This determines which messages and which verification
            state to use, in addition to the aggregator ID argument itself.

        report_index: The index of the report on which to perform this
            operation. This is an index into the `reports` array.

        success: If this is true, the operation should succeed, and its output
            should match the corresponding values in the test vector. If this
            is false, the operation should fail, terminating verification of
            this report.
    """
    operation: (
        Literal["shard"] | Literal["verify_init"]
        | Literal["verifier_shares_to_message"] | Literal["verify_next"]
        | Literal["aggregate"] | Literal["unshard"]
    )
    round: NotRequired[int]
    aggregator_id: NotRequired[int]
    report_index: NotRequired[int]
    success: bool


class VdafReportTestVectorDict(Generic[Measurement], TypedDict):
    """
    This lists VDAF messages related to one report, from sharding to
    verification.

    All VDAF messages are encoded to byte strings, and then hex-encoded.

    Attributes:
        measurement: The measurement used to produce the report.

        nonce: The report's nonce.

        rand: The randomness consumed by the sharding algorithm.

        public_share: The public share from the report.

        input_shares: The input shares from the report.

        verifier_shares: The verifier shares produced during verification. This is
        indexed first by round, and then by aggregator ID.

        verifier_messages: The verifier messages produced during verification. This
            is indexed by round.

        out_shares: The output shares produced by verifying this report. This
            is indexed by round.
    """
    measurement: Measurement
    nonce: str
    rand: str
    public_share: str
    input_shares: list[str]
    verifier_shares: list[list[str]]
    verifier_messages: list[str]
    out_shares: list[str]


class VdafTestVectorDict(Generic[Measurement, AggResult], TypedDict):
    """
    A test vector for evaluation of a VDAF on one or more reports.

    All VDAF messages are encoded to byte strings, and then hex-encoded.

    Attributes:
        operations: A list of operations that should be executed using
            messages from this test vector. These operations should be
            executed in the order they appear.

            The verification state passed between `verify_init()` and
            `verify_next()` does not have a standardized encoded form, and thus
            does not appear in the test vectors. Verification state values must
            be separately stored in between operations. Test vectors must list
            their operations in an order that ensures operations producing
            verification states for any given aggregator ID, report index, and
            round number always appear before operations that consume the same
            verification state in the next round.

        shares: The number of aggregators, and thus the number of input shares
            in a report.

        verify_key: The VDAF verification key.

        agg_param: The aggregation parameter.

        ctx: The context string.

        reports: A list of objects describing messages related to each report,
            from sharding to verification.

        agg_shares: The aggregate shares.

        agg_result: The aggregate result.
    """
    operations: list[VdafTestVectorOperationDict]
    shares: int
    verify_key: str
    agg_param: str
    ctx: str
    reports: list[VdafReportTestVectorDict[Measurement]]
    agg_shares: list[str]
    agg_result: Optional[AggResult]


def gen_test_vec_for_vdaf(
        test_vec_path: str,
        vdaf: Vdaf[
            Measurement,
            AggParam,
            PublicShare,
            InputShare,
            OutShare,
            AggShare,
            AggResult,
            VerifyState,
            VerifierShare,
            VerifierMessage,
        ],
        agg_param: AggParam,
        ctx: bytes,
        measurements: list[Measurement],
        test_vec_instance: int,
        print_test_vec: bool = True) -> \
        VdafTestVectorDict[Measurement, AggResult]:
    """
    Generate test vectors for successful evaluation of a VDAF.
    """

    nonces = [test_vec_gen_rand(vdaf.NONCE_SIZE)
              for _ in range(len(measurements))]
    verify_key = test_vec_gen_rand(vdaf.VERIFY_KEY_SIZE)
    operations: list[VdafTestVectorOperationDict] = []

    test_vec: VdafTestVectorDict[Measurement, AggResult] = {
        'operations': operations,
        'shares': vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': vdaf.encode_agg_param(agg_param).hex(),
        'ctx': ctx.hex(),
        'reports': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_params = vdaf.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )

    out_shares = []
    zip_iter = zip(nonces, measurements)
    for (report_index, (nonce, measurement)) in enumerate(zip_iter):
        assert len(nonce) == vdaf.NONCE_SIZE

        # Each Client shards its measurement into input shares.
        rand = test_vec_gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(ctx, measurement, nonce, rand)
        operations.append({
            'operation': 'shard',
            'report_index': report_index,
            'success': True,
        })

        pub_share_hex = vdaf.encode_public_share(public_share).hex()
        report_test_vec: VdafReportTestVectorDict[Measurement] = {
            'measurement': measurement,
            'nonce': nonce.hex(),
            'rand': rand.hex(),
            'public_share': pub_share_hex,
            'input_shares': [],
            'verifier_shares': [[] for _ in range(vdaf.ROUNDS)],
            'verifier_messages': [],
            'out_shares': [],
        }
        for input_share in input_shares:
            report_test_vec['input_shares'].append(
                vdaf.encode_input_share(input_share).hex())

        # Each Aggregator initializes its verification state.
        verify_states = []
        outbound_verifier_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.verify_init(verify_key, ctx, j,
                                              agg_param,
                                              nonce,
                                              public_share,
                                              input_shares[j])
            verify_states.append(state)
            outbound_verifier_shares.append(share)
            operations.append({
                'operation': 'verify_init',
                'aggregator_id': j,
                'report_index': report_index,
                'success': True,
            })

        for verifier_share in outbound_verifier_shares:
            report_test_vec['verifier_shares'][0].append(
                vdaf.encode_verifier_share(verifier_share).hex())

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS - 1):
            verifier_message = vdaf.verifier_shares_to_message(ctx,
                                                               agg_param,
                                                               outbound_verifier_shares)
            report_test_vec['verifier_messages'].append(
                vdaf.encode_verifier_message(verifier_message).hex())
            operations.append({
                'operation': 'verifier_shares_to_message',
                'round': i,
                'report_index': report_index,
                'success': True,
            })

            outbound_verifier_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.verify_next(ctx, verify_states[j], verifier_message)
                assert isinstance(out, tuple)
                (verify_states[j], verifier_share) = out
                outbound_verifier_shares.append(verifier_share)
                report_test_vec['verifier_shares'][i+1].append(
                    vdaf.encode_verifier_share(verifier_share).hex()
                )
                operations.append({
                    'operation': 'verify_next',
                    'round': i + 1,
                    'aggregator_id': j,
                    'report_index': report_index,
                    'success': True,
                })

        # The final outputs after verification are the output shares.
        verifier_message = vdaf.verifier_shares_to_message(ctx,
                                                           agg_param,
                                                           outbound_verifier_shares)
        report_test_vec['verifier_messages'].append(
            vdaf.encode_verifier_message(verifier_message).hex())
        operations.append({
            'operation': 'verifier_shares_to_message',
            'round': vdaf.ROUNDS - 1,
            'report_index': report_index,
            'success': True,
        })

        outbound_out_shares = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.verify_next(
                ctx, verify_states[j], verifier_message)
            assert not isinstance(out_share, tuple)
            outbound_out_shares.append(out_share)
            report_test_vec['out_shares'].append(
                vdaf.encode_out_share(out_share).hex()
            )
            operations.append({
                'operation': 'verify_next',
                'round': vdaf.ROUNDS,
                'aggregator_id': j,
                'report_index': report_index,
                'success': True,
            })

        test_vec['reports'].append(report_test_vec)

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
        test_vec['agg_shares'].append(
            vdaf.encode_agg_share(agg_share_j).hex())
        operations.append({
            'operation': 'aggregate',
            'aggregator_id': j,
            'success': True,
        })

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    test_vec['agg_result'] = agg_result
    operations.append({
        'operation': 'unshard',
        'success': True,
    })

    if print_test_vec:
        pretty_print_vdaf_test_vec(vdaf, test_vec, type_params)
        write_test_vec(
            test_vec_path,
            test_vec,
            vdaf.test_vec_name,
            str(test_vec_instance),
        )

    return test_vec


def write_test_vec(
        test_vec_path: str,
        test_vec: VdafTestVectorDict[Measurement, AggResult],
        test_vec_name: str,
        test_vec_suffix: str) -> None:
    """
    Write a test vector to a JSON file.
    """
    os.system('mkdir -p {}'.format(test_vec_path))
    filename = '{}/{}_{}.json'.format(
        test_vec_path,
        test_vec_name,
        test_vec_suffix,
    )
    with open(filename, 'w', encoding="UTF-8") as f:
        json.dump(test_vec, f, indent=4, sort_keys=True)
        f.write('\n')


def pretty_print_vdaf_test_vec(
        vdaf: Vdaf[
            Measurement, AggParam, Any, Any, Any, Any, AggResult, Any, Any, Any
        ],
        typed_test_vec: VdafTestVectorDict[Measurement, AggResult],
        type_params: list[str]) -> None:
    test_vec = cast(dict[str, Any], typed_test_vec)
    print('---------- {} ---------------'.format(vdaf.test_vec_name))
    for (i, operation) in enumerate(typed_test_vec['operations']):
        print('operation_{}:'.format(i))
        print('  operation: "{}"'.format(operation['operation']))
        if 'round' in operation:
            print('  round: {}'.format(operation['round']))
        if 'aggregator_id' in operation:
            print('  aggregator_id: {}'.format(operation['aggregator_id']))
        if 'report_index' in operation:
            print('  report_index: {}'.format(operation['report_index']))
        print('  success: {}'.format(operation['success']))
    for type_param in type_params:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] is not None:
        print('agg_param: {}'.format(test_vec['agg_param']))

    for (n, report_test_vec) in enumerate(test_vec['reports']):
        print('upload_{}:'.format(n))
        print('  measurement: {}'.format(report_test_vec['measurement']))
        print('  nonce: "{}"'.format(report_test_vec['nonce']))
        print('  public_share: >-')
        print_wrapped_line(report_test_vec['public_share'], tab=4)

        # Shard
        for (i, input_share) in enumerate(report_test_vec['input_shares']):
            print('  input_share_{}: >-'.format(i))
            print_wrapped_line(input_share, tab=4)

        # Verify
        for (i, (verifier_shares, verifier_message)) in enumerate(
                zip_longest(report_test_vec['verifier_shares'],
                            report_test_vec['verifier_messages'])):
            print('  round_{}:'.format(i))
            for (j, verifier_share) in enumerate(verifier_shares):
                print('    verifier_share_{}: >-'.format(j))
                print_wrapped_line(verifier_share, tab=6)
            if verifier_message is not None:
                print('    verifier_message: >-')
                print_wrapped_line(verifier_message, tab=6)

        for (j, out_share) in enumerate(report_test_vec['out_shares']):
            print('  out_share_{}: {}'.format(j, out_share))

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
        nodes = field.nth_root_powers(test_length)
        lag = Lagrange(field)
        for _ in range(g.ARITY):
            meas_poly.append(field.rand_vec(test_length))
            meas.append(lag.poly_eval(nodes, meas_poly[-1], eval_at))
        out_poly = g.eval_poly(field, meas_poly)

        want = g.eval(field, meas)
        nodes = field.nth_root_powers(len(out_poly))
        got = lag.poly_eval(nodes, out_poly, eval_at)
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
