# Definition of VDAFs.

from __future__ import annotations
from functools import reduce
from sagelib.common import DRAFT, ERR_VERIFY, Bytes, Error, Unsigned, Vec, \
                           gen_rand, print_wrapped_line
from typing import Optional, Tuple, Union
import sagelib.field as field
import json
import os


# A VDAF.
class Vdaf:

    # Length of the verification key shared by the Aggregators.
    VERIFY_KEY_SIZE = None

    # The number of Aggregators.
    SHARES: Unsigned = None

    # The number of rounds of communication during the Prepare phase.
    ROUNDS: Unsigned = None

    # The meeasurement type.
    Measurement = None

    # The aggregation parameter type.
    AggParam = None

    # The state of an aggregator during the Prepare computation.
    Prep = None

    # The output share type.
    OutShare = None

    # The aggregate result type.
    AggResult = None

    # Shard a measurement into a "public share" and a sequence of input shares,
    # one for each Aggregator. This method is run by the Client.
    @classmethod
    def measurement_to_input_shares(Vdaf,
                                    measurement: Measurement) -> (Bytes,
                                                                  Vec[Bytes]):
        raise Error('not implemented')

    # Initialize the Prepare state for the given input share. This method is run
    # by an Aggregator. Along with the the public share and its input share, the
    # inputs include the verification key shared by all of the Aggregators, the
    # Aggregator's ID (a unique integer in range `[0, SHARES)`, and the
    # aggregation parameter and nonce agreed upon by all of the Aggregators.
    @classmethod
    def prep_init(Vdaf,
                  verify_key: Bytes,
                  agg_id: Unsigned,
                  agg_param: AggParam,
                  nonce: Bytes,
                  public_share: Byhtes,
                  input_share: Bytes) -> Prep:
        raise Error('not implemented')

    # Consume the inbound message from the previous round (or `None` if this is
    # the first round) and return the aggregator's share of the next round (or
    # the aggregator's output share if this is the last round).
    @classmethod
    def prep_next(Vdaf,
                  prep: Prep,
                  inbound: Optional[Bytes],
                  ) -> Union[Tuple[Prep, Bytes], Vdaf.OutShare]:
        raise Error('not implemented')

    # Unshard the Prepare message shares from the previous round of the Prapare
    # computation. This is called by an aggregator after receiving all of the
    # message shares from the previous round. The output is passed to
    # Prep.next().
    @classmethod
    def prep_shares_to_prep(Vdaf,
                            agg_param: AggParam,
                            prep_shares: Vec[Bytes]) -> Bytes:
        raise Error('not implemented')

    # Merge a list of output shares into an aggregate share, encoded as a byte
    # string. This is called by an aggregator after recovering a batch of
    # output shares.
    @classmethod
    def out_shares_to_agg_share(Vdaf,
                                agg_param: AggParam,
                                out_shares: Vec[OutShare]) -> Bytes:
        raise Error('not implemented')

    # Unshard the aggregate shares (encoded as byte strings) and compute the
    # aggregate result. This is called by the Collector.
    @classmethod
    def agg_shares_to_result(Vdaf,
                             agg_param: AggParam,
                             agg_shares: Vec[Bytes]) -> AggResult:
        raise Error('not implemented')

    # Add any parameters to `test_vec` that are required to construct this
    # class. Return the key that was set or `None` if `test_vec` was not
    # modified.
    @classmethod
    def test_vec_set_type_param(Vdaf, test_vec):
        return None


# Run the VDAF on a list of measurements.
#
# NOTE This is used to generate {{run-vdaf}}.
def run_vdaf(Vdaf,
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes],
             measurements: Vec[Vdaf.Measurement],
             print_test_vec=False):
    # Generate the long-lived verification key.
    verify_key = gen_rand(Vdaf.VERIFY_KEY_SIZE)
    # REMOVE ME
    test_vec = {
        'verify_key': verify_key.hex(),
        'agg_param': agg_param,
        'prep': [],
        'agg_shares': [],
        'agg_result': None, # set below
    }
    type_param = Vdaf.test_vec_set_type_param(test_vec)

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # REMOVE ME
        prep_test_vec = {
            'measurement': int(measurement),
            'nonce': nonce.hex(),
            'input_shares': [],
            'prep_shares': [[] for _ in range(Vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
        }

        # Each Client shards its measurement into input shares.
        (public_share, input_shares) = \
            Vdaf.measurement_to_input_shares(measurement)

        # REMOVE ME
        for input_share in input_shares:
            prep_test_vec['input_shares'].append(input_share.hex())

        # Each Aggregator initializes its preparation state.
        prep_states = []
        for j in range(Vdaf.SHARES):
            state = Vdaf.prep_init(verify_key, j,
                                   agg_param,
                                   nonce,
                                   public_share,
                                   input_shares[j])
            prep_states.append(state)

        # Aggregators recover their output shares.
        inbound = None
        for i in range(Vdaf.ROUNDS+1):
            outbound = []
            for j in range(Vdaf.SHARES):
                out = Vdaf.prep_next(prep_states[j], inbound)
                if i < Vdaf.ROUNDS:
                    (prep_states[j], out) = out
                outbound.append(out)
            # This is where we would send messages over the
            # network in a distributed VDAF computation.
            if i < Vdaf.ROUNDS:
                # REMOVE ME
                for prep_share in outbound:
                    prep_test_vec['prep_shares'][i].append(prep_share.hex())

                inbound = Vdaf.prep_shares_to_prep(agg_param,
                                                   outbound)
                # REMOVE ME
                prep_test_vec['prep_messages'].append(inbound.hex())

        # REMOVE ME
        for out_share in outbound:
            prep_test_vec['out_shares'].append(
                list(map(lambda x: x.as_unsigned(), out_share)))
        test_vec['prep'].append(prep_test_vec)

        # The final outputs of prepare phase are the output shares.
        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(Vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = Vdaf.out_shares_to_agg_share(agg_param,
                                                   out_shares_j)
        agg_shares.append(agg_share_j)
        # REMOVE ME
        test_vec['agg_shares'].append(agg_share_j.hex())

    # Collector unshards the aggregate.
    agg_result = Vdaf.agg_shares_to_result(agg_param, agg_shares)
    # REMOVE ME
    test_vec['agg_result'] = list(map(lambda x: int(x), agg_result))
    if print_test_vec:
        pretty_print_vdaf_test_vec(Vdaf, test_vec, type_param)

        os.system('mkdir -p test_vec/{}'.format(DRAFT))
        with open('test_vec/{}/{}.json'.format(DRAFT, Vdaf.__name__), 'w') as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def pretty_print_vdaf_test_vec(Vdaf, test_vec, type_param):
    print('---------- {} ---------------'.format(Vdaf.__name__))
    if type_param != None:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] != None:
        print('agg_param: {}'.format(test_vec['agg_param']))

    for (n, prep_test_vec) in enumerate(test_vec['prep']):
        print('upload_{}:'.format(n))
        print('  measurement: {}'.format(prep_test_vec['measurement']))
        print('  nonce: "{}"'.format(prep_test_vec['nonce']))

        # Shard
        for (i, input_share) in enumerate(prep_test_vec['input_shares']):
            print('  input_share_{}: >-'.format(i))
            print_wrapped_line(input_share, tab=4)

        # Prepare
        for (i, (prep_shares, prep_msg)) in enumerate(zip(prep_test_vec['prep_shares'], prep_test_vec['prep_messages'])):
            print('  round_{}:'.format(i))
            for (j, prep_share) in enumerate(prep_shares):
                print('    prep_share_{}: >-'.format(j))
                print_wrapped_line(prep_share, tab=6)
            print('    prep_message: >-')
            print_wrapped_line(prep_msg, tab=6)

        for (j, out_share) in enumerate(prep_test_vec['out_shares']):
            print('  out_share_{}:'.format(j))
            for n in out_share:
                print('    - {}'.format(n))

    # Aggregate
    for (j, agg_share) in enumerate(test_vec['agg_shares']):
        print('agg_share_{}: >-'.format(j))
        print_wrapped_line(agg_share, tab=2)

    # Unshard
    print('agg_result: {}'.format(list(
        map(lambda x: int(x), test_vec['agg_result']))))
    print()


##
# TESTS
#

# An insecure VDAF used only for testing purposes.
class TestVdaf(Vdaf):
    # Operational parameters
    Field = field.Field128

    # Associated parameters
    VERIFY_KEY_SIZE = 0
    SHARES = 2
    ROUNDS = 1

    # Associated types
    OutShare = Vec[Field]
    Measurement = Unsigned
    AggResult = Unsigned

    # Operational parameters
    input_range = range(5)

    class Prep:
        def __init__(self, input_range, encoded_input_share):
            self.input_range = input_range
            self.encoded_input_share = encoded_input_share

    @classmethod
    def setup(cls):
        return (None, [None for _ in range(cls.SHARES)])

    @classmethod
    def measurement_to_input_shares(cls, measurement):
        helper_shares = cls.Field.rand_vec(cls.SHARES-1)
        leader_share = cls.Field(measurement)
        for helper_share in helper_shares:
            leader_share -= helper_share
        input_shares = [cls.Field.encode_vec([leader_share])]
        for helper_share in helper_shares:
            input_shares.append(cls.Field.encode_vec([helper_share]))
        public_share = b'dummy public share'
        return (public_share, input_shares)

    @classmethod
    def prep_init(cls,
                  _verify_key,
                  _agg_id,
                  _agg_param,
                  _nonce,
                  _public_share,
                  input_share):
        return TestVdaf.Prep(cls.input_range, input_share)

    @classmethod
    def prep_next(cls, prep, inbound):
        if inbound is None:
            # Our prepare-message share is just our input share. This is
            # trivially insecure since the recipient can now reconstruct
            # the input.
            return (prep, prep.encoded_input_share)

        # The unsharded prepare message is the plaintext measurement.
        # Check that it is in the specified range.
        measurement = cls.Field.decode_vec(inbound)[0].as_unsigned()
        if measurement not in prep.input_range:
            raise ERR_VERIFY

        return cls.Field.decode_vec(prep.encoded_input_share)

    @classmethod
    def prep_shares_to_prep(cls, _agg_param, prep_shares):
        prep_msg = reduce(lambda x, y: [x[0] + y[0]],
                          map(lambda encoded: cls.Field.decode_vec(encoded),
                              prep_shares))
        return cls.Field.encode_vec(prep_msg)

    @classmethod
    def out_shares_to_agg_share(cls, _agg_param, out_shares):
        return cls.Field.encode_vec(
            reduce(lambda x, y: [x[0] + y[0]], out_shares))

    @classmethod
    def agg_shares_to_result(cls, _agg_param, agg_shares):
        return [reduce(lambda x, y: [x[0] + y[0]],
            map(lambda encoded: cls.Field.decode_vec(encoded),
                agg_shares))[0].as_unsigned()]


def test_vdaf(cls,
              agg_param,
              measurements,
              expected_agg_result,
              print_test_vec=False):
    # The nonces need not be random, but merely non-repeating.
    nonces = [gen_rand(16) for _ in range(len(measurements))]
    agg_result = run_vdaf(cls,
                          agg_param,
                          nonces,
                          measurements,
                          print_test_vec)
    if agg_result != expected_agg_result:
        print('vdaf test failed ({} on {}): unexpected result: got {}; want {}'.format(
            cls.__name__, measurements, agg_result, expected_agg_result))


if __name__ == '__main__':
    test_vdaf(TestVdaf, None, [1, 2, 3, 4], [10])
