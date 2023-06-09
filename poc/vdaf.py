"""Definition of VDAFs."""

from __future__ import annotations
from functools import reduce
import json
import os
from common import ERR_VERIFY, VERSION, Bool, Bytes, Error, \
    Unsigned, Vec, format_dst, gen_rand, \
    to_le_bytes, print_wrapped_line
import field
from prg import PrgSha3
from typing import Optional, Tuple, Union


class Vdaf:
    """A VDAF."""

    # Algorithm identifier for this VDAF, a 32-bit integer.
    ID: Unsigned = None

    # Length of the verification key shared by the Aggregators.
    VERIFY_KEY_SIZE = None

    # Length of the nonce.
    NONCE_SIZE = None

    # Number of random bytes consumed by `measurement_to_input_shares()`.
    RAND_SIZE = None

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

    @classmethod
    def measurement_to_input_shares(Vdaf,
                                    measurement: Measurement,
                                    nonce: Bytes["Vdaf.NONCE_SIZE"],
                                    rand: Bytes["Vdaf.RAND_SIZE"],
                                    ) -> tuple[Bytes, Vec[Bytes]]:
        """
        Shard a measurement into a "public share" and a sequence of input
        shares, one for each Aggregator. This method is run by the Client.
        """
        raise NotImplementedError()

    @classmethod
    def is_valid(Vdaf, agg_param: AggParam,
                 previous_agg_params: set[AggParam]) -> Bool:
        """
        Check if `agg_param` is valid for use with an input share that has
        previously been used with all `previous_agg_params`.
        """
        raise NotImplementedError()

    @classmethod
    def prep_init(Vdaf,
                  verify_key: Bytes,
                  agg_id: Unsigned,
                  agg_param: AggParam,
                  nonce: Bytes,
                  public_share: Bytes,
                  input_share: Bytes) -> Prep:
        """
        Initialize the Prepare state for the given input share. This method is
        run by an Aggregator. Along with the the public share and its input
        share, the inputs include the verification key shared by all of the
        Aggregators, the Aggregator's ID (a unique integer in range `[0,
        SHARES)`, and the aggregation parameter and nonce agreed upon by all of
        the Aggregators.
        """
        raise NotImplementedError()

    @classmethod
    def prep_next(Vdaf,
                  prep: Prep,
                  inbound: Optional[Bytes],
                  ) -> Union[Tuple[Prep, Bytes], Vdaf.OutShare]:
        """
        Consume the inbound message from the previous round (or `None` if this
        is the first round) and return the aggregator's share of the next round
        (or the aggregator's output share if this is the last round).
        """
        raise NotImplementedError()

    @classmethod
    def prep_shares_to_prep(Vdaf,
                            agg_param: AggParam,
                            prep_shares: Vec[Bytes]) -> Bytes:
        """
        Unshard the Prepare message shares from the previous round of the
        Prapare computation. This is called by an aggregator after receiving all
        of the message shares from the previous round. The output is passed to
        Prep.next().
        """
        raise NotImplementedError()

    @classmethod
    def out_shares_to_agg_share(Vdaf,
                                agg_param: AggParam,
                                out_shares: Vec[OutShare]) -> Bytes:
        """
        Merge a list of output shares into an aggregate share, encoded as a byte
        string. This is called by an aggregator after recovering a batch of
        output shares.
        """
        raise NotImplementedError()

    @classmethod
    def agg_shares_to_result(Vdaf,
                             agg_param: AggParam,
                             agg_shares: Vec[Bytes],
                             num_measurements: Unsigned) -> AggResult:
        """
        Unshard the aggregate shares (encoded as byte strings) and compute the
        aggregate result. This is called by the Collector.
        """
        raise NotImplementedError()

    @classmethod
    def domain_separation_tag(Vdaf, usage: Unsigned) -> Bytes:
        """
        Format domain separation tag for this VDAF with the given usage.
        """
        return format_dst(0, Vdaf.ID, usage)

    @classmethod
    def test_vec_set_type_param(Vdaf, test_vec):
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Return the key that was set or `None` if `test_vec` was not
        modified.
        """
        return None


# NOTE This is used to generate {{run-vdaf}}.
def run_vdaf(Vdaf,
             verify_key: Bytes[Vdaf.VERIFY_KEY_SIZE],
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes[Vdaf.NONCE_SIZE]],
             measurements: Vec[Vdaf.Measurement],
             print_test_vec=False,
             test_vec_instance=0):
    """Run the VDAF on a list of measurements."""

    # REMOVE ME
    test_vec = {
        'shares': Vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': agg_param,
        'prep': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_param = Vdaf.test_vec_set_type_param(test_vec)

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == Vdaf.NONCE_SIZE

        # REMOVE ME
        prep_test_vec = {
            'measurement': int(measurement),
            'nonce': nonce.hex(),
            'public_share': None,  # set below
            'input_shares': [],
            'prep_shares': [[] for _ in range(Vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
        }

        # Each Client shards its measurement into input shares.
        rand = gen_rand(Vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            Vdaf.measurement_to_input_shares(measurement, nonce, rand)

        # REMOVE ME
        prep_test_vec['rand'] = rand.hex()
        prep_test_vec['public_share'] = public_share.hex()
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
            prep_test_vec['out_shares'].append([
                to_le_bytes(x.as_unsigned(), x.ENCODED_SIZE).hex()
                for x in out_share
            ])
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
    num_measurements = len(measurements)
    agg_result = Vdaf.agg_shares_to_result(agg_param, agg_shares,
                                           num_measurements)
    # REMOVE ME
    test_vec['agg_result'] = agg_result
    if print_test_vec:
        pretty_print_vdaf_test_vec(Vdaf, test_vec, type_param)

        os.system('mkdir -p test_vec/{:02}'.format(VERSION))
        with open('test_vec/{:02}/{}_{}.json'.format(
                VERSION, Vdaf.test_vec_name, test_vec_instance), 'w') as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def pretty_print_vdaf_test_vec(Vdaf, test_vec, type_param):
    print('---------- {} ---------------'.format(Vdaf.test_vec_name))
    if type_param != None:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] != None:
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
    print('agg_result: {}'.format(test_vec['agg_result']))
    print()


##
# TESTS
#

class TestVdaf(Vdaf):
    """An insecure VDAF used only for testing purposes."""
    # Operational parameters
    Field = field.Field128

    # Associated parameters
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = 0
    NONCE_SIZE = 13
    RAND_SIZE = 16
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
    def measurement_to_input_shares(cls, measurement, nonce, rand):
        helper_shares = PrgSha3.expand_into_vec(cls.Field,
                                                rand,
                                                b'',
                                                b'',
                                                cls.SHARES-1)
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
    def agg_shares_to_result(cls, _agg_param, agg_shares, _num_measurements):
        return reduce(lambda x, y: [x[0] + y[0]],
                      map(lambda encoded: cls.Field.decode_vec(encoded),
                          agg_shares))[0].as_unsigned()


def test_vdaf(Vdaf,
              agg_param,
              measurements,
              expected_agg_result,
              print_test_vec=False,
              test_vec_instance=0):
    # Test that the algorithm identifier is in the correct range.
    assert 0 <= Vdaf.ID and Vdaf.ID < 2 ** 32

    # Run the VDAF on the set of measurmenets.
    nonces = [gen_rand(Vdaf.NONCE_SIZE) for _ in range(len(measurements))]
    verify_key = gen_rand(Vdaf.VERIFY_KEY_SIZE)
    agg_result = run_vdaf(Vdaf,
                          verify_key,
                          agg_param,
                          nonces,
                          measurements,
                          print_test_vec,
                          test_vec_instance)
    if agg_result != expected_agg_result:
        print('vdaf test failed ({} on {}): unexpected result: got {}; want {}'.format(
            Vdaf.test_vec_name, measurements, agg_result, expected_agg_result))


if __name__ == '__main__':
    test_vdaf(TestVdaf, None, [1, 2, 3, 4], 10)
