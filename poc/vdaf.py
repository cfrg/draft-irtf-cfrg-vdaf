"""Definition of VDAFs."""

import json
import os
from typing import Any, Union

from common import (TEST_VECTOR_PATH, format_dst, gen_rand, print_wrapped_line,
                    to_le_bytes)


class Vdaf:
    """A VDAF."""

    # Algorithm identifier for this VDAF, a 32-bit integer.
    ID: int  # `range(2**32)`

    # Length of the verification key shared by the Aggregators.
    VERIFY_KEY_SIZE: int

    # Length of the nonce.
    NONCE_SIZE: int

    # Number of random bytes consumed by `shard()`.
    RAND_SIZE: int

    # The number of Aggregators.
    SHARES: int

    # The number of rounds of communication during the Prepare phase.
    ROUNDS: int

    # The measurement type.
    Measurement: Any = None

    # The aggregation parameter type.
    AggParam: Any = None

    # The public share type.
    PublicShare: Any = None

    # The input share type.
    InputShare: Any = None

    # The output share type.
    OutShare: Any = None

    # The aggregate share type.
    AggShare: Any = None

    # The aggregate result type.
    AggResult: Any = None

    # The state of an Aggregator during preparation.
    PrepState: Any = None

    # The preparation share type.
    PrepShare: Any = None

    # The preparation message type.
    PrepMessage: Any = None

    @classmethod
    def shard(Vdaf,
              measurement: Measurement,
              nonce: bytes,
              rand: bytes,
              ) -> tuple[PublicShare, list[InputShare]]:
        """
        Shard a measurement into a "public share" and a sequence of input
        shares, one for each Aggregator. This method is run by the Client.

        Pre-conditions:

            - `len(nonce) == Vdaf.NONCE_SIZE`
            - `len(rand) == Vdaf.RAND_SIZE`
        """
        raise NotImplementedError()

    @classmethod
    def is_valid(Vdaf, agg_param: AggParam,
                 previous_agg_params: set[AggParam]) -> bool:
        """
        Check if `agg_param` is valid for use with an input share that has
        previously been used with all `previous_agg_params`.
        """
        raise NotImplementedError()

    @classmethod
    def prep_init(Vdaf,
                  verify_key: bytes,
                  agg_id: int,
                  agg_param: AggParam,
                  nonce: bytes,
                  public_share: PublicShare,
                  input_share: InputShare) -> tuple[PrepState, PrepShare]:
        """
        Initialize the prep state for the given input share and return the
        initial prep share. This method is run by an Aggregator. Along with the
        public share and its input share, the inputs include the verification
        key shared by all of the Aggregators, the Aggregator's ID, and the
        aggregation parameter and nonce agreed upon by all of the Aggregators.

        Pre-conditions:

            - `len(verify_key) == Vdaf.VERIFY_KEY_SIZE`
            - `agg_id` in `range(0, Vdaf.SHARES)`
            - `len(nonce) == Vdaf.NONCE_SIZE`
        """
        raise NotImplementedError()

    @classmethod
    def prep_next(Vdaf,
                  prep_state: PrepState,
                  prep_msg: PrepMessage,
                  ) -> Union[tuple[PrepState, PrepShare], OutShare]:
        """
        Consume the inbound message from the previous round and return the
        Aggregator's share of the next round (or the aggregator's output share
        if this is the last round).
        """
        raise NotImplementedError()

    @classmethod
    def prep_shares_to_prep(Vdaf,
                            agg_param: AggParam,
                            prep_shares: list[PrepShare]) -> PrepMessage:
        """
        Unshard the prep shares from the previous round of preparation. This is
        called by an Aggregator after receiving all of the message shares from
        the previous round.
        """
        raise NotImplementedError()

    @classmethod
    def aggregate(Vdaf,
                  agg_param: AggParam,
                  out_shares: list[OutShare]) -> AggShare:
        """
        Merge a list of output shares into an aggregate share, encoded as a byte
        string. This is called by an aggregator after recovering a batch of
        output shares.
        """
        raise NotImplementedError()

    @classmethod
    def unshard(Vdaf,
                agg_param: AggParam,
                agg_shares: list[AggShare],
                num_measurements: int) -> AggResult:
        """
        Unshard the aggregate shares (encoded as byte strings) and compute the
        aggregate result. This is called by the Collector.

        Pre-condition:

            - `num_measurements >= 1`
        """
        raise NotImplementedError()

    @classmethod
    def domain_separation_tag(Vdaf, usage: int) -> bytes:
        """
        Format domain separation tag for this VDAF with the given usage.

        Pre-conditions:

            - `usage` in `range(2**16)`
        """
        return format_dst(0, Vdaf.ID, usage)

    # Methods for generating test vectors

    @classmethod
    def test_vec_set_type_param(Vdaf, test_vec) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []

    @classmethod
    def test_vec_encode_input_share(Vdaf, input_share):
        raise NotImplementedError()

    @classmethod
    def test_vec_encode_public_share(Vdaf, public_share):
        raise NotImplementedError()

    @classmethod
    def test_vec_encode_agg_share(Vdaf, agg_share):
        raise NotImplementedError()

    @classmethod
    def test_vec_encode_prep_share(Vdaf, prep_share):
        raise NotImplementedError()

    @classmethod
    def test_vec_encode_prep_msg(Vdaf, prep_message):
        raise NotImplementedError()


# NOTE This is used to generate {{run-vdaf}}.
def run_vdaf(vdaf,
             verify_key,
             agg_param,
             nonces,
             measurements,
             print_test_vec=False,
             test_vec_instance=0):
    """Run the VDAF on a list of measurements.

    Pre-conditions:

        - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
        - `len(nonces) == len(measurements)`
        - `len(nonce) == vdaf.NONCE_SIZE` for each `nonce` in `nonces`
    """

    # REMOVE ME
    test_vec = {
        'shares': vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': agg_param,
        'prep': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_params = vdaf.test_vec_set_type_param(test_vec)

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == vdaf.NONCE_SIZE

        # REMOVE ME
        prep_test_vec = {
            'measurement': measurement,
            'nonce': nonce.hex(),
            'public_share': None,  # set below
            'input_shares': [],
            'prep_shares': [[] for _ in range(vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
        }

        # Each Client shards its measurement into input shares.
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(measurement, nonce, rand)

        # REMOVE ME
        prep_test_vec['rand'] = rand.hex()
        prep_test_vec['public_share'] = \
            vdaf.test_vec_encode_public_share(public_share).hex()
        for input_share in input_shares:
            prep_test_vec['input_shares'].append(
                vdaf.test_vec_encode_input_share(input_share).hex())

        # Each Aggregator initializes its preparation state.
        prep_states = []
        outbound = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.prep_init(verify_key, j,
                                            agg_param,
                                            nonce,
                                            public_share,
                                            input_shares[j])
            prep_states.append(state)
            outbound.append(share)
        # REMOVE ME
        for prep_share in outbound:
            prep_test_vec['prep_shares'][0].append(
                vdaf.test_vec_encode_prep_share(prep_share).hex())

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS-1):
            prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                                outbound)
            # REMOVE ME
            prep_test_vec['prep_messages'].append(
                vdaf.test_vec_encode_prep_msg(prep_msg).hex())

            outbound = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(prep_states[j], prep_msg)
                (prep_states[j], out) = out
                outbound.append(out)
            # REMOVE ME
            for prep_share in outbound:
                prep_test_vec['prep_shares'][i+1].append(
                    vdaf.test_vec_encode_prep_share(prep_share).hex())

        # The final outputs of the prepare phase are the output shares.
        prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                            outbound)
        # REMOVE ME
        prep_test_vec['prep_messages'].append(
            vdaf.test_vec_encode_prep_msg(prep_msg).hex())
        outbound = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(prep_states[j], prep_msg)
            outbound.append(out_share)

        # REMOVE ME
        for out_share in outbound:
            prep_test_vec['out_shares'].append([
                to_le_bytes(x.as_unsigned(), x.ENCODED_SIZE).hex()
                for x in out_share
            ])
        test_vec['prep'].append(prep_test_vec)

        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.aggregate(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)
        # REMOVE ME
        test_vec['agg_shares'].append(
            vdaf.test_vec_encode_agg_share(agg_share_j).hex())

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    # REMOVE ME
    test_vec['agg_result'] = agg_result
    if print_test_vec:
        pretty_print_vdaf_test_vec(vdaf, test_vec, type_params)

        os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
        with open(
            '{}/{}_{}.json'.format(
                TEST_VECTOR_PATH, vdaf.test_vec_name, test_vec_instance),
            'w'
        ) as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def pretty_print_vdaf_test_vec(Vdaf, test_vec, type_params):
    print('---------- {} ---------------'.format(Vdaf.test_vec_name))
    for type_param in type_params:
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
