# Definition of VDAFs.

from __future__ import annotations
from functools import reduce
from sagelib.common import ERR_VERIFY, Bytes, Error, Unsigned, Vec, gen_rand
from typing import Optional, Tuple, Union
import sagelib.field as field


# A VDAF.
class Vdaf:

    # The number of Aggregators.
    SHARES: Unsigned = None

    # The number of rounds of communication during the Prepare phase.
    ROUNDS: Unsigned = None

    # The meeasurement type.
    Measurement = None

    # Type of the public parameter used by a Client to produce its input
    # shares.
    PublicParam = None

    # The type of the verification parameter used by an Aggregator during the
    # Prepare computation.
    VerifyParam = None

    # The aggregation parameter type.
    AggParam = None

    # The state of an aggregator during the Prepare computation.
    Prep = None

    # The output share type.
    OutShare = None

    # The aggregate share type.
    AggShare = None

    # The aggregate result type.
    AggResult = None

    # Generate and return the public parameter used by the clients and the
    # verification parameter used by each aggregator.
    @classmethod
    def setup(cls) -> Tuple[PublicParam, Vec[VerifyParam]]:
        raise Error("not implemented")

    # Shard a measurement into a sequence of input shares. This method is run
    # by the client.
    @classmethod
    def measurement_to_input_shares(cls,
                                    public_param: PublicParam,
                                    measurement: Measurement) -> Vec[Bytes]:
        raise Error("not implemented")

    # Initialize the Prpare state for the given input share. This method is
    # run by an aggregator. Along with the input share, the inputs include the
    # aggregator's verificaiton parameter and the aggregation parameter and
    # nonce agreed upon by all of the aggregators.
    @classmethod
    def prep_init(cls,
                  verify_param: VerifyParam,
                  agg_param: AggParam,
                  nonce: Bytes,
                  input_share: Bytes) -> Prep:
        raise Error("not implemented")

    # Consume the inbound message from the previous round (or `None` if this is
    # the first round) and return the aggregator's share of the next round (or
    # the aggregator's output share if this is the last round).
    @classmethod
    def prep_next(cls,
                  prep: Prep,
                  inbound: Optional[Bytes],
                  ) -> Union[Tuple[Prep, Bytes], Vdaf.OutShare]:
        raise Error("not implemented")

    # Unshard the Prepare message shares from the previous round of the Prapare
    # computation. This is called by an aggregator after receiving all of the
    # message shares from the previous round. The output is passed to
    # Prep.next().
    @classmethod
    def prep_shares_to_prep(cls,
                            agg_param: AggParam,
                            prep_shares: Vec[Bytes]) -> Bytes:
        raise Error("not implemented")

    # Merge a list of output shares into an aggregate share. This is called by
    # an aggregator after recovering a batch of output shares.
    @classmethod
    def out_shares_to_agg_share(cls,
                                agg_param: AggParam,
                                out_shares: Vec[Prep.OutShare]) -> AggShare:
        raise Error("not implemented")

    # Unshard the aggregate shares and compute the aggregate result. This is
    # called by the ccollector.
    @classmethod
    def agg_shares_to_result(cls,
                             agg_param: AggParam,
                             agg_shares: Vec[AggShare]) -> AggResult:
        raise Error("not implemented")


# Run the VDAF on a list of measurements.
#
# NOTE This is used to generate {{run-vdaf}}.
def run_vdaf(Vdaf,
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes],
             measurements: Vec[Vdaf.Measurement]):
    # Distribute long-lived parameters.
    (public_param, verify_params) = Vdaf.setup()

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # Each Client shards its input into shares.
        input_shares = Vdaf.measurement_to_input_shares(public_param,
                                                        measurement)

        # Each Aggregator initializes its preparation state.
        prep_states = []
        for j in range(Vdaf.SHARES):
            state = Vdaf.prep_init(verify_params[j],
                                   agg_param,
                                   nonce,
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
            # This is where we would send messages over the network in a
            # distributed VDAF computation.
            if i < Vdaf.ROUNDS:
                inbound = Vdaf.prep_shares_to_prep(agg_param, outbound)

        # The final outputs of prepare phasre are the output shares.
        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an aggregate share.
    agg_shares = []
    for j in range(Vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = Vdaf.out_shares_to_agg_share(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate.
    return Vdaf.agg_shares_to_result(agg_param, agg_shares)


##
# TESTS
#

# An insecure VDAF used only for testing purposes.
class VdafTest(Vdaf):
    # Generic parameters
    Field = field.Field

    # Associated parameters
    SHARES = 2
    ROUNDS = 1

    # Associated types
    AggShare = Vec[Field]
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
    def measurement_to_input_shares(cls, _public_param, measurement):
        helper_shares = cls.Field.rand_vec(cls.SHARES-1)
        leader_share = cls.Field(measurement)
        for helper_share in helper_shares:
            leader_share -= helper_share
        input_shares = [cls.Field.encode_vec([leader_share])]
        for helper_share in helper_shares:
            input_shares.append(cls.Field.encode_vec([helper_share]))
        return input_shares

    @classmethod
    def prep_init(cls, _verify_param, _agg_param, _nonce, input_share):
        return VdafTest.Prep(cls.input_range, input_share)

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
        return reduce(lambda x, y: [x[0] + y[0]], out_shares)

    @classmethod
    def agg_shares_to_result(cls, _agg_param, agg_shares):
        return reduce(lambda x, y: [x[0] + y[0]], agg_shares)[0].as_unsigned()


class VdafTestField128(VdafTest):
    Field = field.Field128


def test_vdaf(Vdaf, agg_param, measurements, expected_agg_result):
    # The nonces need not be random, but merely non-repeating.
    nonces = [gen_rand(16) for _ in range(len(measurements))]
    agg_result = run_vdaf(Vdaf, agg_param, nonces, measurements)
    if agg_result != expected_agg_result:
        print("vdaf test failed ({}): unexpected result: got {}; want {}".format(
            measurements, agg_result, expected_agg_result))


if __name__ == "__main__":
    test_vdaf(VdafTestField128, None, [1, 2, 3, 4], 10)
