# API for VDAFs and commonly used primitives.

from __future__ import annotations

import os

from typing import Optional, Tuple, Union

from sagelib.field import Field64
from sagelib.common import Error, Unit, Vec


# A VDAF.
class Vdaf:

    # The number of Aggregators.
    SHARES: int

    # The number of rounds of communication during the Prepare phase.
    ROUNDS: int

    # The public parameter used by a Client to produce its input shares.
    class PublicParam:
        pass

    # The verification parameter used by an Aggregator during the Prepare
    # computation.
    class VerifyParam:
        pass

    # An aggregation parameter for this VDAF.
    class AggParam:
        pass

    # An aggregate share for this VDAF.
    class AggShare:
        pass

    # A measurement for this VDAF.
    class Measurement:
        pass

    # The aggregate result for this VDAF.
    class AggResult:
        pass

    # The state of an aggregator during the Prepare computation.
    class Prep:

        # An output share for this VDAF.
        class OutShare:
            pass

        # Consume the inbound message from the previous round (or `None` if
        # this is the first round) and return the aggregator's share of the
        # next round (or the aggregator's output share if this is the last
        # round).
        def next(self, inbound: Optional[bytes]) -> Union[bytes, OutShare]:
            raise Error("not implemented")

    # Generate and return the public parameter used by the clients and the
    # verification parameter used by each aggregator.
    def setup(self) -> Tuple[PublicParam, Vec[VerifyParam]]:
        raise Error("not implemented")

    # Shard a measurement into a sequence of input shares. This method is run
    # by the client.
    def measurement_to_input_shares(self,
                                    public_param: PublicParam,
                                    measurement: Measurement) -> Vec[bytes]:
        raise Error("not implemented")

    # Initialize the Prpare state for the given input share. This method is
    # run by an aggregator. Along with the input share, the inputs include the
    # aggregator's verificaiton parameter and the aggregation parameter and
    # nonce agreed upon by all of the aggregators.
    def prep_init(self,
                  verify_parm: VerifyParam,
                  agg_param: AggParam,
                  nonce: bytes,
                  input_share: bytes) -> Prep:
        raise Error("not implemented")

    # Unshard the Prepare message shares from the previous round of the Prapare
    # computation. This is called by an aggregator after receiving all of the
    # message shares from the previous round. The output is passed to
    # Prep.next().
    def prep_shares_to_prep(self,
                            agg_param: AggParam,
                            prep_shares: Vec[bytes]) -> bytes:
        raise Error("not implemented")

    # Merge a list of output shares into an aggregate share. This is called by
    # an aggregator after recovering a batch of output shares.
    def out_shares_to_agg_share(self,
                                agg_param: AggParam,
                                out_shares: Vec[Prep.OutShare]) -> AggShare:
        raise Error("not implemented")

    # Unshard the aggregate shares and compute the aggregate result. This is
    # called by the ccollector.
    def agg_shares_to_result(self,
                             agg_param: AggParam,
                             agg_shares: Vec[AggShare]) -> AggResult:
        raise Error("not implemented")


# Run the VDAF on a list of measurements.
#
# NOTE This is used to generate {{run-vdaf}}.
def run_vdaf(vdaf: Vdaf,
             agg_param: Vdaf.AggParam,
             nonces: Vec[bytes],
             measurements: Vec[Vdaf.Measurement]):
    # Distribute long-lived parameters.
    (public_param, verify_params) = vdaf.setup()

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # Each Client shards its input into shares.
        input_shares = vdaf.measurement_to_input_shares(public_param,
                                                        measurement)

        # Each Aggregator initializes its preparation state.
        prep_states = []
        for j in range(vdaf.SHARES):
            state = vdaf.prep_init(verify_params[j],
                                   agg_param,
                                   nonce,
                                   input_shares[j])
            prep_states.append(state)

        # Aggregators recover their output shares.
        inbound = None
        for i in range(vdaf.ROUNDS+1):
            outbound = []
            for j in range(vdaf.SHARES):
                outbound.append(prep_states[j].next(inbound))
            # This is where we would send messages over the network in a
            # distributed VDAF computation.
            inbound = vdaf.prep_shares_to_prep(agg_param, outbound)

        # The final outputs of prepare phasre are the output shares.
        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an aggregate share.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.out_to_agg_share(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate.
    return vdaf.agg_shares_to_result(agg_param, agg_shares)


# An insecure VDAF used only for testing purposes.
class TestVdaf(Vdaf):

    PublicParam = Unit
    VerifyParam = Unit
    AggParam = Unit
    AggShare = Field64
    Measurement = int
    AggResult = int

    def __init__(self, input_range: int, num_shares: int, num_rounds: int):
        self.input_range = input_range
        self.SHARES = num_shares
        self.ROUNDS = num_rounds

    def setup(self):
        return (None, [None for _ in range(self.ROUNDS)])

    def measurement_to_input_shares(self, _, measurement):
        rand = Field64.rand_vec(1)


def test_vdaf(vdaf: Vdaf,
              agg_param: Vdaf.AggParam,
              measurements: Vec[Vdaf.Measurement],
              expected_agg_result: Vdaf.AggResult):
    nonces = [os.urandom(16) for _ in range(len(measurements))]
    agg_result = run_vdaf(vdaf, agg_param, nonces, measurements)
    assert agg_result == expected_agg_result


if __name__ == "__main__":
    test_vdaf(TestVdaf(range(4), 2, 1), None, [1, 2, 3, 4], 10)
