# Definition of DAFs.

from __future__ import annotations
from sagelib.common import Unsigned, Vec
import sagelib.field as field
import json


# A DAF
class Daf:

    # The number of Aggregators.
    SHARES: Unsigned = None

    # The measurement type.
    Measurement = None

    # The aggregation parameter type.
    AggParam = None

    # The output share type.
    OutShare = None

    # The aggregate share type.
    AggShare = None

    # The aggregate result type.
    AggResult = None

    # Shard a measurement into a sequence of input shares. This method is run
    # by the client.
    @classmethod
    def measurement_to_input_shares(Daf,
                                    measurement: Measurement) -> Vec[Bytes]:
        raise Error('not implemented')

    # Prepare an input share for aggregation. This algorithm takes as input an
    # Aggregator's input share and an aggreation parameter and returns the
    # corresponding output share.
    @classmethod
    def prep(Daf,
             agg_param: AggParam,
             input_share: Bytes) -> OutShare:
        raise Error('not implemented')

    # Merge a list of output shares into an aggregate share. This is called by
    # an Aggregator after recovering a batch of output shares.
    @classmethod
    def out_shares_to_agg_share(Daf,
                                agg_param: AggParam,
                                out_shares: Vec[OutShare]) -> AggShare:
        raise Error('not implemented')

    # Unshard the aggregate shares and compute the aggregate result. This is
    # called by the Collector.
    @classmethod
    def agg_shares_to_result(Daf,
                             agg_param: AggParam,
                             agg_shares: Vec[AggShare]) -> AggResult:
        raise Error('not implemented')

    # Returns a printable version of the verification parameters. This is used
    # for test vector generation.
    @classmethod
    def test_vector_verify_params(Daf, verify_params: Vec[VerifyParam]):
        raise Error('not implemented')


# Run a DAF on a list of measurements.
def run_daf(Daf,
            agg_param: Daf.AggParam,
            measurements: Vec[Daf.Measurement]):
    out_shares = [ [] for j in range(Daf.SHARES) ]
    for measurement in measurements:
        # Each Client shards its measurement into input shares and
        # distributes them among the Aggregators.
        input_shares = Daf.measurement_to_input_shares(measurement)

        # Each Aggregator prepares its input share for aggregation.
        for j in range(Daf.SHARES):
            out_shares[j].append(Daf.prep(agg_param, input_shares[j]))

    # Each Aggregator aggregates its output shares into an aggregate
    # share and it to the Collector.
    agg_shares = []
    for j in range(Daf.SHARES):
        agg_share_j = Daf.out_shares_to_agg_share(agg_param,
                                                  out_shares[j])
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate result.
    agg_result = Daf.agg_shares_to_result(agg_param, agg_shares)
    return agg_result


##
# TESTS
#

# A simpmle DAF used for testing.
class DafTest(Daf):
    # Operational parameters
    Field = field.Field128

    # Associated parameters
    SHARES = 2

    # Associated types
    AggShare = Vec[Field]
    OutShare = Vec[Field]
    Measurement = Unsigned
    AggResult = Unsigned

    @classmethod
    def measurement_to_input_shares(cls, measurement):
        helper_shares = cls.Field.rand_vec(cls.SHARES-1)
        leader_share = cls.Field(measurement)
        for helper_share in helper_shares:
            leader_share -= helper_share
        input_shares = [cls.Field.encode_vec([leader_share])]
        for helper_share in helper_shares:
            input_shares.append(cls.Field.encode_vec([helper_share]))
        return input_shares

    @classmethod
    def prep(cls, _agg_param, input_share):
        # For this simple test DAF, the output share is the same as the input
        # share.
        return cls.Field.decode_vec(input_share)

    @classmethod
    def out_shares_to_agg_share(cls, _agg_param, out_shares):
        return reduce(lambda x, y: [x[0] + y[0]], out_shares)

    @classmethod
    def agg_shares_to_result(cls, _agg_param, agg_shares):
        return [reduce(lambda x, y: [x[0] + y[0]], agg_shares)[0].as_unsigned()]

    @classmethod
    def test_vector_verify_params(cls, verify_params: Vec[VerifyParam]):
        pass


def test_daf(cls,
             agg_param,
             measurements,
             expected_agg_result):
    agg_result = run_daf(cls,
                         agg_param,
                         measurements)
    if agg_result != expected_agg_result:
        print('vdaf test failed ({} on {}): unexpected result: got {}; want {}'.format(
            cls, measurements, agg_result, expected_agg_result))


if __name__ == '__main__':
    test_daf(DafTest, None, [1, 2, 3, 4], [10])
