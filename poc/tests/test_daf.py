import unittest
from functools import reduce

from common import gen_rand
from daf import Daf, run_daf
from field import Field128
from xof import XofTurboShake128


class TestDaf(Daf):
    """A simple DAF used for testing."""

    # Operational parameters
    Field = Field128

    # Associated parameters
    ID = 0xFFFFFFFF
    SHARES = 2
    NONCE_SIZE = 0
    RAND_SIZE = 16

    # Associated types
    Measurement = int
    PublicShare = None
    InputShare = Field
    OutShare = Field
    AggShare = Field
    AggResult = int

    @classmethod
    def shard(cls, measurement, _nonce, rand):
        helper_shares = XofTurboShake128.expand_into_vec(cls.Field,
                                                         rand,
                                                         b'',
                                                         b'',
                                                         cls.SHARES-1)
        leader_share = cls.Field(measurement)
        for helper_share in helper_shares:
            leader_share -= helper_share
        input_shares = [leader_share] + helper_shares
        return (None, input_shares)

    @classmethod
    def prep(cls, _agg_id, _agg_param, _nonce, _public_share, input_share):
        # For this simple test DAF, the output share is the same as the input
        # share.
        return input_share

    @classmethod
    def aggregate(cls, _agg_param, out_shares):
        return reduce(lambda x, y: x + y, out_shares)

    @classmethod
    def unshard(cls, _agg_param, agg_shares, _num_measurements):
        return reduce(lambda x, y: x + y, agg_shares).as_unsigned()


def test_daf(Daf,
             agg_param,
             measurements,
             expected_agg_result):
    # Test that the algorithm identifier is in the correct range.
    assert 0 <= Daf.ID and Daf.ID < 2 ** 32

    # Run the DAF on the set of measurements.
    nonces = [gen_rand(Daf.NONCE_SIZE) for _ in range(len(measurements))]
    agg_result = run_daf(Daf,
                         agg_param,
                         measurements,
                         nonces)
    if agg_result != expected_agg_result:
        print('daf test failed ({} on {}): unexpected result: got {}; want {}'
              .format(Daf.__class__, measurements, agg_result,
                      expected_agg_result))


class TestDafCase(unittest.TestCase):
    def test_test_daf(self):
        test_daf(TestDaf, None, [1, 2, 3, 4], 10)
