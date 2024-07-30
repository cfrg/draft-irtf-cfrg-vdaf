import unittest
from functools import reduce
from typing import TypeVar

from vdaf_poc.common import gen_rand
from vdaf_poc.daf import Daf, run_daf
from vdaf_poc.field import Field128
from vdaf_poc.xof import XofTurboShake128


class TestDaf(
        Daf[
            int,  # Measurement
            None,  # AggParam
            None,  # PublicShare
            Field128,  # InputShare
            Field128,  # OutShare
            Field128,  # AggShare
            int,  # AggResult
        ]):
    """A simple DAF used for testing."""

    ID = 0xFFFFFFFF
    SHARES = 2
    NONCE_SIZE = 0
    RAND_SIZE = 16

    def shard(
            self,
            measurement: int,
            nonce: bytes,
            rand: bytes) -> tuple[None, list[Field128]]:
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("incorrect size of random bytes argument")

        helper_shares = XofTurboShake128.expand_into_vec(
            Field128,
            rand,
            b'',
            b'',
            self.SHARES - 1,
        )
        leader_share = Field128(measurement)
        for helper_share in helper_shares:
            leader_share -= helper_share
        input_shares = [leader_share] + helper_shares
        return (None, input_shares)

    def is_valid(
            self,
            _agg_param: None,
            _previous_agg_params: list[None]) -> bool:
        return True

    def prep(
            self,
            _agg_id: int,
            _agg_param: None,
            nonce: bytes,
            _public_share: None,
            input_share: Field128) -> Field128:
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")

        # For this simple test DAF, the output share is the same as the input
        # share.
        return input_share

    def aggregate(
            self,
            _agg_param: None,
            out_shares: list[Field128]) -> Field128:
        return reduce(lambda x, y: x + y, out_shares)

    def unshard(
            self,
            _agg_param: None,
            agg_shares: list[Field128],
            _num_measurements: int) -> int:
        return reduce(lambda x, y: x + y, agg_shares).as_unsigned()


Measurement = TypeVar("Measurement")
AggParam = TypeVar("AggParam")
PublicShare = TypeVar("PublicShare")
InputShare = TypeVar("InputShare")
OutShare = TypeVar("OutShare")
AggShare = TypeVar("AggShare")
AggResult = TypeVar("AggResult")


def test_daf(
        daf: Daf[
            Measurement,
            AggParam,
            PublicShare,
            InputShare,
            OutShare,
            AggShare,
            AggResult
        ],
        agg_param: AggParam,
        measurements: list[Measurement],
        expected_agg_result: AggResult) -> None:
    # Test that the algorithm identifier is in the correct range.
    assert 0 <= daf.ID and daf.ID < 2 ** 32

    # Run the DAF on the set of measurements.
    nonces = [gen_rand(daf.NONCE_SIZE) for _ in range(len(measurements))]
    agg_result = run_daf(daf,
                         agg_param,
                         measurements,
                         nonces)
    if agg_result != expected_agg_result:
        print('daf test failed ({} on {}): unexpected result: got {}; want {}'
              .format(daf.__class__, measurements, agg_result,
                      expected_agg_result))


class TestDafCase(unittest.TestCase):
    def test_test_daf(self) -> None:
        test_daf(TestDaf(), None, [1, 2, 3, 4], 10)
