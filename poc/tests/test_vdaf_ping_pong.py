import math
import unittest
from typing import Union, cast

from vdaf_poc.common import from_be_bytes, to_be_bytes
from vdaf_poc.test_utils import TestVdaf
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.vdaf_ping_pong import Continued, Finished, PingPong


class PingPongTester(
        PingPong[
            int,  # Measurement
            int,  # AggParam,
            str,  # PublicShare
            int,  # InputShare
            int,  # OutShare
            int,  # AggShare
            int,  # AggResult
            tuple[int, int],  # PrepState
            str,  # PrepShhare
            str,  # PrepMessage
        ]):
    """
    Computes the aggregation function f(agg_param, m[1], ..., m[N]) = agg_param
    * (m[1] + ... + m[N]). This VDAF is not secure, but is sufficient to
    exercise the code paths relevant to the ping pong topology.
    """

    ID: int = 0xFFFFFFFF
    VERIFY_KEY_SIZE: int = 0
    NONCE_SIZE: int = 0
    RAND_SIZE: int = 0
    SHARES: int = 2
    ROUNDS: int

    def __init__(self, num_rounds: int) -> None:
        self.ROUNDS = num_rounds

    # `Vdaf`

    def shard(self,
              measurement: int,
              _nonce: bytes,
              _rand: bytes) -> tuple[str, list[int]]:
        return ('public share', [measurement, measurement])

    def is_valid(self,
                 agg_param: int,
                 previous_agg_params: list[int]) -> bool:
        return len(previous_agg_params) == 0

    def prep_init(self,
                  _verify_key: bytes,
                  _agg_id: int,
                  _agg_param: int,
                  _nonce: bytes,
                  public_share: str,
                  input_share: int) -> tuple[tuple[int, int], str]:
        if public_share != 'public share':
            raise ValueError('unexpected public share')
        current_round = 0
        return (
            (current_round, input_share),
            'prep round {}'.format(current_round),
        )

    def prep_shares_to_prep(self,
                            _agg_param: int,
                            prep_shares: list[str]) -> str:
        for prep_share in prep_shares[1:]:
            if prep_share != prep_shares[0]:
                raise ValueError('unexpected prep share')
        return prep_shares[0]

    def prep_next(self,
                  prep_state: tuple[int, int],
                  prep_msg: str) -> Union[tuple[tuple[int, int], str], int]:
        (current_round, out_share) = prep_state
        if prep_msg != "prep round {}".format(current_round):
            raise ValueError("unexpted prep message")
        if current_round+1 == self.ROUNDS:
            return out_share
        return (
            (current_round+1, out_share),
            "prep round {}".format(current_round+1),
        )

    def aggregate(self, _agg_param: int, out_shares: list[int]) -> int:
        return sum(out_shares)

    def unshard(self,
                agg_param: int,
                agg_shares: list[int],
                _num_measurements: int) -> int:
        return agg_param * sum(agg_shares) // self.SHARES

    def test_vec_encode_input_share(self, input_share: int) -> bytes:
        return to_be_bytes(input_share, 8)

    def test_vec_encode_public_share(self, public_share: str) -> bytes:
        return public_share.encode('utf-8')

    def test_vec_encode_agg_share(self, agg_share: int) -> bytes:
        return to_be_bytes(agg_share, 8)

    def test_vec_encode_prep_share(self, prep_share: str) -> bytes:
        return self.encode_prep_share(prep_share)

    def test_vec_encode_prep_msg(self, prep_msg: str) -> bytes:
        return self.encode_prep_msg(prep_msg)

    # `PingPong`

    def decode_public_share(self, encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def decode_input_share(self, _agg_id: int, encoded: bytes) -> int:
        return from_be_bytes(encoded)

    def encode_prep_share(self, prep_share: str) -> bytes:
        return prep_share.encode('utf-8')

    def decode_prep_share(self,
                          _prep_state: tuple[int, int],
                          encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def encode_prep_msg(self, prep_msg: str) -> bytes:
        return prep_msg.encode('utf-8')

    def decode_prep_msg(self,
                        _prep_state: tuple[int, int],
                        encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def decode_agg_param(self, encoded: bytes) -> int:
        return from_be_bytes(encoded)

    def encode_agg_param(self, agg_param: int) -> bytes:
        return to_be_bytes(agg_param, 8)


class TestPingPongTester(TestVdaf):
    def test(self) -> None:
        """Ensure `PingPongTester` correctly implements the `Vdaf` API."""
        self.run_vdaf_test(
            cast(Vdaf, PingPongTester(10)),
            23,  # agg_param,
            [1, 2, 3, 4],  # measurements
            10 * 23,  # expected_agg_result
        )


class TestPingPong(unittest.TestCase):
    def test_one_round(self) -> None:
        """Test the ping pong flow with a 1-round VDAF."""
        vdaf = PingPongTester(1)
        verify_key = b''

        measurement = 1337
        nonce = b''
        rand = b''
        (public_share, input_shares) = vdaf.shard(
            measurement,
            nonce,
            rand,
        )

        agg_param = 23
        (leader_state, msg) = vdaf.ping_pong_leader_init(
            verify_key,
            vdaf.encode_agg_param(agg_param),
            nonce,
            vdaf.test_vec_encode_public_share(public_share),
            vdaf.test_vec_encode_input_share(input_shares[0]),
        )
        self.assertEqual(leader_state, Continued((0, measurement), 0))

        (helper_state, msg) = vdaf.ping_pong_helper_init(
            verify_key,
            vdaf.encode_agg_param(agg_param),
            nonce,
            vdaf.test_vec_encode_public_share(public_share),
            vdaf.test_vec_encode_input_share(input_shares[1]),
            cast(bytes, msg),
        )
        self.assertEqual(helper_state, Finished(measurement))

        (leader_state, msg) = vdaf.ping_pong_leader_continued(
            vdaf.encode_agg_param(agg_param),
            leader_state,
            cast(bytes, msg),
        )
        self.assertEqual(msg, None)
        self.assertEqual(leader_state, Finished(measurement))

    def test_multi_round(self) -> None:
        """Test the ping pong flow with multiple rounds."""
        verify_key = b''
        measurement = 1337
        nonce = b''
        rand = b''
        agg_param = 23

        for num_rounds in range(1, 10):
            num_steps = math.ceil((num_rounds+1) / 2)

            vdaf = PingPongTester(num_rounds)

            (public_share, input_shares) = vdaf.shard(
                measurement,
                nonce,
                rand,
            )

            (leader_state, msg) = vdaf.ping_pong_leader_init(
                verify_key,
                vdaf.encode_agg_param(agg_param),
                nonce,
                vdaf.test_vec_encode_public_share(public_share),
                vdaf.test_vec_encode_input_share(input_shares[0]),
            )
            self.assertEqual(leader_state, Continued((0, measurement), 0))

            for step in range(num_steps):
                if step == 0:
                    (helper_state, msg) = vdaf.ping_pong_helper_init(
                        verify_key,
                        vdaf.encode_agg_param(agg_param),
                        nonce,
                        vdaf.test_vec_encode_public_share(public_share),
                        vdaf.test_vec_encode_input_share(input_shares[1]),
                        cast(bytes, msg),
                    )
                else:
                    (helper_state, msg) = vdaf.ping_pong_helper_continued(
                        vdaf.encode_agg_param(agg_param),
                        helper_state,
                        cast(bytes, msg),
                    )

                if isinstance(leader_state, Continued):
                    (leader_state, msg) = vdaf.ping_pong_leader_continued(
                        vdaf.encode_agg_param(agg_param),
                        leader_state,
                        cast(bytes, msg),
                    )

            self.assertEqual(msg, None)
            self.assertEqual(leader_state, Finished(measurement))
            self.assertEqual(helper_state, Finished(measurement))
