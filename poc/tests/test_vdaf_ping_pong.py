import math
import unittest
from typing import Union, cast

from vdaf_poc.common import from_be_bytes, to_be_bytes
from vdaf_poc.test_utils import TestVdaf
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.vdaf_ping_pong import (Continued, Finished, FinishedWithOutbound,
                                     PingPong, State)


class PingPongTester(
        PingPong[
            int,  # Measurement
            int,  # AggParam,
            str,  # PublicShare
            int,  # InputShare
            int,  # OutShare
            int,  # AggShare
            int,  # AggResult
            tuple[int, int],  # VerifyState
            str,  # VerifierShare
            str,  # VerifierMessage
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
              _ctx: bytes,
              measurement: int,
              _nonce: bytes,
              _rand: bytes) -> tuple[str, list[int]]:
        return ('public share', [measurement, measurement])

    def is_valid(self,
                 agg_param: int,
                 previous_agg_params: list[int]) -> bool:
        return len(previous_agg_params) == 0

    def verify_init(self,
                    _verify_key: bytes,
                    _ctx: bytes,
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
            'verify round {}'.format(current_round),
        )

    def verifier_shares_to_message(self,
                                   _ctx: bytes,
                                   _agg_param: int,
                                   verifier_shares: list[str]) -> str:
        for verifier_share in verifier_shares[1:]:
            if verifier_share != verifier_shares[0]:
                raise ValueError('unexpected verifier share')
        return verifier_shares[0]

    def verify_next(self,
                    _ctx: bytes,
                    verify_state: tuple[int, int],
                    verifier_message: str) -> Union[tuple[tuple[int, int], str], int]:
        (current_round, out_share) = verify_state
        if verifier_message != "verify round {}".format(current_round):
            raise ValueError(f"unexpected verifier message {verifier_message}")
        if current_round+1 == self.ROUNDS:
            return out_share
        return (
            (current_round+1, out_share),
            "verify round {}".format(current_round+1),
        )

    def agg_init(self, _agg_param: int) -> int:
        return 0

    def agg_update(self,
                   _agg_param: int,
                   agg_share: int,
                   agg_delta: int) -> int:
        return agg_share + agg_delta

    def merge(self,
              _agg_param: int,
              _agg_shares: list[int]) -> int:
        raise NotImplementedError("not needed by tests")

    def unshard(self,
                agg_param: int,
                agg_shares: list[int],
                _num_measurements: int) -> int:
        return agg_param * sum(agg_shares) // self.SHARES

    def encode_input_share(self, input_share: int) -> bytes:
        return to_be_bytes(input_share, 8)

    def decode_input_share(self, _agg_id: int, encoded: bytes) -> int:
        return from_be_bytes(encoded)

    def encode_public_share(self, public_share: str) -> bytes:
        return public_share.encode('utf-8')

    def decode_public_share(self, encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def encode_agg_share(self, agg_share: int) -> bytes:
        return to_be_bytes(agg_share, 8)

    def decode_agg_share(self, _agg_param: int, encoded: bytes) -> int:
        return from_be_bytes(encoded)

    def encode_verifier_share(self, verifier_share: str) -> bytes:
        return verifier_share.encode('utf-8')

    def decode_verifier_share(self,
                              _verify_state: tuple[int, int],
                              encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def encode_verifier_message(self, verifier_message: str) -> bytes:
        return verifier_message.encode('utf-8')

    def decode_verifier_message(self,
                                _verify_state: tuple[int, int],
                                encoded: bytes) -> str:
        return encoded.decode('utf-8')

    def encode_out_share(self, out_share: int) -> bytes:
        return to_be_bytes(out_share, 8)

    def decode_out_share(self, _agg_param: int, encoded: bytes) -> int:
        return from_be_bytes(encoded)

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
        ctx = b'some context'
        nonce = b''
        rand = b''
        (public_share, input_shares) = vdaf.shard(
            ctx,
            measurement,
            nonce,
            rand,
        )

        agg_param = 23
        leader_init_state = vdaf.ping_pong_leader_init(
            verify_key,
            ctx,
            vdaf.encode_agg_param(agg_param),
            nonce,
            vdaf.encode_public_share(public_share),
            vdaf.encode_input_share(input_shares[0]),
        )
        assert isinstance(leader_init_state, Continued)
        self.assertEqual(leader_init_state.verify_round, 0)

        helper_state = vdaf.ping_pong_helper_init(
            verify_key,
            ctx,
            vdaf.encode_agg_param(agg_param),
            nonce,
            vdaf.encode_public_share(public_share),
            vdaf.encode_input_share(input_shares[1]),
            leader_init_state.outbound,
        )
        assert isinstance(helper_state, FinishedWithOutbound)

        leader_state = vdaf.ping_pong_leader_continued(
            ctx,
            vdaf.encode_agg_param(agg_param),
            leader_init_state,
            helper_state.outbound,
        )
        self.assertTrue(isinstance(leader_state, Finished))

    def test_multi_round(self) -> None:
        """Test the ping pong flow with multiple rounds."""
        verify_key = b''
        measurement = 1337
        ctx = b'some application'
        nonce = b''
        rand = b''
        agg_param = 23

        for num_rounds in range(1, 10):
            num_steps = math.ceil((num_rounds+1) / 2)

            vdaf = PingPongTester(num_rounds)

            (public_share, input_shares) = vdaf.shard(
                ctx,
                measurement,
                nonce,
                rand,
            )

            leader_state: State = vdaf.ping_pong_leader_init(
                verify_key,
                ctx,
                vdaf.encode_agg_param(agg_param),
                nonce,
                vdaf.encode_public_share(public_share),
                vdaf.encode_input_share(input_shares[0]),
            )
            assert isinstance(leader_state, Continued)
            self.assertEqual(leader_state.verify_round, 0)

            for step in range(num_steps):
                if step == 0:
                    assert isinstance(leader_state, Continued)
                    helper_state: State = vdaf.ping_pong_helper_init(
                        verify_key,
                        ctx,
                        vdaf.encode_agg_param(agg_param),
                        nonce,
                        vdaf.encode_public_share(public_share),
                        vdaf.encode_input_share(input_shares[1]),
                        leader_state.outbound,
                    )
                else:
                    assert isinstance(leader_state, Continued) or \
                        isinstance(leader_state, FinishedWithOutbound)
                    helper_state = vdaf.ping_pong_helper_continued(
                        vdaf.encode_agg_param(agg_param),
                        ctx,
                        cast(Continued, helper_state),
                        leader_state.outbound,
                    )

                if isinstance(leader_state, Continued):
                    assert isinstance(helper_state, Continued) or \
                        isinstance(helper_state, FinishedWithOutbound)
                    leader_state = vdaf.ping_pong_leader_continued(
                        vdaf.encode_agg_param(agg_param),
                        ctx,
                        leader_state,
                        helper_state.outbound,
                    )

            if num_rounds & 1 == 1:
                self.assertTrue(isinstance(leader_state, Finished))
                self.assertTrue(isinstance(helper_state, FinishedWithOutbound))
            else:
                self.assertTrue(isinstance(leader_state, FinishedWithOutbound))
                self.assertTrue(isinstance(helper_state, Finished))
