import unittest
from copy import deepcopy
from typing import TypeVar

from field import Field, Field128
from flp import Flp, run_flp

F = TypeVar("F", bound=Field)


class FlpTest(Flp[int, int, F]):
    """An insecure FLP used only for testing."""
    PROVE_RAND_LEN = 2
    QUERY_RAND_LEN = 3
    MEAS_LEN = 2
    OUTPUT_LEN = 1
    PROOF_LEN = 2
    VERIFIER_LEN = 2

    meas_range = range(5)

    def __init__(self, field: type[F], joint_rand_len: int):
        self.field = field
        self.JOINT_RAND_LEN = joint_rand_len

    def encode(self, measurement: int) -> list[F]:
        return [self.field(measurement)] * 2

    def prove(self, meas: list[F], _prove_rand: list[F], _joint_rand: list[F]) -> list[F]:
        # The proof is the measurement itself for this trivially insecure FLP.
        return deepcopy(meas)

    def query(self, meas: list[F], proof: list[F], query_rand: list[F], joint_rand: list[F], _num_shares: int) -> list[F]:
        return deepcopy(proof)

    def decide(self, verifier: list[F]) -> bool:
        """Decide if a verifier message was generated from a valid
        measurement."""
        if len(verifier) != 2 or \
                verifier[0] != verifier[1] or \
                verifier[0].as_unsigned() not in self.meas_range:
            return False
        return True

    def truncate(self, meas: list[F]) -> list[F]:
        return [meas[0]]

    def decode(self, output: list[F], _num_measurements: int) -> int:
        return output[0].as_unsigned()


class TestFlp(unittest.TestCase):
    def test_flp(self) -> None:
        flp = FlpTest(Field128, 1)
        assert run_flp(flp, flp.encode(0), 3) is True
        assert run_flp(flp, flp.encode(4), 3) is True
        assert run_flp(flp, [Field128(1337)], 3) is False
