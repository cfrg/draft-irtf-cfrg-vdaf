import unittest
from copy import deepcopy
from typing import Generic, TypeVar

import field
from flp import Flp, run_flp


F = TypeVar('F', bound=field.Field)


class FlpTest(Flp[int, int, F]):
    """An insecure FLP used only for testing."""
    # Associated parameters
    JOINT_RAND_LEN = 1
    PROVE_RAND_LEN = 2
    QUERY_RAND_LEN = 3
    MEAS_LEN = 2
    OUTPUT_LEN = 1
    PROOF_LEN = 2
    VERIFIER_LEN = 2

    # Operational parameters
    meas_range = range(5)
    field: type[F]

    def __init__(self, field: type[F]):
        self.field = field

    def encode(self, measurement: int):
        return [self.field(measurement)] * 2

    def prove(self,
              meas: list[F],
              prove_rand: list[F],
              joint_rand: list[F]) -> list[F]:
        # The proof is the measurement itself for this trivially insecure FLP.
        return deepcopy(meas)

    def query(self,
              meas: list[F],
              proof: list[F],
              query_rand: list[F],
              joint_rand: list[F],
              num_shares: int) -> list[F]:
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

    @staticmethod
    def with_joint_rand_len(joint_rand_len):
        flp = FlpTest(field.Field128)
        flp.JOINT_RAND_LEN = joint_rand_len
        return flp


class TestFlp(unittest.TestCase):
    def test_flp(self):
        flp = FlpTest(field.Field128)
        assert run_flp(flp, flp.encode(0), 3) is True
        assert run_flp(flp, flp.encode(4), 3) is True
        assert run_flp(flp, [field.Field128(1337)], 3) is False
