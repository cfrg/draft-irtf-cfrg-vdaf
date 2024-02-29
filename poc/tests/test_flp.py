import unittest
from copy import deepcopy

from common import ERR_ENCODE, Unsigned
from field import Field128
from flp import Flp, run_flp


class FlpTest(Flp):
    """An insecure FLP used only for testing."""
    # Associated parameters
    JOINT_RAND_LEN = 1
    PROVE_RAND_LEN = 2
    QUERY_RAND_LEN = 3
    MEAS_LEN = 2
    OUTPUT_LEN = 1
    PROOF_LEN = 2
    VERIFIER_LEN = 2

    # Associated types
    Measurement = Unsigned
    AggResult = Unsigned

    # Operational parameters
    meas_range = range(5)

    def encode(self, measurement):
        if measurement not in self.meas_range:
            raise ERR_ENCODE
        return [self.Field(measurement)] * 2

    def prove(self, meas, prove_rand, joint_rand):
        # The proof is the measurement itself for this trivially insecure FLP.
        return deepcopy(meas)

    def query(self, meas, proof, query_rand, joint_rand, _num_shares):
        return deepcopy(proof)

    def decide(self, verifier):
        """Decide if a verifier message was generated from a valid
        measurement."""
        if len(verifier) != 2 or \
                verifier[0] != verifier[1] or \
                verifier[0].as_unsigned() not in self.meas_range:
            return False
        return True

    def truncate(self, meas):
        return [meas[0]]

    def decode(self, output, _num_measurements):
        return output[0].as_unsigned()


class FlpTestField128(FlpTest):
    Field = Field128

    @staticmethod
    def with_joint_rand_len(joint_rand_len):
        flp = FlpTestField128()
        flp.JOINT_RAND_LEN = joint_rand_len
        return flp


class TestFlp(unittest.TestCase):
    def test_flp(self):
        flp = FlpTestField128()
        assert run_flp(flp, flp.encode(0), 3) is True
        assert run_flp(flp, flp.encode(4), 3) is True
        assert run_flp(flp, [Field128(1337)], 3) is False
