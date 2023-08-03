"""Fully linear proof (FLP) systems."""

from copy import deepcopy

import field
from common import ERR_ENCODE, Bool, Unsigned, Vec, vec_add, vec_sub
from field import Field


class Flp:
    """The base class for FLPs."""

    # Generic paraemters
    Measurement = None
    AggResult = None
    Field: field.Field = None

    # Length of the joint randomness shared by the prover and verifier.
    JOINT_RAND_LEN: Unsigned

    # Length of the randomness consumed by the prover.
    PROVE_RAND_LEN: Unsigned

    # Length of the randomness consumed by the verifier.
    QUERY_RAND_LEN: Unsigned

    # Length of the encoded measurement.
    MEAS_LEN: Unsigned

    # Length of aggregatable output.
    OUTPUT_LEN: Unsigned

    # Length of the proof.
    PROOF_LEN: Unsigned

    # Length of the verifier message.
    VERIFIER_LEN: Unsigned

    def encode(self, measurement: Measurement) -> Vec[Field]:
        """Encode a measurement."""
        raise NotImplementedError()

    def prove(self,
              meas: Vec[Field],
              prove_rand: Vec[Field],
              joint_rand: Vec[Field]) -> Vec[Field]:
        """Generate a proof of a measurement's validity."""
        raise NotImplementedError()

    def query(self,
              meas: Vec[Field],
              proof: Vec[Field],
              query_rand: Vec[Field],
              joint_rand: Vec[Field],
              num_shares: Unsigned) -> Vec[Field]:
        """Generate a verifier message for a measurement and proof."""
        raise NotImplementedError()

    def decide(self, verifier: Vec[Field]) -> Bool:
        """Decide if a verifier message was generated from a valid measurement."""
        raise NotImplementedError()

    def truncate(self, meas: Vec[Field]) -> Vec[Field]:
        """Map an encoded measurement to an aggregatable output."""
        raise NotImplementedError()

    def decode(self, output: Vec[Field], num_measurements: Unsigned) -> AggResult:
        """Decode an aggregate result."""
        raise NotImplementedError()

    def test_vec_set_type_param(self, test_vec):
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Return the key that was set or `None` if `test_vec` was not
        modified.
        """
        return None


def additive_secret_share(vec: Vec[Field],
                          num_shares: Unsigned,
                          field: type) -> Vec[Vec[Field]]:
    shares = [
        field.rand_vec(len(vec))
        for _ in range(num_shares - 1)
    ]
    last_share = vec
    for other_share in shares:
        last_share = vec_sub(last_share, other_share)
    shares.append(last_share)
    return shares


# NOTE This is used to generate {{run-flp}}.
def run_flp(flp, meas: Vec[Flp.Field], num_shares: Unsigned):
    """Run the FLP on an encoded measurement."""

    joint_rand = flp.Field.rand_vec(flp.JOINT_RAND_LEN)
    prove_rand = flp.Field.rand_vec(flp.PROVE_RAND_LEN)
    query_rand = flp.Field.rand_vec(flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = flp.prove(meas, prove_rand, joint_rand)

    # Shard the measurement and the proof.
    meas_shares = additive_secret_share(meas, num_shares, flp.Field)
    proof_shares = additive_secret_share(proof, num_shares, flp.Field)

    # Verifier queries the meas shares and proof shares.
    verifier_shares = [
        flp.query(
            meas_share,
            proof_share,
            query_rand,
            joint_rand,
            num_shares,
        )
        for meas_share, proof_share in zip(meas_shares, proof_shares)
    ]

    # Combine the verifier shares into the verifier.
    verifier = flp.Field.zeros(len(verifier_shares[0]))
    for verifier_share in verifier_shares:
        verifier = vec_add(verifier, verifier_share)

    # Verifier decides if the measurement is valid.
    return flp.decide(verifier)


##
# TESTS
#


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
    Field = field.Field128

    @staticmethod
    def with_joint_rand_len(joint_rand_len):
        flp = FlpTestField128()
        flp.JOINT_RAND_LEN = joint_rand_len
        return flp


if __name__ == '__main__':
    flp = FlpTestField128()
    assert run_flp(flp, flp.encode(0), 3) == True
    assert run_flp(flp, flp.encode(4), 3) == True
    assert run_flp(flp, [field.Field128(1337)], 3) == False
