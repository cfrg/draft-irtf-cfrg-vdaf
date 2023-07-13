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
    Field = field.Field

    # Length of the joint randomness shared by the prover and verifier.
    JOINT_RAND_LEN: Unsigned

    # Length of the randomness consumed by the prover.
    PROVE_RAND_LEN: Unsigned

    # Length of the randomness consumed by the verifier.
    QUERY_RAND_LEN: Unsigned

    # Length of the encoded input.
    INPUT_LEN: Unsigned

    # Length of aggregatable output.
    OUTPUT_LEN: Unsigned

    # Length of the proof.
    PROOF_LEN: Unsigned

    # Length of the verifier message.
    VERIFIER_LEN: Unsigned

    @classmethod
    def encode(Flp, measurement: Measurement) -> Vec[Field]:
        """Encode a measurement as an input."""
        raise NotImplementedError()

    @classmethod
    def prove(Flp,
              inp: Vec[Field],
              prove_rand: Vec[Field],
              joint_rand: Vec[Field]) -> Vec[Field]:
        """Generate a proof of an input's validity."""
        raise NotImplementedError()

    @classmethod
    def query(Flp,
              inp: Vec[Field],
              proof: Vec[Field],
              query_rand: Vec[Field],
              joint_rand: Vec[Field],
              num_shares: Unsigned) -> Vec[Field]:
        """Generate a verifier message for an input and proof."""
        raise NotImplementedError()

    @classmethod
    def decide(Flp, verifier: Vec[Field]) -> Bool:
        """Decide if a verifier message was generated from a valid input."""
        raise NotImplementedError()

    @classmethod
    def truncate(Flp, inp: Vec[Field]) -> Vec[Field]:
        """Map an input to an aggregatable output."""
        raise NotImplementedError()

    @classmethod
    def decode(output: Vec[Field], num_measurements: Unsigned) -> AggResult:
        """Decode an aggregate result."""
        raise NotImplementedError()

    @classmethod
    def test_vec_set_type_param(Vdaf, test_vec):
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
def run_flp(Flp, inp: Vec[Flp.Field], num_shares: Unsigned):
    """Run the FLP on an input."""

    joint_rand = Flp.Field.rand_vec(Flp.JOINT_RAND_LEN)
    prove_rand = Flp.Field.rand_vec(Flp.PROVE_RAND_LEN)
    query_rand = Flp.Field.rand_vec(Flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = Flp.prove(inp, prove_rand, joint_rand)

    # Shard the input and the proof.
    input_shares = additive_secret_share(inp, num_shares, Flp.Field)
    proof_shares = additive_secret_share(proof, num_shares, Flp.Field)

    # Verifier queries the input shares and proof shares.
    verifier_shares = [
        Flp.query(
            input_share,
            proof_share,
            query_rand,
            joint_rand,
            num_shares,
        )
        for input_share, proof_share in zip(input_shares, proof_shares)
    ]

    # Combine the verifier shares into the verifier.
    verifier = Flp.Field.zeros(len(verifier_shares[0]))
    for verifier_share in verifier_shares:
        verifier = vec_add(verifier, verifier_share)

    # Verifier decides if the input is valid.
    return Flp.decide(verifier)


##
# TESTS
#


class FlpTest(Flp):
    """An insecure FLP used only for testing."""
    # Associated parameters
    JOINT_RAND_LEN = 1
    PROVE_RAND_LEN = 2
    QUERY_RAND_LEN = 3
    INPUT_LEN = 2
    OUTPUT_LEN = 1
    PROOF_LEN = 2
    VERIFIER_LEN = 2

    # Associated types
    Measurement = Unsigned
    AggResult = Unsigned

    # Operational parameters
    input_range = range(5)

    @classmethod
    def encode(cls, measurement):
        if measurement not in cls.input_range:
            raise ERR_ENCODE
        return [cls.Field(measurement)] * 2

    @classmethod
    def prove(cls, inp, prove_rand, joint_rand):
        # The proof is the input itself for this trivially insecure FLP.
        return deepcopy(inp)

    @classmethod
    def query(cls, inp, proof, query_rand, joint_rand, _num_shares):
        return deepcopy(proof)

    @classmethod
    def decide(cls, verifier):
        """Decide if a verifier message was generated from a valid input."""
        if len(verifier) != 2 or \
                verifier[0] != verifier[1] or \
                verifier[0].as_unsigned() not in cls.input_range:
            return False
        return True

    @classmethod
    def truncate(cls, inp):
        return [inp[0]]

    @classmethod
    def decode(cls, output, _num_measurements):
        return output[0].as_unsigned()


class FlpTestField128(FlpTest):
    Field = field.Field128

    @classmethod
    def with_joint_rand_len(cls, joint_rand_len):
        class NewFlpTestField128(FlpTestField128):
            JOINT_RAND_LEN = joint_rand_len
        return NewFlpTestField128


if __name__ == '__main__':
    cls = FlpTestField128
    assert run_flp(cls, cls.encode(0), 3) == True
    assert run_flp(cls, cls.encode(4), 3) == True
    assert run_flp(cls, [field.Field128(1337)], 3) == False
