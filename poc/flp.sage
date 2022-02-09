# Fully linear proof (FLP) systems.

from copy import deepcopy
from sagelib.common import ERR_ENCODE, Bool, Error, Unsigned, Vec

import sagelib.field as field


# The base class for FLPs.
class Flp:
    # Generic paraemters
    Field = field.Field
    Measurement = None

    # Length of the joint randomness shared by the prover and verifier.
    JOINT_RAND_LEN: Unsigned

    # Length of the randomness consumed by the prover.
    JOINT_RAND_LEN: Unsigned

    # Length of the randomness consumed by the verifier.
    JOINT_RAND_LEN: Unsigned

    # Length of the encoded input.
    INPUT_LEN: Unsigned

    # Length of aggregatable output.
    OUTPUT_LEN: Unsigned

    # Length of the proof.
    PROOF_LEN: Unsigned

    # Length of the verifier message.
    VERIFIER_LEN: Unsigned

    # Encode a measurement as an input.
    @classmethod
    def encode(cls, measurement: Measurement) -> Vec[Field]:
        raise Error("not implemented")

    # Generate a proof of an input's validity.
    @classmethod
    def prove(cls,
              inp: Vec[Field],
              prove_rand: Vec[Field],
              joint_rand: Vec[Field]) -> Vec[Field]:
        raise Error("not implemented")

    # Generate a verifier message for an input and proof.
    @classmethod
    def query(cls,
              inp: Vec[Field],
              proof: Vec[Field],
              query_rand: Vec[Field],
              joint_rand: Vec[Field],
              num_shares: Unsigned) -> Vec[Field]:
        raise Error("not implemented")

    # Decide if a verifier message was generated from a valid input.
    @classmethod
    def decide(cls, verifier: Vec[Field]) -> Bool:
        raise Error("not implemented")

    #  Map an input to an aggregatable output.
    @classmethod
    def truncate(cls, inp: Vec[Field]) -> Vec[Field]:
        raise Error("not implemented")


# Run the FLP on an input.
#
# NOTE This is used to generate {{run-flp}}.
def run_flp(Flp, inp: Vec[Flp.Field], num_shares: Unsigned):
    joint_rand = Flp.Field.rand_vec(Flp.JOINT_RAND_LEN)
    prove_rand = Flp.Field.rand_vec(Flp.PROVE_RAND_LEN)
    query_rand = Flp.Field.rand_vec(Flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = Flp.prove(inp, prove_rand, joint_rand)

    # Verifier queries the input and proof.
    verifier = Flp.query(inp, proof, query_rand, joint_rand, num_shares)

    # Verifier decides if the input is valid.
    return Flp.decide(verifier)


##
# TESTS
#

# An insecure FLP used only for testing.
class FlpTest(Flp):
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

    # Decide if a verifier message was generated from a valid input.
    @classmethod
    def decide(cls, verifier):
        if len(verifier) != 2 or \
                verifier[0] != verifier[1] or \
                verifier[0].as_unsigned() not in cls.input_range:
            return False
        return True

    @classmethod
    def truncate(cls, inp):
        return [inp[0]]


class FlpTestField128(FlpTest):
    Field = field.Field128

    @classmethod
    def with_joint_rand_len(cls, joint_rand_len):
        new_cls = deepcopy(cls)
        new_cls.JOINT_RAND_LEN = joint_rand_len
        return new_cls


def test_flp(Flp, inp, expected_decision):
    assert run_flp(Flp, inp, 1) == expected_decision


if __name__ == "__main__":
    cls = FlpTestField128
    test_flp(cls, cls.encode(0), True)
    test_flp(cls, cls.encode(4), True)
    test_flp(cls, [field.Field128(1337)], False)
