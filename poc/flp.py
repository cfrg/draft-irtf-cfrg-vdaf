"""Fully linear proof (FLP) systems."""

import field
from common import Bool, Unsigned, Vec, vec_add, vec_sub
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

    def test_vec_set_type_param(self, test_vec) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []


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
