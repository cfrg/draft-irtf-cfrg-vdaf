"""Fully linear proof (FLP) systems."""

from abc import ABCMeta, abstractmethod
from typing import Any, Generic, TypeVar

from vdaf_poc.common import vec_add, vec_sub
from vdaf_poc.field import Field

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=Field)


class Flp(Generic[Measurement, AggResult, F], metaclass=ABCMeta):
    """The base class for FLPs."""

    # Class object for the field.
    field: type[F]

    # Length of the joint randomness shared by the prover and verifier.
    JOINT_RAND_LEN: int

    # Length of the randomness consumed by the prover.
    PROVE_RAND_LEN: int

    # Length of the randomness consumed by the verifier.
    QUERY_RAND_LEN: int

    # Length of the encoded measurement.
    MEAS_LEN: int

    # Length of aggregatable output.
    OUTPUT_LEN: int

    # Length of the proof.
    PROOF_LEN: int

    # Length of the verifier message.
    VERIFIER_LEN: int

    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def encode(self, measurement: Measurement) -> list[F]:
        """Encode a measurement."""
        pass

    @abstractmethod
    def prove(self,
              meas: list[F],
              prove_rand: list[F],
              joint_rand: list[F]) -> list[F]:
        """
        Generate a proof of a measurement's validity.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
            - `len(prove_rand) == self.PROVE_RAND_LEN`
            - `len(joint_rand) == self.JOINT_RAND_LEN`
        """
        pass

    @abstractmethod
    def query(self,
              meas: list[F],
              proof: list[F],
              query_rand: list[F],
              joint_rand: list[F],
              num_shares: int) -> list[F]:
        """
        Generate a verifier message for a measurement and proof.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
            - `len(proof) == self.PROOF_LEN`
            - `len(query_rand) == self.QUERY_RAND_LEN`
            - `len(joint_rand) == self.JOINT_RAND_LEN`
            - `num_shares >= 1`
        """
        pass

    @abstractmethod
    def decide(self, verifier: list[F]) -> bool:
        """
        Decide if a verifier message was generated from a valid measurement.

        Pre-conditions:

            - `len(verifier) == self.VERIFIER_LEN`
        """
        pass

    @abstractmethod
    def truncate(self, meas: list[F]) -> list[F]:
        """
        Map an encoded measurement to an aggregatable output.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
        """
        pass

    @abstractmethod
    def decode(self, output: list[F], num_measurements: int) -> AggResult:
        """
        Decode an aggregate result.

        Pre-conditions:

            - `len(output) == self.OUTPUT_LEN`
            - `num_measurements >= 1`
        """
        pass

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []


def additive_secret_share(
        vec: list[F],
        num_shares: int,
        field: type[F]) -> list[list[F]]:
    shares = [
        field.rand_vec(len(vec))
        for _ in range(num_shares - 1)
    ]
    last_share = vec
    for other_share in shares:
        last_share = vec_sub(last_share, other_share)
    shares.append(last_share)
    return shares


# NOTE This function is excerpted in the document, as the figure
# {{run-flp}}. Its width should be limited to 69 columns to avoid
# warnings from xml2rfc.
# ===================================================================
def run_flp(
        flp: Flp[Measurement, AggResult, F],
        meas: list[F],
        num_shares: int) -> bool:
    """Run the FLP on an encoded measurement."""

    joint_rand = flp.field.rand_vec(flp.JOINT_RAND_LEN)
    prove_rand = flp.field.rand_vec(flp.PROVE_RAND_LEN)
    query_rand = flp.field.rand_vec(flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = flp.prove(meas, prove_rand, joint_rand)

    # Shard the measurement and the proof.
    meas_shares = additive_secret_share(
        meas,
        num_shares,
        flp.field,
    )
    proof_shares = additive_secret_share(
        proof,
        num_shares,
        flp.field,
    )

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
    verifier = flp.field.zeros(len(verifier_shares[0]))
    for verifier_share in verifier_shares:
        verifier = vec_add(verifier, verifier_share)

    # Verifier decides if the measurement is valid.
    return flp.decide(verifier)
