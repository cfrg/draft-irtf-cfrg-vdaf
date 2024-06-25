from abc import ABCMeta, abstractmethod
from typing import Any, Generic, TypeVar

from common import next_power_of_2
from field import Field

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=Field)


class Gadget(Generic[F], metaclass=ABCMeta):
    """A validity circuit gadget."""

    # Length of the input to the gadget.
    ARITY: int

    # Arithmetic degree of the circuit.
    DEGREE: int

    @abstractmethod
    def eval(self, field: type[F], inp: list[F]) -> F:
        """Evaluate the gadget on a sequence of field elements."""
        pass

    @abstractmethod
    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        """Evaluate the gadget on a sequence of polynomials over a field."""
        pass

    def check_gadget_eval(self, inp: list[F]) -> None:
        if len(inp) != self.ARITY:
            raise ValueError('input length must equal the gadget arity')

    def check_gadget_eval_poly(self, inp_poly: list[list[F]]) -> None:
        if len(inp_poly) != self.ARITY:
            raise ValueError('number of inputs must equal the gadget arity')
        for polynomial in inp_poly:
            if len(polynomial) != len(inp_poly[0]):
                raise ValueError('each input must have the same length')


class Valid(Generic[Measurement, AggResult, F], metaclass=ABCMeta):
    """
    A validity circuit and affine-aggregatable encoding.

    Generic type parameters:
    Measurement -- the measurement type
    AggResult -- the aggregate result type
    Field -- An FFT-friendly field

    Attributes:
    field -- Class object for the FFT-friendly field.
    MEAS_LEN -- Length of the encoded measurement input to the validity
        circuit.
    JOINT_RAND_LEN -- Length of the random input of the validity circuit.
    OUTPUT_LEN -- Length of the aggregatable output for this type.
    EVAL_OUTPUT_LEN -- Length of the output of `eval()`.
    GADGETS -- The sequence of gadgets for this validity circuit.
    GADGET_CALLS -- The number of times each gadget is called. This must have
        the same length as `GADGETS`.
    """

    # Class object for the field.
    field: type[F]

    # Length of the encoded measurement input to the validity circuit.
    MEAS_LEN: int

    # Length of the random input of the validity circuit.
    JOINT_RAND_LEN: int

    # Length of the aggregatable output for this type.
    OUTPUT_LEN: int

    # Length of the output of `eval()`.
    EVAL_OUTPUT_LEN: int

    # The sequence of gadgets for this validity circuit.
    GADGETS: list[Gadget[F]]

    # The number of times each gadget is called. This must have the same length
    # as `GADGETS`.
    GADGET_CALLS: list[int]

    def prove_rand_len(self) -> int:
        """Length of the prover randomness."""
        return sum(g.ARITY for g in self.GADGETS)

    def query_rand_len(self) -> int:
        """Length of the query randomness."""
        query_rand_len = len(self.GADGETS)
        if self.EVAL_OUTPUT_LEN > 1:
            query_rand_len += 1
        return query_rand_len

    def proof_len(self) -> int:
        """Length of the proof."""
        length = 0
        for (g, g_calls) in zip(self.GADGETS, self.GADGET_CALLS):
            P = next_power_of_2(1 + g_calls)
            length += g.ARITY + g.DEGREE * (P - 1) + 1
        return length

    def verifier_len(self) -> int:
        """Length of the verifier message."""
        length = 1
        for g in self.GADGETS:
            length += g.ARITY + 1
        return length

    @abstractmethod
    def encode(self, measurement: Measurement) -> list[F]:
        """Encode a measurement."""
        pass

    @abstractmethod
    def truncate(self, meas: list[F]) -> list[F]:
        """
        Truncate a measurement to the length of an aggregatable output.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
        """
        pass

    @abstractmethod
    def decode(self,
               output: list[F],
               num_measurements: int) -> AggResult:
        """
        Decode an aggregate result.

        Pre-conditions:

            - `len(output) == self.OUTPUT_LEN`
            - `num_measurements >= 1`
        """
        raise NotImplementedError()

    @abstractmethod
    def eval(self,
             meas: list[F],
             joint_rand: list[F],
             num_shares: int) -> list[F]:
        """
        Evaluate the circuit on the provided measurement and joint randomness.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
            - `len(joint_rand) == self.JOINT_RAND_LEN`
            - `num_shares >= 1`

        Post-conditions:

            - return value has length `self.EVAL_OUTPUT_LEN`
        """
        raise NotImplementedError()

    def test_vec_set_type_param(self, _test_vec: dict[str, Any]) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []

    def check_valid_eval(self, meas: list[F], joint_rand: list[F]) -> None:
        if len(meas) != self.MEAS_LEN:
            raise ValueError('incorrect measurement length')
        if len(joint_rand) != self.JOINT_RAND_LEN:
            raise ValueError('incorrect joint randomness length')
