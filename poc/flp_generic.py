"""A generic FLP based on {{BBCGGI19}}, Theorem 4.3."""

import copy
from abc import ABCMeta, abstractmethod
from typing import Any, Generic, Optional, TypeVar, cast

from common import front, next_power_of_2
from field import (FftField, Field64, Field128, poly_eval, poly_interp,
                   poly_mul, poly_strip)
from flp import Flp

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=FftField)


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

    # NOTE: The prove_rand_len(), query_rand_len(), proof_len(), and
    # verifier_len() methods are excerpted in the document, de-indented.
    # Their width should be limited to 69 columns after de-indenting, or
    # 73 columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
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


class ProveGadget(Gadget[F]):
    def __init__(self, field: type[F], wire_seeds: list[F], g: Gadget[F], g_calls: int):
        self.inner = g
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wire = []
        P = next_power_of_2(1 + g_calls)
        for j in range(g.ARITY):
            self.wire.append(field.zeros(P))
            self.wire[j][0] = wire_seeds[j]
        self.k = 0

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.k += 1
        for j in range(len(inp)):
            self.wire[j][self.k] = inp[j]
        return self.inner.eval(field, inp)

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        return self.inner.eval_poly(field, inp_poly)


def prove_wrapped(
        valid: Valid[Measurement, AggResult, F],
        prove_rand: list[F]) -> Valid[Measurement, AggResult, F]:
    if len(prove_rand) != valid.prove_rand_len():
        raise ValueError('incorrect proof length')

    wrapped_gadgets: list[Gadget[F]] = []
    for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
        wire_seeds, prove_rand = prove_rand[:g.ARITY], prove_rand[g.ARITY:]
        wrapped = ProveGadget[F](valid.field, wire_seeds, g, g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(prove_rand) == 0
    wrapped_valid = copy.deepcopy(valid)
    wrapped_valid.GADGETS = wrapped_gadgets
    return wrapped_valid


class QueryGadget(Gadget[F]):
    def __init__(
            self,
            field: type[F],
            wire_seeds: list[F],
            gadget_poly: list[F],
            g: Gadget[F],
            g_calls: int):
        self.inner = g
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wire = []
        self.gadget_poly = gadget_poly
        P = next_power_of_2(1 + g_calls)
        for j in range(g.ARITY):
            self.wire.append(field.zeros(P))
            self.wire[j][0] = wire_seeds[j]
        assert field.GEN_ORDER % P == 0
        self.alpha = field.gen() ** (field.GEN_ORDER // P)
        self.k = 0

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.k += 1
        for j in range(len(inp)):
            self.wire[j][self.k] = inp[j]
        return poly_eval(field, self.gadget_poly, self.alpha ** self.k)

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        raise NotImplementedError(
            "QueryGadget does not need to implement eval_poly()"
        )


def query_wrapped(
        valid: Valid[Measurement, AggResult, F],
        proof: list[F]) -> Valid[Measurement, AggResult, F]:
    if len(proof) != valid.proof_len():
        raise ValueError('incorrect proof length')

    wrapped_gadgets: list[Gadget[F]] = []
    for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        gadget_poly_len = g.DEGREE * (P - 1) + 1
        wire_seeds, proof = proof[:g.ARITY], proof[g.ARITY:]
        gadget_poly, proof = proof[:gadget_poly_len], proof[gadget_poly_len:]
        wrapped = QueryGadget(
            valid.field,
            wire_seeds,
            gadget_poly,
            g,
            g_calls,
        )
        wrapped_gadgets.append(wrapped)
    assert len(proof) == 0
    wrapped_valid = copy.deepcopy(valid)
    wrapped_valid.GADGETS = wrapped_gadgets
    return wrapped_valid


class FlpGeneric(Flp[Measurement, AggResult, F]):
    """An FLP constructed from a validity circuit."""

    # Validity circuit and AFE.
    valid: Valid[Measurement, AggResult, F]

    def __init__(self, valid: Valid[Measurement, AggResult, F]):
        """Instantiate the generic FLP for the given validity circuit."""
        self.valid = valid
        self.field = valid.field
        self.PROVE_RAND_LEN = valid.prove_rand_len()
        self.QUERY_RAND_LEN = valid.query_rand_len()
        self.JOINT_RAND_LEN = valid.JOINT_RAND_LEN
        self.MEAS_LEN = valid.MEAS_LEN
        self.OUTPUT_LEN = valid.OUTPUT_LEN
        self.PROOF_LEN = valid.proof_len()
        self.VERIFIER_LEN = valid.verifier_len()

    def prove(self, meas: list[F], prove_rand: list[F], joint_rand: list[F]) -> list[F]:
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget.
        valid = prove_wrapped(self.valid, prove_rand)
        valid.eval(meas, joint_rand, 1)

        # Construct the proof.
        proof = []
        # Downcast the gadgets from list[Gadget[F]] to list[ProveGadget[F]],
        # so we can access the wire values. The call to prove_wrapped() above
        # ensures that all gadgets will be of this type.
        for g in cast(list[ProveGadget[F]], valid.GADGETS):
            P = len(g.wire[0])

            # Compute the wire polynomials for this gadget.
            #
            # NOTE We pad the wire inputs to the nearest power of 2 so that we
            # can use FFT for interpolating the wire polynomials. Perhaps there
            # is some clever math for picking `wire_inp` in a way that avoids
            # having to pad.
            assert self.field.GEN_ORDER % P == 0
            alpha = self.field.gen() ** (self.field.GEN_ORDER // P)
            wire_inp = [alpha ** k for k in range(P)]
            wire_polys = []
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.field, wire_inp, g.wire[j])
                wire_polys.append(wire_poly)

            # Compute the gadget polynomial.
            gadget_poly = g.eval_poly(self.field, wire_polys)

            for j in range(g.ARITY):
                proof.append(g.wire[j][0])
            proof += gadget_poly

        return proof

    def query(
            self,
            meas: list[F],
            proof: list[F],
            query_rand: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget. The gadget output is computed by
        # evaluating the gadget polynomial.
        valid = query_wrapped(self.valid, proof)
        out = valid.eval(meas, joint_rand, num_shares)

        if len(out) != self.valid.EVAL_OUTPUT_LEN:
            raise ValueError('circuit has unexpected output length')

        if len(query_rand) != self.valid.query_rand_len():
            raise ValueError('incorrect query randomness length')

        # Reduce the output.
        if self.valid.EVAL_OUTPUT_LEN > 1:
            ([r], query_rand) = front(1, query_rand)
            r_power = r
            v = self.field(0)
            for x in out:
                v += r_power * x
                r_power *= r
        else:
            [v] = out

        # Construct the verifier message.
        verifier = [v]
        for (g, t) in zip(cast(list[QueryGadget[F]], valid.GADGETS), query_rand):
            P = len(g.wire[0])

            # Check if `t` is a degenerate point and abort if so.
            #
            # A degenerate point is one that was used as an input for
            # constructing the gadget polynomial. Using such a point would leak
            # an output of the gadget to the verifier.
            if t ** P == self.field(1):
                raise ValueError('query randomness contains a root of unity')

            # Compute the well-formedness test for the gadget polynomial.
            wire_inp = [g.alpha ** k for k in range(P)]
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.field, wire_inp, g.wire[j])
                verifier.append(poly_eval(self.field, wire_poly, t))

            verifier.append(poly_eval(self.field, g.gadget_poly, t))

        return verifier

    def decide(self, verifier: list[F]) -> bool:
        if len(verifier) != self.valid.verifier_len():
            raise ValueError('incorrect verifier length')

        # Check the output of the validity circuit.
        v, verifier = verifier[0], verifier[1:]
        if v != self.field(0):
            return False

        # Check for well-formedness of each gadget polynomial.
        for g in self.valid.GADGETS:
            x, verifier = verifier[:g.ARITY], verifier[g.ARITY:]
            y, verifier = verifier[0], verifier[1:]
            z = g.eval(self.field, x)
            if z != y:
                return False

        assert len(verifier) == 0
        return True

    def encode(self, measurement: Measurement) -> list[F]:
        return self.valid.encode(measurement)

    def truncate(self, meas: list[F]) -> list[F]:
        return self.valid.truncate(meas)

    def decode(self, output: list[F], num_measurements: int) -> AggResult:
        return self.valid.decode(output, num_measurements)

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        return self.valid.test_vec_set_type_param(test_vec)


##
# GADGETS
#

class Mul(Gadget[F]):
    ARITY = 2
    DEGREE = 2

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(self, _field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)
        return inp[0] * inp[1]

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)
        return poly_mul(field, inp_poly[0], inp_poly[1])


class Range2(Gadget[F]):
    """
    Takes one input and computes x^2 - x.
    """

    ARITY = 1
    DEGREE = 2

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(self, _field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)
        return inp[0] * inp[0] - inp[0]

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)
        output_poly_length = self.DEGREE * (len(inp_poly[0]) - 1) + 1
        out = [field(0) for _ in range(output_poly_length)]
        x = inp_poly[0]
        x_squared = poly_mul(field, x, x)
        for (i, x_i) in enumerate(x):
            out[i] -= x_i
        for (i, x_squared_i) in enumerate(x_squared):
            out[i] += x_squared_i
        return poly_strip(field, out)


class PolyEval(Gadget[F]):
    # Polynomial coefficients.
    p: list[int]

    ARITY = 1

    def __init__(self, p: list[int]):
        """
        Instantiate this gadget with the given polynomial.
        """

        # Strip leading zeros.
        for i in reversed(range(len(p))):
            if p[i] != 0:
                p = p[:i+1]
                break

        if len(p) < 1:
            raise ValueError('invalid polynomial: zero length')

        self.p = p
        self.DEGREE = len(p) - 1

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)
        p = [field(coeff) for coeff in self.p]
        return poly_eval(field, p, inp[0])

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)
        p = [field(coeff) for coeff in self.p]
        out = [field(0)] * (self.DEGREE * len(inp_poly[0]))
        out[0] = p[0]
        x = inp_poly[0]
        for i in range(1, len(p)):
            for j in range(len(x)):
                out[j] += p[i] * x[j]
            x = poly_mul(field, x, inp_poly[0])
        return poly_strip(field, out)


class ParallelSum(Gadget[F]):
    """
    Evaluates a subcircuit (represented by a Gadget) on multiple inputs, adds
    the results, and returns the sum.

    The `count` parameter determines how many times the `subcircuit` gadget will
    be called. The arity of this gadget is equal to the arity of the subcircuit
    multiplied by the `count` parameter, and the degree of this gadget is equal
    to the degree of the subcircuit. Input wires will be sequentially mapped to
    input wires of the subcircuit instances.

    Section 4.4 of the BBCGGI19 paper outlines an optimization for circuits
    fitting the parallel sum form, wherein a sum of n identical subcircuits can
    be replaced with sqrt(n) parallel sum gadgets, each adding up sqrt(n)
    subcircuit results. This results in smaller proofs, since the proof size
    linearly depends on both the arity of gadgets and the number of times
    gadgets are called.
    """

    subcircuit: Gadget[F]
    count: int

    def __init__(self, subcircuit: Gadget[F], count: int):
        self.subcircuit = subcircuit
        self.count = count
        self.ARITY = subcircuit.ARITY * count
        self.DEGREE = subcircuit.DEGREE

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(self, field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)
        out = field(0)
        for i in range(self.count):
            start_index = i * self.subcircuit.ARITY
            end_index = (i + 1) * self.subcircuit.ARITY
            out += self.subcircuit.eval(
                field,
                inp[start_index:end_index],
            )
        return out

    def eval_poly(self, field: type[F], inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)
        output_poly_length = self.DEGREE * (len(inp_poly[0]) - 1) + 1
        out_sum = [field(0) for _ in range(output_poly_length)]
        for i in range(self.count):
            start_index = i * self.subcircuit.ARITY
            end_index = (i + 1) * self.subcircuit.ARITY
            out_current = self.subcircuit.eval_poly(
                field,
                inp_poly[start_index:end_index]
            )
            for j in range(output_poly_length):
                out_sum[j] += out_current[j]
        return poly_strip(field, out_sum)


##
# TYPES
#

class Count(
        Valid[
            int,  # Measurement, 0 or 1
            int,  # AggResult
            Field64,
        ]):
    field = Field64
    GADGETS: list[Gadget[Field64]] = [Mul()]
    GADGET_CALLS = [1]
    MEAS_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1
    EVAL_OUTPUT_LEN = 1

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            meas: list[Field64],
            joint_rand: list[Field64],
            _num_shares: int) -> list[Field64]:
        self.check_valid_eval(meas, joint_rand)
        squared = self.GADGETS[0].eval(self.field, [meas[0], meas[0]])
        return [squared - meas[0]]

    def encode(self, measurement: int) -> list[Field64]:
        if measurement not in [0, 1]:
            raise ValueError('measurement out of range')
        return [self.field(measurement)]

    def truncate(self, meas: list[Field64]) -> list[Field64]:
        if len(meas) != 1:
            raise ValueError('incorrect encoded measurement length')
        return meas

    def decode(self, output: list[Field64], _num_measurements: int) -> int:
        return output[0].as_unsigned()


class Sum(
        Valid[
            int,  # Measurement, `range(2 ** self.bits)`
            int,  # AggResult
            Field128,
        ]):
    field = Field128
    GADGETS: list[Gadget[Field128]] = [Range2()]
    JOINT_RAND_LEN = 1
    OUTPUT_LEN = 1
    EVAL_OUTPUT_LEN = 1

    def __init__(self, bits: int):
        """
        Instantiate an instace of the `Sum` circuit for measurements in range `[0,
        2^bits)`.
        """

        if 2 ** bits >= self.field.MODULUS:
            raise ValueError('bit size exceeds field modulus')

        self.GADGET_CALLS = [bits]
        self.MEAS_LEN = bits

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            meas: list[Field128],
            joint_rand: list[Field128],
            _num_shares: int) -> list[Field128]:
        self.check_valid_eval(meas, joint_rand)
        out = self.field(0)
        r = joint_rand[0]
        for b in meas:
            out += r * self.GADGETS[0].eval(self.field, [b])
            r *= joint_rand[0]
        return [out]

    # NOTE: The encode(), truncate(), and decode() methods are excerpted
    # in the document, de-indented. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def encode(self, measurement: int) -> list[Field128]:
        if 0 > measurement or measurement >= 2 ** self.MEAS_LEN:
            raise ValueError('measurement out of range')

        return self.field.encode_into_bit_vector(measurement,
                                                 self.MEAS_LEN)

    def truncate(self, meas: list[Field128]) -> list[Field128]:
        return [self.field.decode_from_bit_vector(meas)]

    def decode(
            self,
            output: list[Field128],
            _num_measurements: int) -> int:
        return output[0].as_unsigned()

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['bits'] = int(self.MEAS_LEN)
        return ['bits']


class Histogram(
        Valid[
            int,        # Measurement, `range(length)`
            list[int],  # AggResult
            Field128,
        ]):
    length: int
    chunk_length: int

    field = Field128
    JOINT_RAND_LEN = 2
    EVAL_OUTPUT_LEN = 1

    def __init__(self, length: int, chunk_length: int):
        """
        Instantiate an instance of the `Histogram` circuit with the given
        length and chunk_length.
        """

        if length <= 0:
            raise ValueError('invalid length')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        self.length = length
        self.chunk_length = chunk_length
        self.GADGETS: list[Gadget[Field128]] = [
            ParallelSum(Mul(), chunk_length),
        ]
        self.GADGET_CALLS = [(length + chunk_length - 1) // chunk_length]
        self.MEAS_LEN = self.length
        self.OUTPUT_LEN = self.length

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            meas: list[Field128],
            joint_rand: list[Field128],
            num_shares: int) -> list[Field128]:
        self.check_valid_eval(meas, joint_rand)

        # Check that each bucket is one or zero.
        range_check = self.field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            inputs: list[Optional[Field128]]
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            range_check += self.GADGETS[0].eval(
                self.field,
                cast(list[Field128], inputs),
            )

        # Check that the buckets sum to 1.
        sum_check = -shares_inv
        for b in meas:
            sum_check += b

        out = joint_rand[1] * range_check + \
            joint_rand[1] ** 2 * sum_check
        return [out]

    # NOTE: The encode(), truncate(), and decode() methods are excerpted
    # in the document, de-indented. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def encode(self, measurement: int) -> list[Field128]:
        encoded = [self.field(0)] * self.length
        encoded[measurement] = self.field(1)
        return encoded

    def truncate(self, meas: list[Field128]) -> list[Field128]:
        return meas

    def decode(
            self,
            output: list[Field128],
            _num_measurements: int) -> list[int]:
        return [bucket_count.as_unsigned() for bucket_count in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = int(self.length)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'chunk_length']


class MultihotCountVec(
        Valid[
            list[int],  # Measurement, a vector of bits
            list[int],  # AggResult, a vector of counts
            Field128,
        ]):
    """
    A validity circuit that checks each Client's measurement is a bit
    vector with at most `max_weight` number of 1s. We call the number
    of 1s in the vector the vector's "weight".

    The circuit determines whether the weight of the vector is at most
    `max_weight` as follows. First, it computes the weight of the
    vector by summing the entries. Second, it compares the computed
    weight to the weight reported by the Client and accepts the input
    only if they are equal. Let

    * `bits_for_weight = max_weight.bit_length()`
    * `offset = 2**bits_for_weight - 1 - max_weight`

    The reported weight is encoded by adding `offset` to it and
    bit-encoding the result. Observe that only a value at most
    `max_weight` can be encoded with `bits_for_weight` bits.

    The verifier checks that each entry of the encoded measurement is
    a bit (i.e., either one or zero). It then decodes the reported
    weight and subtracts it from `offset + sum(count_vec)`, where
    `count_vec` is the count vector. The result is zero if and only if
    the reported weight is equal to the true weight.
    """
    field = Field128
    JOINT_RAND_LEN = 2
    EVAL_OUTPUT_LEN = 1

    def __init__(self, length: int, max_weight: int, chunk_length: int):
        """
        Instantiate an instance of the this circuit with the given
        `length`, `max_weight`, and `chunk_length`.

        Pre-conditions:

            - `length > 0`
            - `0 < max_weight` and `max_weight <= length`
            - `chunk_length > 0`
        """
        if length <= 0:
            raise ValueError('invalid length')
        if max_weight <= 0 or max_weight > length:
            raise ValueError('invalid max_weight')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        # Compute the number of bits to represent `max_weight`.
        self.bits_for_weight = max_weight.bit_length()
        self.offset = self.field((2 ** self.bits_for_weight) - 1 - max_weight)

        # Make sure `offset + length` doesn't overflow the field
        # modulus. Otherwise we may not correctly compute the sum
        # measurement vector entries during circuit evaluation.
        if self.field.MODULUS - self.offset.as_unsigned() <= length:
            raise ValueError('length and max_weight are too large '
                             'for the current field size')

        self.length = length
        self.max_weight = max_weight
        self.chunk_length = chunk_length
        self.GADGETS: list[Gadget[Field128]] = [
            ParallelSum(Mul(), chunk_length),
        ]
        self.GADGET_CALLS = [
            (length + self.bits_for_weight + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = self.length + self.bits_for_weight
        self.OUTPUT_LEN = self.length

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            meas: list[Field128],
            joint_rand: list[Field128],
            num_shares: int) -> list[Field128]:
        self.check_valid_eval(meas, joint_rand)

        # Check that each entry in the input vector is one or zero.
        range_check = self.field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            inputs: list[Optional[Field128]]
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            range_check += self.GADGETS[0].eval(
                self.field,
                cast(list[Field128], inputs),
            )

        # Check that the weight `offset` plus the sum of the counters
        # is equal to the value claimed by the Client.
        count_vec = meas[:self.length]
        weight = sum(count_vec, self.field(0))
        weight_reported = \
            self.field.decode_from_bit_vector(meas[self.length:])
        weight_check = self.offset*shares_inv + weight - \
            weight_reported

        out = joint_rand[1] * range_check + \
            joint_rand[1] ** 2 * weight_check
        return [out]

    # NOTE: The encode(), truncate(), and decode() methods are excerpted
    # in the document, de-indented. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def encode(self, measurement: list[int]) -> list[Field128]:
        if len(measurement) != self.length:
            raise ValueError('invalid Client measurement length')

        # The first part is the vector of counters.
        count_vec = list(map(self.field, measurement))

        # The second part is the reported weight.
        weight_reported = sum(count_vec, self.field(0))

        encoded = []
        encoded += count_vec
        encoded += self.field.encode_into_bit_vector(
            (self.offset + weight_reported).as_unsigned(),
            self.bits_for_weight)
        return encoded

    def truncate(self, meas: list[Field128]) -> list[Field128]:
        return meas[:self.length]

    def decode(
            self,
            output: list[Field128],
            _num_measurements: int) -> list[int]:
        return [bucket_count.as_unsigned() for bucket_count in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = int(self.length)
        test_vec['max_weight'] = int(self.max_weight)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'max_weight', 'chunk_length']


class SumVec(
        Valid[
            list[int],  # Measurement
            list[int],  # AggResult
            F,
        ]):
    length: int
    bits: int
    chunk_length: int

    field: type[F]
    JOINT_RAND_LEN = 1
    EVAL_OUTPUT_LEN = 1

    def __init__(self, length: int, bits: int, chunk_length: int, field: type[F]):
        """
        Instantiate the `SumVec` circuit for measurements with `length`
        elements, each in the range `[0, 2^bits)`.
        """

        if 2 ** bits >= field.MODULUS:
            raise ValueError('bit size exceeds field modulus')
        if bits <= 0:
            raise ValueError('invalid bits')
        if length <= 0:
            raise ValueError('invalid length')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        self.length = length
        self.bits = bits
        self.chunk_length = chunk_length
        self.field = field
        self.GADGETS: list[Gadget[F]] = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [
            (length * bits + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = length * bits
        self.OUTPUT_LEN = length

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)

        out = self.field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.field(num_shares).inv()

        for i in range(self.GADGET_CALLS[0]):
            inputs: list[Optional[F]]
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            out += self.GADGETS[0].eval(
                self.field,
                cast(list[F], inputs),
            )

        return [out]

    # NOTE: The encode(), truncate(), and decode() methods are excerpted
    # in the document, de-indented. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def encode(self, measurement: list[int]) -> list[F]:
        if len(measurement) != self.length:
            raise ValueError('incorrect measurement length')

        encoded = []
        for val in measurement:
            if val not in range(2**self.bits):
                raise ValueError(
                    'entry of measurement vector is out of range'
                )

            encoded += self.field.encode_into_bit_vector(val, self.bits)
        return encoded

    def truncate(self, meas: list[F]) -> list[F]:
        truncated = []
        for i in range(self.length):
            truncated.append(self.field.decode_from_bit_vector(
                meas[i * self.bits: (i + 1) * self.bits]
            ))
        return truncated

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [x.as_unsigned() for x in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = self.length
        test_vec['bits'] = self.bits
        test_vec['chunk_length'] = self.chunk_length
        return ['length', 'bits', 'chunk_length']


# TODO(issue #306) Replace `Sum` with this type.
class SumOfRangeCheckedInputs(
        Valid[
            int,  # Measurement, `range(self.max_measurement + 1)`
            int,  # AggResult
            Field64,
        ]):
    field = Field64
    GADGETS: list[Gadget[Field64]] = [Range2()]
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1

    def __init__(self, max_measurement: int):
        """
        Similar to `Sum` but with an arbitrary bound.

        The circuit checks that the measurement is in
        `range(max_measurement+1)`. This is accomplished by encoding the
        measurement in a way that ensures it is in range, then comparing the
        reported measurement to the range checked measurement.

        Let

        - `bits = max_measurement.bit_length()`
        - `offset = 2**bits - 1 - max_measurement`

        The range checked measurement is the bit-encoding of `offset` plus the
        measurement. Observe that only measurements in at most
        `max_measurement` can be encoded with `bits` bits.

        To do the range check, the circuit first checks that each
        entry of this bit vector is a one or a zero. It then decodes
        it and subtracts it from `offset` plus the reported value.
        Since the range checked measurement is in the correct range,
        equality implies that the reported measurement is as well.
        """
        self.bits = max_measurement.bit_length()
        self.offset = self.field(2 ** self.bits - 1 - max_measurement)
        self.max_measurement = max_measurement

        if 2 ** self.bits >= self.field.MODULUS:
            raise ValueError('bound exceeds field modulus')

        self.GADGET_CALLS = [2 * self.bits]
        self.MEAS_LEN = 2 * self.bits
        self.EVAL_OUTPUT_LEN = 2 * self.bits + 1

    def eval(
            self,
            meas: list[Field64],
            joint_rand: list[Field64],
            num_shares: int) -> list[Field64]:
        self.check_valid_eval(meas, joint_rand)
        shares_inv = self.field(num_shares).inv()

        out = []
        for b in meas:
            out.append(self.GADGETS[0].eval(self.field, [b]))

        range_check = self.offset * shares_inv + \
            self.field.decode_from_bit_vector(meas[:self.bits]) - \
            self.field.decode_from_bit_vector(meas[self.bits:])
        out.append(range_check)
        return out

    def encode(self, measurement: int) -> list[Field64]:
        encoded = []
        encoded += self.field.encode_into_bit_vector(
            measurement,
            self.bits
        )
        encoded += self.field.encode_into_bit_vector(
            measurement + self.offset.as_unsigned(),
            self.bits
        )
        return encoded

    def truncate(self, meas: list[Field64]) -> list[Field64]:
        return [self.field.decode_from_bit_vector(meas[:self.bits])]

    def decode(self, output: list[Field64], _num_measurements: int) -> int:
        return output[0].as_unsigned()

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['max_measurement'] = int(self.MEAS_LEN)
        return ['max_measurement']
