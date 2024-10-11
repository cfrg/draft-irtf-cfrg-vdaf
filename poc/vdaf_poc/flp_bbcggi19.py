"""The FLP of {{BBCGGI19}}, Theorem 4.3."""

from abc import ABCMeta, abstractmethod
from copy import deepcopy
from typing import Any, Generic, Optional, TypeVar, cast

from vdaf_poc.common import front, next_power_of_2
from vdaf_poc.field import (NttField, poly_eval, poly_interp, poly_mul,
                            poly_strip)
from vdaf_poc.flp import Flp

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)


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
    Field -- An NTT-friendly field

    Attributes:
    field -- Class object for the NTT-friendly field.
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
    # verifier_len() methods are excerpted in the document, de-indented. Their
    # width should be limited to 69 columns after de-indenting, or 73 columns
    # before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def prove_rand_len(self) -> int:
        """Length of the prover randomness."""
        return sum(g.ARITY for g in self.GADGETS)

    def query_rand_len(self) -> int:
        """Length of the query randomness."""
        query_rand_len = len(self.GADGETS)
        if self.EVAL_OUTPUT_LEN > 1:
            query_rand_len += self.EVAL_OUTPUT_LEN
        return query_rand_len

    def proof_len(self) -> int:
        """Length of the proof."""
        length = 0
        for (g, g_calls) in zip(self.GADGETS, self.GADGET_CALLS):
            p = next_power_of_2(1 + g_calls)
            length += g.ARITY + g.DEGREE * (p - 1) + 1
        return length

    def verifier_len(self) -> int:
        """Length of the verifier message."""
        length = 1
        for g in self.GADGETS:
            length += g.ARITY + 1
        return length

    def check_valid_eval(
            self,
            meas: list[F],
            joint_rand: list[F]) -> None:
        if len(meas) != self.MEAS_LEN:
            raise ValueError('incorrect measurement length')
        if len(joint_rand) != self.JOINT_RAND_LEN:
            raise ValueError('incorrect joint randomness length')

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
               agg: list[F],
               num_measurements: int) -> AggResult:
        """
        Decode an aggregate result.

        Pre-conditions:

            - `len(agg) == self.OUTPUT_LEN`
            - `num_measurements >= 1`
        """
        pass

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
        pass

    def test_vec_set_type_param(self, _test_vec: dict[str, Any]) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []


# NOTE: The class below is excerpted in the document. Its width
# should be limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class ProveGadget(Gadget[F]):
    """
    Gadget wrapper that records the input wires for each evaluation.
    """

    def __init__(self,
                 field: type[F],
                 wire_seeds: list[F],
                 g: Gadget[F],
                 g_calls: int):
        assert len(wire_seeds) == g.ARITY  # REMOVE ME
        p = next_power_of_2(1 + g_calls)
        self.inner = g
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wires = []
        self.k = 0  # evaluation counter
        for s in wire_seeds:
            wire = field.zeros(p)
            wire[0] = s  # set the wire seed
            self.wires.append(wire)

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.k += 1
        for j in range(len(inp)):
            self.wires[j][self.k] = inp[j]
        return self.inner.eval(field, inp)

    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        return self.inner.eval_poly(field, inp_poly)

    @classmethod
    def wrap(cls,
             valid: Valid[Measurement, AggResult, F],
             prove_rand: list[F],
             ) -> Valid[Measurement, AggResult, F]:
        """
        Make a copy of `valid` with each gadget wrapped for recording
        the wire inputs. `prove_rand` is used to produce the wire
        seeds for each gadget.
        """
        assert len(prove_rand) == valid.prove_rand_len()  # REMOVE ME
        wrapped_gadgets: list[Gadget[F]] = []
        for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
            (wire_seeds, prove_rand) = front(g.ARITY, prove_rand)
            wrapped = cls(valid.field, wire_seeds, g, g_calls)
            wrapped_gadgets.append(wrapped)
        assert len(prove_rand) == 0  # REMOVE ME
        wrapped_valid = deepcopy(valid)
        wrapped_valid.GADGETS = wrapped_gadgets
        return wrapped_valid


# NOTE: The class below is excerpted in the document. Its width
# should be limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class QueryGadget(Gadget[F]):
    """
    Gadget wrapper that records the input wires for each evaluation.
    Rather than evaluate the circuit, use the provided gadget
    polynomial to produce the output.
    """

    def __init__(
            self,
            field: type[F],
            wire_seeds: list[F],
            gadget_poly: list[F],
            g: Gadget[F],
            g_calls: int):
        assert len(wire_seeds) == g.ARITY  # REMOVE ME
        p = next_power_of_2(1 + g_calls)
        assert field.GEN_ORDER % p == 0  # REMOVE ME
        self.alpha = field.gen() ** (field.GEN_ORDER // p)
        self.poly = gadget_poly
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wires = []
        self.k = 0
        for s in wire_seeds:
            wire = field.zeros(p)
            wire[0] = s  # set the wire seed
            self.wires.append(wire)

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.k += 1
        for j in range(len(inp)):
            self.wires[j][self.k] = inp[j]
        return poly_eval(field, self.poly, self.alpha ** self.k)

    # REMOVE ME
    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        raise NotImplementedError("not used by verifier")

    @classmethod
    def wrap(cls,
             valid: Valid[Measurement, AggResult, F],
             proof: list[F]) -> Valid[Measurement, AggResult, F]:
        assert len(proof) == valid.proof_len()  # REMOVE ME
        wrapped_gadgets: list[Gadget[F]] = []
        for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
            p = next_power_of_2(1 + g_calls)
            gadget_poly_len = g.DEGREE * (p - 1) + 1
            (wire_seeds, proof) = front(g.ARITY, proof)
            (gadget_poly, proof) = front(gadget_poly_len, proof)
            wrapped = cls(valid.field,
                          wire_seeds,
                          gadget_poly,
                          g,
                          g_calls)
            wrapped_gadgets.append(wrapped)
        assert len(proof) == 0  # REMOVE ME
        wrapped_valid = deepcopy(valid)
        wrapped_valid.GADGETS = wrapped_gadgets
        return wrapped_valid


class FlpBBCGGI19(Flp[Measurement, AggResult, F]):
    """The FLP of {{BBCGGI19}}, Theorem 4.3 with some extensions."""

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

    # NOTE: Methods `prove()`, `query()`, and `decide()` are all
    # excerpted in the document, de-indented. Their width should be
    # limited to 73 columns to avoid warnings from xml2rfc.
    # ===================================================================
    def prove(self,
              meas: list[F],
              prove_rand: list[F],
              joint_rand: list[F]) -> list[F]:
        assert len(meas) == self.MEAS_LEN  # REMOVE ME
        assert len(prove_rand) == self.PROVE_RAND_LEN  # REMOVE ME
        assert len(joint_rand) == self.JOINT_RAND_LEN  # REMOVE ME

        # Evaluate the validity circuit, recording the value of each
        # input wire for each evaluation of each gadget.
        valid = ProveGadget.wrap(self.valid, prove_rand)
        valid.eval(meas, joint_rand, 1)

        # Construct the proof, which consists of the wire seeds and
        # gadget polynomial for each gadget.
        proof = []
        for g in cast(list[ProveGadget[F]], valid.GADGETS):
            p = len(g.wires[0])

            # Compute the wire polynomials for this gadget. For each `j`,
            # find the lowest degree polynomial `wire_poly` for which
            # `wire_poly(alpha^k) = g.wires[j][k]` for all `k`. Note that
            # each `g.wires[j][0]` is set to the seed of wire `j`, which
            # is included in the prove randomness.
            #
            # Implementation note: `alpha` is a root of unity, which
            # means `poly_interp()` can be evaluated using the NTT. Note
            # that `g.wires[j]` is padded with 0s to a power of 2.
            assert self.field.GEN_ORDER % p == 0  # REMOVE ME
            alpha = self.field.gen() ** (self.field.GEN_ORDER // p)
            wire_inp = [alpha ** k for k in range(p)]
            wire_polys = []
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.field, wire_inp, g.wires[j])
                wire_polys.append(wire_poly)

            # Compute the gadget polynomial by evaluating the gadget on
            # the wire polynomials. By construction we have that
            # `gadget_poly(alpha^k)` is the `k`-th output.
            gadget_poly = g.eval_poly(self.field, wire_polys)

            for j in range(g.ARITY):
                proof.append(g.wires[j][0])
            proof += gadget_poly

        assert len(proof) == self.PROOF_LEN  # REMOVE ME
        return proof

    def query(self,
              meas: list[F],
              proof: list[F],
              query_rand: list[F],
              joint_rand: list[F],
              num_shares: int) -> list[F]:
        assert len(meas) == self.MEAS_LEN  # REMOVE ME
        assert len(proof) == self.PROOF_LEN  # REMOVE ME
        assert len(query_rand) == self.QUERY_RAND_LEN  # REMOVE ME
        assert len(joint_rand) == self.JOINT_RAND_LEN  # REMOVE ME

        # Evaluate the validity circuit, recording the value of each
        # input wire for each evaluation of each gadget. Use the gadget
        # polynomials encoded by `proof` to compute the gadget outputs.
        valid = QueryGadget.wrap(self.valid, proof)
        out = valid.eval(meas, joint_rand, num_shares)
        assert len(out) == self.valid.EVAL_OUTPUT_LEN  # REMOVE ME

        # Reduce the output.
        if self.valid.EVAL_OUTPUT_LEN > 1:
            (rand, query_rand) = front(
                self.valid.EVAL_OUTPUT_LEN,
                query_rand,
            )
            v = self.field(0)
            for (r, out_elem) in zip(rand, out):
                v += r * out_elem
        else:
            [v] = out

        # Construct the verifier message, which consists of the reduced
        # circuit output and each gadget test.
        verifier = [v]
        for (g, t) in zip(cast(list[QueryGadget[F]], valid.GADGETS),
                          query_rand):
            p = len(g.wires[0])

            # Abort if `t` is one of the inputs used to compute the wire
            # polynomials so that the verifier message doesn't leak the
            # gadget output. It suffices to check if `t` is a root of
            # unity, which implies it is a power of `alpha`.
            if t ** p == self.field(1):
                raise ValueError('test point is a root of unity')

            # To test the gadget, we re-compute the wire polynomials and
            # check for consistency with the gadget polynomial provided
            # by the prover. To start, evaluate the gadget polynomial and
            # each of the wire polynomials at the random point `t`.
            wire_checks = []
            wire_inp = [g.alpha ** k for k in range(p)]
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.field, wire_inp, g.wires[j])
                wire_checks.append(poly_eval(self.field, wire_poly, t))

            gadget_check = poly_eval(self.field, g.poly, t)

            verifier += wire_checks
            verifier.append(gadget_check)

        return verifier

    def decide(self, verifier: list[F]) -> bool:
        assert len(verifier) == self.VERIFIER_LEN  # REMOVE ME

        # Check the output of the validity circuit.
        ([v], verifier) = front(1, verifier)
        if v != self.field(0):
            return False

        # Complete each gadget test.
        for g in self.valid.GADGETS:
            (wire_checks, verifier) = front(g.ARITY, verifier)
            ([gadget_check], verifier) = front(1, verifier)
            if g.eval(self.field, wire_checks) != gadget_check:
                return False

        assert len(verifier) == 0  # REMOVE ME
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

# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class Mul(Gadget[F]):
    ARITY = 2
    DEGREE = 2

    def eval(self, _field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)  # REMOVE ME
        return inp[0] * inp[1]

    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)  # REMOVE ME
        return poly_mul(field, inp_poly[0], inp_poly[1])


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class PolyEval(Gadget[F]):
    ARITY = 1
    p: list[int]  # polynomial coefficients

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
        self.check_gadget_eval(inp)  # REMOVE ME
        p = [field(coeff) for coeff in self.p]
        return poly_eval(field, p, inp[0])

    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)  # REMOVE ME
        p = [field(coeff) for coeff in self.p]
        out = [field(0)] * (self.DEGREE * len(inp_poly[0]))
        out[0] = p[0]
        x = inp_poly[0]
        for i in range(1, len(p)):
            for j in range(len(x)):
                out[j] += p[i] * x[j]
            x = poly_mul(field, x, inp_poly[0])
        return poly_strip(field, out)


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class ParallelSum(Gadget[F]):
    # REMOVE ME
    """
    Evaluates a subcircuit (represented by a Gadget) on multiple
    inputs, adds the results, and returns the sum.

    The `count` parameter determines how many times the `subcircuit`
    gadget will be called. The arity of this gadget is equal to the
    arity of the subcircuit multiplied by the `count` parameter, and
    the degree of this gadget is equal to the degree of the
    subcircuit. Input wires will be sequentially mapped to input
    wires of the subcircuit instances.

    Section 4.4 of the BBCGGI19 paper outlines an optimization for
    circuits fitting the parallel sum form, wherein a sum of n
    identical subcircuits can be replaced with sqrt(n) parallel sum
    gadgets, each adding up sqrt(n) subcircuit results. This results
    in smaller proofs, since the proof size linearly depends on both
    the arity of gadgets and the number of times gadgets are called.
    """
    subcircuit: Gadget[F]
    count: int

    def __init__(self, subcircuit: Gadget[F], count: int):
        self.subcircuit = subcircuit
        self.count = count
        self.ARITY = subcircuit.ARITY * count
        self.DEGREE = subcircuit.DEGREE

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)  # REMOVE ME
        out = field(0)
        for i in range(self.count):
            start_index = i * self.subcircuit.ARITY
            end_index = (i + 1) * self.subcircuit.ARITY
            out += self.subcircuit.eval(
                field,
                inp[start_index:end_index],
            )
        return out

    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)  # REMOVE ME
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

# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class Count(Valid[int, int, F]):
    GADGETS: list[Gadget[F]] = [Mul()]
    GADGET_CALLS = [1]
    MEAS_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1
    EVAL_OUTPUT_LEN = 1

    # Class object for the field.
    field: type[F]

    def __init__(self, field: type[F]):
        self.field = field

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            _num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME
        squared = self.GADGETS[0].eval(self.field,
                                       [meas[0], meas[0]])
        return [squared - meas[0]]

    def encode(self, measurement: int) -> list[F]:
        if measurement not in range(2):  # REMOVE ME
            raise ValueError('measurement out of range')  # REMOVE ME
        return [self.field(measurement)]

    def truncate(self, meas: list[F]) -> list[F]:
        if len(meas) != 1:  # REMOVE ME
            raise ValueError('incorrect measurement length')  # REMOVE ME
        return meas

    def decode(self, output: list[F], _num_measurements: int) -> int:
        return output[0].as_unsigned()


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class Histogram(Valid[int, list[int], F]):
    EVAL_OUTPUT_LEN = 2
    field: type[F]
    length: int
    chunk_length: int

    def __init__(self,
                 field: type[F],
                 length: int,
                 chunk_length: int):
        """
        Instantiate an instance of the `Histogram` circuit with the
        given `length` and `chunk_length`.
        """
        # REMOVE ME
        if length <= 0:
            raise ValueError('invalid length')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        self.field = field
        self.length = length
        self.chunk_length = chunk_length
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [
            (length + chunk_length - 1) // chunk_length]
        self.MEAS_LEN = self.length
        self.OUTPUT_LEN = self.length
        self.JOINT_RAND_LEN = self.GADGET_CALLS[0]

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME

        # Check that each bucket is one or zero.
        range_check = self.field(0)
        shares_inv = self.field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            r = joint_rand[i]
            r_power = r
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

            range_check += self.GADGETS[0].eval(
                self.field,
                cast(list[F], inputs),
            )

        # Check that the buckets sum to 1.
        sum_check = -shares_inv
        for b in meas:
            sum_check += b

        return [range_check, sum_check]

    def encode(self, measurement: int) -> list[F]:
        encoded = [self.field(0)] * self.length
        encoded[measurement] = self.field(1)
        return encoded

    def truncate(self, meas: list[F]) -> list[F]:
        return meas

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [bucket_count.as_unsigned()
                for bucket_count in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = int(self.length)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'chunk_length']


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class MultihotCountVec(Valid[list[int], list[int], F]):
    # REMOVE ME
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
    EVAL_OUTPUT_LEN = 2
    field: type[F]

    def __init__(self,
                 field: type[F],
                 length: int,
                 max_weight: int,
                 chunk_length: int):
        """
        Instantiate an instance of the this circuit with the given
        `length`, `max_weight`, and `chunk_length`.

        Pre-conditions:

            - `length > 0`
            - `0 < max_weight` and `max_weight <= length`
            - `chunk_length > 0`
        """
        # REMOVE ME
        if length <= 0:
            raise ValueError('invalid length')
        if max_weight <= 0 or max_weight > length:
            raise ValueError('invalid max_weight')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        self.field = field

        # Compute the number of bits to represent `max_weight`.
        self.bits_for_weight = max_weight.bit_length()
        self.offset = self.field(
            2**self.bits_for_weight - 1 - max_weight)

        # Make sure `offset + length` doesn't overflow the field
        # modulus. Otherwise we may not correctly compute the sum
        # measurement vector entries during circuit evaluation.
        if self.field.MODULUS - self.offset.as_unsigned() <= length:
            raise ValueError('length and max_weight are too large '
                             'for the current field size')

        self.length = length
        self.max_weight = max_weight
        self.chunk_length = chunk_length
        self.GADGETS: list[Gadget[F]] = [
            ParallelSum(Mul(), chunk_length),
        ]
        self.GADGET_CALLS = [
            (length + self.bits_for_weight + chunk_length - 1)
            // chunk_length
        ]
        self.MEAS_LEN = self.length + self.bits_for_weight
        self.OUTPUT_LEN = self.length
        self.JOINT_RAND_LEN = self.GADGET_CALLS[0]

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME

        # Check that each entry in the input vector is one or zero.
        range_check = self.field(0)
        shares_inv = self.field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            r = joint_rand[i]
            r_power = r
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

            range_check += self.GADGETS[0].eval(
                self.field,
                cast(list[F], inputs),
            )

        # Check that the weight `offset` plus the sum of the counters
        # is equal to the value claimed by the Client.
        count_vec = meas[:self.length]
        weight = sum(count_vec, self.field(0))
        weight_reported = \
            self.field.decode_from_bit_vector(meas[self.length:])
        weight_check = self.offset*shares_inv + weight - \
            weight_reported

        return [range_check, weight_check]

    def encode(self, measurement: list[int]) -> list[F]:
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

    def truncate(self, meas: list[F]) -> list[F]:
        return meas[:self.length]

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [bucket_count.as_unsigned() for
                bucket_count in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = int(self.length)
        test_vec['max_weight'] = int(self.max_weight)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'max_weight', 'chunk_length']


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class SumVec(Valid[list[int], list[int], F]):
    EVAL_OUTPUT_LEN = 1
    length: int
    bits: int
    chunk_length: int
    field: type[F]

    def __init__(self,
                 field: type[F],
                 length: int,
                 bits: int,
                 chunk_length: int):
        """
        Instantiate the `SumVec` circuit for measurements with
        `length` elements, each in the range `[0, 2^bits)`.
        """
        # REMOVE ME
        if 2 ** bits >= field.MODULUS:
            raise ValueError('bit size exceeds field modulus')
        if bits <= 0:
            raise ValueError('invalid bits')
        if length <= 0:
            raise ValueError('invalid length')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        self.field = field
        self.length = length
        self.bits = bits
        self.chunk_length = chunk_length
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [
            (length * bits + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = length * bits
        self.OUTPUT_LEN = length
        self.JOINT_RAND_LEN = self.GADGET_CALLS[0]

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME

        out = self.field(0)
        shares_inv = self.field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            r = joint_rand[i]
            r_power = r
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

    def encode(self, measurement: list[int]) -> list[F]:
        # REMOVE ME
        if len(measurement) != self.length:
            raise ValueError('incorrect measurement length')

        encoded = []
        for val in measurement:
            # REMOVE ME
            if val not in range(2**self.bits):
                raise ValueError(
                    'entry of measurement vector is out of range'
                )

            encoded += self.field.encode_into_bit_vector(
                val, self.bits)
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


# NOTE: This class is excerpted in the document, de-indented. Its
# width should be limited to 69 columns to avoid warnings from
# xml2rfc.
# ===================================================================
class Sum(Valid[int, int, F]):
    GADGETS: list[Gadget[F]] = [PolyEval([0, -1, 1])]
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1
    field: type[F]

    def __init__(self, field: type[F], max_measurement: int):
        # REMOVE ME
        """
        A circuit that checks that the measurement is in range `[0,
        max_measurement]`. This is accomplished by encoding the
        measurement as a bit vector, encoding the measurement plus an
        offset as a bit vector, then checking that the two encoded
        integers are consistent.

        Let

        - `bits = max_measurement.bit_length()`
        - `offset = 2**bits - 1 - max_measurement`

        The first bit-encoded integer is the measurement itself. Note
        that only measurements between `0` and `2**bits - 1` can be
        encoded this way with `bits` bits. The second bit-encoded integer
        is the sum of the measurement and `offset`. Observe that only
        measurements between `-offset` and `max_measurement` inclusive
        can be encoded this way with `bits` bits.

        To do the range check, the circuit first checks that each entry
        of both bit vectors is a one or a zero. It then decodes both the
        measurement and the offset measurement, and subtracts `offset`
        from the latter. It then checks if these two values are equal.
        Since both the measurement and the measurement plus `offset` are
        in the same range of `0` to `2**bits - 1`, this means that the
        measurement itself is between `0` and `max_measurement`.
        """
        self.field = field
        self.bits = max_measurement.bit_length()
        self.offset = self.field(2**self.bits - 1 - max_measurement)
        self.max_measurement = max_measurement
        if 2 ** self.bits >= self.field.MODULUS:  # REMOVE ME
            raise ValueError('bound exceeds field modulus')  # REMOVE ME

        self.GADGET_CALLS = [2 * self.bits]
        self.MEAS_LEN = 2 * self.bits
        self.EVAL_OUTPUT_LEN = 2 * self.bits + 1

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME
        shares_inv = self.field(num_shares).inv()

        out = []
        for b in meas:
            out.append(self.GADGETS[0].eval(self.field, [b]))

        range_check = self.offset * shares_inv + \
            self.field.decode_from_bit_vector(meas[:self.bits]) - \
            self.field.decode_from_bit_vector(meas[self.bits:])
        out.append(range_check)
        return out

    def encode(self, measurement: int) -> list[F]:
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

    def truncate(self, meas: list[F]) -> list[F]:
        return [self.field.decode_from_bit_vector(meas[:self.bits])]

    def decode(self, output: list[F], _num_measurements: int) -> int:
        return output[0].as_unsigned()

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['max_measurement'] = int(self.max_measurement)
        return ['max_measurement']
