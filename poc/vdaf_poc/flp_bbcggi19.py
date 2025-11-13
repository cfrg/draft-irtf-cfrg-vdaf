"""The FLP of {{BBCGGI19}}, Theorem 4.3."""

from abc import ABCMeta, abstractmethod
from copy import deepcopy
from typing import Any, Generic, Optional, TypeVar, cast

from vdaf_poc.common import assert_power_of_2, front, next_power_of_2
from vdaf_poc.field import Lagrange, NttField, poly_eval
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
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wires = []
        self.k = 0
        for s in wire_seeds:
            wire = field.zeros(p)
            wire[0] = s  # set the wire seed
            self.wires.append(wire)

        # Recover all the values of the gadget_poly.
        lag = Lagrange(field)
        n = next_power_of_2(len(gadget_poly))
        gadget_poly = list(gadget_poly)
        lag.extend_values_to_power_of_2(gadget_poly, n)

        # Calculate 'size' evaluations of the gadget_poly.
        size = next_power_of_2(g.DEGREE * (p - 1) + 1)
        while len(gadget_poly) < size:
            gadget_poly = lag.double_evaluations(gadget_poly)
        self.poly = gadget_poly

        # Get the step size used to index the gadget evaluations.
        log_size = assert_power_of_2(size)
        log_p = assert_power_of_2(p)
        self.step = 1 << (log_size-log_p)

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.k += 1
        for j in range(len(inp)):
            self.wires[j][self.k] = inp[j]
        return self.poly[self.k*self.step]

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
        for g, g_calls in zip(valid.GADGETS, valid.GADGET_CALLS):
            g = cast(ProveGadget[F], g)

            # Define `p` as the smallest power of two accommodating all
            # gadget calls plus one.
            p = next_power_of_2(1 + g_calls)
            assert self.field.GEN_ORDER % p == 0  # REMOVE ME

            # The validity circuit evaluation defines one polynomial for
            # each input wire of each gadget.
            # For each wire `j`, the vector `g.wires[j]` of length `p`
            # is built as follows:
            # - `g.wires[j][0]` is set to the seed for wire `j` (from
            #   the prover's randomness).
            # - The subsequent entries are the assigned values from each
            #   gadget call.
            # - Pad the vector with zeros to reach length `p`.
            # The wire polynomial is then defined by its evaluations:
            #   `wire_poly(alpha**k) = g.wires[j][k]`
            # for all `k`, where `alpha` is a `p`-th root of unity.
            wire_polys = [g.wires[j] for j in range(g.ARITY)]
            assert all(len(wp) == p for wp in wire_polys)  # REMOVE ME

            wire_seeds = [g.wires[j][0] for j in range(g.ARITY)]
            proof += wire_seeds

            # Compute the gadget polynomial by evaluating the gadget
            # on the wire polynomials. By construction we have that
            # `gadget_poly(alpha**k)` is the `k`-th output.
            gadget_poly = g.eval_poly(self.field, wire_polys)
            gadget_poly_len = g.DEGREE * (p - 1) + 1
            proof += gadget_poly[:gadget_poly_len]

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
        lag = Lagrange(self.field)
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
            # by the prover. To start, evaluate the gadget polynomial
            # and each of the wire polynomials at the random point `t`.
            wire_checks = lag.poly_eval_batched(g.wires[:g.ARITY], t)
            gadget_check = lag.poly_eval(g.poly, t)

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
        return Lagrange(field).poly_mul(inp_poly[0], inp_poly[1])


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class PolyEval(Gadget[F]):
    ARITY = 1
    p: list[int]  # polynomial coefficients

    def __init__(self, p: list[int], num_calls: int):
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
        wire_poly_len = next_power_of_2(1+num_calls)
        gadget_poly_len = self.DEGREE*(wire_poly_len-1) + 1
        self.n = next_power_of_2(gadget_poly_len)

    def eval(self, field: type[F], inp: list[F]) -> F:
        self.check_gadget_eval(inp)  # REMOVE ME
        p = [field(coeff) for coeff in self.p]
        return poly_eval(field, p, inp[0])

    def eval_poly(self,
                  field: type[F],
                  inp_poly: list[list[F]]) -> list[F]:
        self.check_gadget_eval_poly(inp_poly)  # REMOVE ME
        inp_poly_len = len(inp_poly[0])
        assert_power_of_2(inp_poly_len)

        # Convert the input polynomial from Lagrange to monomial basis.
        inp_mon = field.inv_ntt(inp_poly[0], inp_poly_len)
        # Obtain n evaluations of the input polynomial I.
        inp_lag = field.ntt(inp_mon, self.n)
        # Returns the polynomial composition (P*I)
        p_mon = [field(coeff) for coeff in self.p]
        return [poly_eval(field, p_mon, x) for x in inp_lag]


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
        output_poly_length = next_power_of_2(
            self.DEGREE * (len(inp_poly[0]) - 1) + 1
        )
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
        return out_sum


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

    def encode(self, measurement: int) -> list[F]:
        if measurement not in range(2):  # REMOVE ME
            raise ValueError('measurement out of range')  # REMOVE ME
        return [self.field(measurement)]

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            _num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME
        squared = self.GADGETS[0].eval(self.field,
                                       [meas[0], meas[0]])
        return [squared - meas[0]]

    def truncate(self, meas: list[F]) -> list[F]:
        if len(meas) != 1:  # REMOVE ME
            raise ValueError('incorrect measurement length')  # REMOVE ME
        return meas

    def decode(self, output: list[F], _num_measurements: int) -> int:
        return output[0].int()


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

    def encode(self, measurement: int) -> list[F]:
        encoded = [self.field(0)] * self.length
        encoded[measurement] = self.field(1)
        return encoded

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

    def truncate(self, meas: list[F]) -> list[F]:
        return meas

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [bucket_count.int()
                for bucket_count in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = int(self.length)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'chunk_length']


# NOTE: This class is excerpted in the document. Its width should be
# limited to 69 columns to avoid warnings from xml2rfc.
# ===================================================================
class MultihotCountVec(Valid[list[bool], list[int], F]):
    # REMOVE ME
    """
    A validity circuit that checks each Client's measurement is a bit
    vector with at most `max_weight` number of true values. We call
    the number of true values in the vector the vector's "weight".

    The circuit validates the encoded measurement as follows. It first
    checks that each entry of the encoded measurement is a bit
    (i.e., either one or zero). Next, it computes the weight of the
    vector by summing the entries and compares the computed weight to
    the weight reported by the Client, accepting the input only if they
    are equal. The reported weight is encoded using the same modified
    bit decomposition as in the Sum circuit, in order to ensure that it
    is in the correct range.
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
        # Precompute value for range check of claimed weight.
        rest_all_ones_value = 2 ** (self.bits_for_weight - 1) - 1
        self.last_weight = max_weight - rest_all_ones_value

        # Make sure `length` and `max_weight` don't overflow the
        # field modulus. Otherwise we may not correctly compute the
        # sum of measurement vector entries during circuit evaluation.
        if self.field.MODULUS <= length:
            raise ValueError('length is too large for the '
                             'current field size')
        if self.field.MODULUS <= max_weight:
            raise ValueError('max_weight is too large for the '
                             'current field size')

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

    def encode(self, measurement: list[bool]) -> list[F]:
        if len(measurement) != self.length:
            raise ValueError('invalid Client measurement length')

        # The first part is the vector of counters.
        count_vec = [self.field(int(x)) for x in measurement]

        # The second part is the reported weight.
        weight_reported = sum(measurement)

        encoded = []
        encoded += count_vec
        # Implementation note: this conditional should be replaced
        # with constant time operations in practice in order to
        # reduce leakage via timing side channels.
        if weight_reported <= 2 ** (self.bits_for_weight - 1) - 1:
            encoded += self.field.encode_into_bit_vec(
                weight_reported,
                self.bits_for_weight - 1,
            )
            encoded += [self.field(0)]
        else:
            encoded += self.field.encode_into_bit_vec(
                weight_reported - self.last_weight,
                self.bits_for_weight - 1,
            )
            encoded += [self.field(1)]
        return encoded

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

        # Check that the sum of the counters is equal to the value
        # claimed by the Client.
        count_vec = meas[:self.length]
        weight = sum(count_vec, self.field(0))
        weight_reported = (
            self.field.decode_from_bit_vec(meas[self.length:-1])
            + meas[-1] * self.field(self.last_weight)
        )
        weight_check = weight - weight_reported

        return [range_check, weight_check]

    def truncate(self, meas: list[F]) -> list[F]:
        return meas[:self.length]

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [bucket_count.int() for
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
    max_measurement: int
    chunk_length: int
    field: type[F]

    def __init__(self,
                 field: type[F],
                 length: int,
                 max_measurement: int,
                 chunk_length: int):
        """
        Instantiate the `SumVec` circuit for measurements with
        `length` elements, each in the range `[0, max_measurement]`.
        """
        # REMOVE ME
        if length <= 0:
            raise ValueError('invalid length')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')
        if max_measurement <= 0:
            raise ValueError('invalid max_measurement')

        self.field = field
        self.length = length
        bits = max_measurement.bit_length()
        self.bits = bits
        self.max_measurement = max_measurement
        rest_all_ones_value = 2 ** (bits - 1) - 1
        self.last_weight = max_measurement - rest_all_ones_value
        self.chunk_length = chunk_length
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [
            (length * bits + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = length * bits
        self.OUTPUT_LEN = length
        self.JOINT_RAND_LEN = self.GADGET_CALLS[0]

        # REMOVE ME
        if 2 ** bits >= field.MODULUS:
            raise ValueError('bound exceeds field modulus')

    def encode(self, measurement: list[int]) -> list[F]:
        # REMOVE ME
        if len(measurement) != self.length:
            raise ValueError('incorrect measurement length')

        encoded = []
        for val in measurement:
            # REMOVE ME
            if val < 0 or val > self.max_measurement:
                raise ValueError(
                    'entry of measurement vector is out of range'
                )

            # Implementation note: this conditional should be
            # replaced with constant time operations in practice in
            # order to reduce leakage via timing side channels.
            if val <= 2 ** (self.bits - 1) - 1:
                encoded += self.field.encode_into_bit_vec(
                    val,
                    self.bits - 1
                )
                encoded += [self.field(0)]
            else:
                encoded += self.field.encode_into_bit_vec(
                    val - self.last_weight,
                    self.bits - 1
                )
                encoded += [self.field(1)]
        return encoded

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

    def truncate(self, meas: list[F]) -> list[F]:
        truncated = []
        for i in range(self.length):
            truncated.append(
                self.field.decode_from_bit_vec(
                    meas[i * self.bits: (i + 1) * self.bits - 1]
                )
                + meas[(i + 1) * self.bits - 1]
                * self.field(self.last_weight)
            )
        return truncated

    def decode(
            self,
            output: list[F],
            _num_measurements: int) -> list[int]:
        return [x.int() for x in output]

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['length'] = self.length
        test_vec['max_measurement'] = self.max_measurement
        test_vec['chunk_length'] = self.chunk_length
        return ['length', 'max_measurement', 'chunk_length']


# NOTE: This class is excerpted in the document. Its
# width should be limited to 69 columns to avoid warnings from
# xml2rfc.
# ===================================================================
class Sum(Valid[int, int, F]):
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1
    field: type[F]

    def __init__(self, field: type[F], max_measurement: int):
        # REMOVE ME
        """
        A circuit that checks that the measurement is in the range
        `[0, max_measurement]`. This is accomplished by encoding the
        measurement as a vector of zeroes and ones, such that a
        weighted sum of the "bits" can only be in this range. All but
        the last of the weights are successive powers of two, as in
        the binary bit decomposition, and the last weight is chosen
        such that the sum of all weights is equal to
        `max_measurement`. With these weights, valid measurements
        have either one or two possible representations as a vector
        of field elements with value zero or one, and invalid
        measurements cannot be represented.

        The validity circuit checks that each entry of the bit vector
        has a value of zero or one.
        """
        self.field = field
        bits = max_measurement.bit_length()
        self.bits = bits
        self.max_measurement = max_measurement
        rest_all_ones_value = 2 ** (bits - 1) - 1
        self.last_weight = max_measurement - rest_all_ones_value

        if 2 ** self.bits >= self.field.MODULUS:  # REMOVE ME
            raise ValueError('bound exceeds field modulus')  # REMOVE ME

        self.GADGET_CALLS = [self.bits]
        self.GADGETS = [PolyEval([0, -1, 1], self.bits)]
        self.MEAS_LEN = self.bits
        self.EVAL_OUTPUT_LEN = self.bits

    def encode(self, measurement: int) -> list[F]:
        encoded = []
        # Implementation note: this conditional should be replaced
        # with constant time operations in practice in order to
        # reduce leakage via timing side channels.
        if measurement <= 2 ** (self.bits - 1) - 1:
            encoded += self.field.encode_into_bit_vec(
                measurement,
                self.bits - 1
            )
            encoded += [self.field(0)]
        else:
            encoded += self.field.encode_into_bit_vec(
                measurement - self.last_weight,
                self.bits - 1
            )
            encoded += [self.field(1)]
        return encoded

    def eval(
            self,
            meas: list[F],
            joint_rand: list[F],
            _num_shares: int) -> list[F]:
        self.check_valid_eval(meas, joint_rand)  # REMOVE ME

        out = []
        for b in meas:
            out.append(self.GADGETS[0].eval(self.field, [b]))

        return out

    def truncate(self, meas: list[F]) -> list[F]:
        return [
            self.field.decode_from_bit_vec(meas[:self.bits - 1])
            + meas[self.bits - 1] * self.field(self.last_weight)
        ]

    def decode(self, output: list[F], _num_measurements: int) -> int:
        return output[0].int()

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['max_measurement'] = int(self.max_measurement)
        return ['max_measurement']
