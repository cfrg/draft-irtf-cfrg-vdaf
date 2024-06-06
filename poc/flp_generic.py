"""A generic FLP based on {{BBCGGI19}}, Theorem 4.3."""

import copy

import field
from common import next_power_of_2
from field import poly_eval, poly_interp, poly_mul, poly_strip
from flp import Flp


class Gadget:
    """A validity circuit gadget."""

    # Length of the input to the gadget.
    ARITY: int

    # Arithmetic degree of the circuit.
    DEGREE: int

    def eval(self, Field, inp):
        """Evaluate the gadget on a sequence of field elements."""
        raise NotImplementedError()

    def eval_poly(self, Field, inp_poly):
        """Evaluate the gadget on a sequence of polynomials over a field."""
        raise NotImplementedError()

    def check_gadget_eval(self, inp):
        if len(inp) != self.ARITY:
            raise ValueError('input length must equal the gadget arity')

    def check_gadget_eval_poly(self, inp_poly):
        if len(inp_poly) != self.ARITY:
            raise ValueError('number of inputs must equal the gadget arity')
        for j in range(len(inp_poly)):
            if len(inp_poly[j]) != len(inp_poly[0]):
                raise ValueError('each input must have the same length')


class Valid:
    """
    A validity circuit.
    """

    # Generic parameters overwritten by a concrete validity circuit. `Field`
    # MUST be FFT-friendly.
    Measurement = None
    AggResult = None
    Field: field.FftField = None

    # Length of the encoded measurement input to the validity circuit.
    MEAS_LEN: int

    # Length of the random input of the validity circuit.
    JOINT_RAND_LEN: int

    # Length of the aggregatable output for this type.
    OUTPUT_LEN: int

    # The sequence of gadgets for this validity circuit.
    GADGETS: list[Gadget]

    # The number of times each gadget is called. This must have the same length
    # as `GADGETS`.
    GADGET_CALLS: list[int]

    def prove_rand_len(self):
        """Length of the prover randomness."""
        return sum(g.ARITY for g in self.GADGETS)

    def query_rand_len(self):
        """Length of the query randomness."""
        return len(self.GADGETS)

    def proof_len(self):
        """Length of the proof."""
        length = 0
        for (g, g_calls) in zip(self.GADGETS, self.GADGET_CALLS):
            P = next_power_of_2(1 + g_calls)
            length += g.ARITY + g.DEGREE * (P - 1) + 1
        return length

    def verifier_len(self):
        """Length of the verifier message."""
        length = 1
        for g in self.GADGETS:
            length += g.ARITY + 1
        return length

    def encode(self, measurement: Measurement) -> list[Field]:
        """Encode a measurement."""
        raise NotImplementedError()

    def truncate(self, meas: list[Field]) -> list[Field]:
        """
        Truncate a measurement to the length of an aggregatable output.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
        """
        raise NotImplementedError()

    def decode(self,
               output: list[Field],
               num_measurements: int) -> AggResult:
        """
        Decode an aggregate result.

        Pre-conditions:

            - `len(output) == self.OUTPUT_LEN`
            - `num_measurements >= 1`
        """
        raise NotImplementedError()

    def eval(self,
             meas: list[Field],
             joint_rand: list[Field],
             num_shares: int):
        """
        Evaluate the circuit on the provided measurement and joint randomness.

        Pre-conditions:

            - `len(meas) == self.MEAS_LEN`
            - `len(joint_rand) == self.JOINT_RAND_LEN`
            - `num_shares >= 1`
        """
        raise NotImplementedError()

    def test_vec_set_type_param(self, _test_vec) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []

    def check_valid_eval(self, meas, joint_rand):
        if len(meas) != self.MEAS_LEN:
            raise ValueError('incorrect measurement length')
        if len(joint_rand) != self.JOINT_RAND_LEN:
            raise ValueError('incorrect joint randomness length')

    @classmethod
    def with_field(cls, field: field.FftField):
        class _ValidWithField(cls):
            Field = field
        return _ValidWithField


class ProveGadget:
    def __init__(self, Field, wire_seeds, g, g_calls):
        self.inner = g
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wire = []
        P = next_power_of_2(1 + g_calls)
        for j in range(g.ARITY):
            self.wire.append(Field.zeros(P))
            self.wire[j][0] = wire_seeds[j]
        self.k = 0

    def eval(self, Field, inp):
        self.k += 1
        for j in range(len(inp)):
            self.wire[j][self.k] = inp[j]
        return self.inner.eval(Field, inp)

    def eval_poly(self, Field, inp_poly):
        return self.inner.eval_poly(Field, inp_poly)


def prove_wrapped(valid, prove_rand):
    if len(prove_rand) != valid.prove_rand_len():
        raise ValueError('incorrect proof length')

    wrapped_gadgets = []
    for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
        wire_seeds, prove_rand = prove_rand[:g.ARITY], prove_rand[g.ARITY:]
        wrapped = ProveGadget(valid.Field, wire_seeds, g, g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(prove_rand) == 0
    wrapped_valid = copy.deepcopy(valid)
    wrapped_valid.GADGETS = wrapped_gadgets
    return wrapped_valid


class QueryGadget:
    def __init__(self, Field, wire_seeds, gadget_poly, g, g_calls):
        self.inner = g
        self.ARITY = g.ARITY
        self.DEGREE = g.DEGREE
        self.wire = []
        self.gadget_poly = gadget_poly
        P = next_power_of_2(1 + g_calls)
        for j in range(g.ARITY):
            self.wire.append(Field.zeros(P))
            self.wire[j][0] = wire_seeds[j]
        assert Field.GEN_ORDER % P == 0
        self.alpha = Field.gen() ** (Field.GEN_ORDER // P)
        self.k = 0

    def eval(self, Field, inp):
        self.k += 1
        for j in range(len(inp)):
            self.wire[j][self.k] = inp[j]
        return poly_eval(Field, self.gadget_poly, self.alpha ** self.k)


def query_wrapped(valid, proof):
    if len(proof) != valid.proof_len():
        raise ValueError('incorrect proof length')

    wrapped_gadgets = []
    for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        gadget_poly_len = g.DEGREE * (P - 1) + 1
        wire_seeds, proof = proof[:g.ARITY], proof[g.ARITY:]
        gadget_poly, proof = proof[:gadget_poly_len], proof[gadget_poly_len:]
        wrapped = QueryGadget(valid.Field,
                              wire_seeds,
                              gadget_poly,
                              g,
                              g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(proof) == 0
    wrapped_valid = copy.deepcopy(valid)
    wrapped_valid.GADGETS = wrapped_gadgets
    return wrapped_valid


class FlpGeneric(Flp):
    """An FLP constructed from a validity circuit."""

    Field: field.FftField = None
    Valid = None

    def __init__(self, valid):
        """Instantiate the generic FLP for the given validity circuit."""
        self.Valid = valid
        self.Measurement = valid.Measurement
        self.AggResult = valid.AggResult
        self.Field = valid.Field
        self.PROVE_RAND_LEN = valid.prove_rand_len()
        self.QUERY_RAND_LEN = valid.query_rand_len()
        self.JOINT_RAND_LEN = valid.JOINT_RAND_LEN
        self.MEAS_LEN = valid.MEAS_LEN
        self.OUTPUT_LEN = valid.OUTPUT_LEN
        self.PROOF_LEN = valid.proof_len()
        self.VERIFIER_LEN = valid.verifier_len()

    def prove(self, meas, prove_rand, joint_rand):
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget.
        valid = prove_wrapped(self.Valid, prove_rand)
        valid.eval(meas, joint_rand, 1)

        # Construct the proof.
        proof = []
        for g in valid.GADGETS:
            P = len(g.wire[0])

            # Compute the wire polynomials for this gadget.
            #
            # NOTE We pad the wire inputs to the nearest power of 2 so that we
            # can use FFT for interpolating the wire polynomials. Perhaps there
            # is some clever math for picking `wire_inp` in a way that avoids
            # having to pad.
            assert self.Field.GEN_ORDER % P == 0
            alpha = self.Field.gen() ** (self.Field.GEN_ORDER // P)
            wire_inp = [alpha ** k for k in range(P)]
            wire_polys = []
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.Field, wire_inp, g.wire[j])
                wire_polys.append(wire_poly)

            # Compute the gadget polynomial.
            gadget_poly = g.eval_poly(self.Field, wire_polys)

            for j in range(g.ARITY):
                proof.append(g.wire[j][0])
            proof += gadget_poly

        return proof

    def query(self, meas, proof, query_rand, joint_rand, num_shares):
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget. The gadget output is computed by
        # evaluating the gadget polynomial.
        valid = query_wrapped(self.Valid, proof)
        v = valid.eval(meas, joint_rand, num_shares)

        if len(query_rand) != self.Valid.query_rand_len():
            raise ValueError('incorrect query randomness length')

        # Construct the verifier message.
        verifier = [v]
        for (g, t) in zip(valid.GADGETS, query_rand):
            P = len(g.wire[0])

            # Check if `t` is a degenerate point and abort if so.
            #
            # A degenerate point is one that was used as an input for
            # constructing the gadget polynomial. Using such a point would leak
            # an output of the gadget to the verifier.
            if t ** P == self.Field(1):
                raise ValueError('query randomness contains a root of unity')

            # Compute the well-formedness test for the gadget polynomial.
            x = []
            wire_inp = [g.alpha ** k for k in range(P)]
            for j in range(g.ARITY):
                wire_poly = poly_interp(self.Field, wire_inp, g.wire[j])
                x.append(poly_eval(self.Field, wire_poly, t))

            y = poly_eval(self.Field, g.gadget_poly, t)

            verifier += x
            verifier.append(y)

        return verifier

    def decide(self, verifier):
        if len(verifier) != self.Valid.verifier_len():
            raise ValueError('incorrect verifier length')

        # Check the output of the validity circuit.
        v, verifier = verifier[0], verifier[1:]
        if v != self.Field(0):
            return False

        # Check for well-formedness of each gadget polynomial.
        for g in self.Valid.GADGETS:
            x, verifier = verifier[:g.ARITY], verifier[g.ARITY:]
            y, verifier = verifier[0], verifier[1:]
            z = g.eval(self.Field, x)
            if z != y:
                return False

        assert len(verifier) == 0
        return True

    def encode(self, measurement):
        return self.Valid.encode(measurement)

    def truncate(self, meas):
        return self.Valid.truncate(meas)

    def decode(self, output, num_measurements):
        return self.Valid.decode(output, num_measurements)

    def test_vec_set_type_param(self, test_vec):
        return self.Valid.test_vec_set_type_param(test_vec)


##
# GADGETS
#

class Mul(Gadget):
    ARITY = 2
    DEGREE = 2

    def eval(self, Field, inp):
        self.check_gadget_eval(inp)
        return inp[0] * inp[1]

    def eval_poly(self, Field, inp_poly):
        self.check_gadget_eval_poly(inp_poly)
        return poly_mul(Field, inp_poly[0], inp_poly[1])


class Range2(Gadget):
    """
    Takes one input and computes x^2 - x.
    """

    ARITY = 1
    DEGREE = 2

    def eval(self, Field, inp):
        self.check_gadget_eval(inp)
        return inp[0] * inp[0] - inp[0]

    def eval_poly(self, Field, inp_poly):
        self.check_gadget_eval_poly(inp_poly)
        output_poly_length = self.DEGREE * (len(inp_poly[0]) - 1) + 1
        out = [Field(0) for _ in range(output_poly_length)]
        x = inp_poly[0]
        x_squared = poly_mul(Field, x, x)
        for (i, x_i) in enumerate(x):
            out[i] -= x_i
        for (i, x_squared_i) in enumerate(x_squared):
            out[i] += x_squared_i
        return poly_strip(Field, out)


class PolyEval(Gadget):
    # Operational parameters
    p = None

    ARITY = 1
    DEGREE = None  # Set by constructor

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

    def eval(self, Field, inp):
        self.check_gadget_eval(inp)
        p = list(map(lambda coeff: Field(coeff), self.p))
        return poly_eval(Field, p, inp[0])

    def eval_poly(self, Field, inp_poly):
        self.check_gadget_eval_poly(inp_poly)
        p = list(map(lambda coeff: Field(coeff), self.p))
        out = [Field(0) for _ in range(self.DEGREE * len(inp_poly[0]))]
        out[0] = p[0]
        x = inp_poly[0]
        for i in range(1, len(p)):
            for j in range(len(x)):
                out[j] += p[i] * x[j]
            x = poly_mul(Field, x, inp_poly[0])
        return poly_strip(Field, out)


class ParallelSum(Gadget):
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

    # Operational parameters
    subcircuit = None
    count = None

    ARITY = None  # Set by constructor
    DEGREE = None  # Set by constructor

    def __init__(self, subcircuit: Gadget, count: int):
        self.subcircuit = subcircuit
        self.count = count
        self.ARITY = subcircuit.ARITY * count
        self.DEGREE = subcircuit.DEGREE

    def eval(self, Field, inp):
        self.check_gadget_eval(inp)
        out = Field(0)
        for i in range(self.count):
            start_index = i * self.subcircuit.ARITY
            end_index = (i + 1) * self.subcircuit.ARITY
            out += self.subcircuit.eval(Field, inp[start_index:end_index])
        return out

    def eval_poly(self, Field, inp_poly):
        self.check_gadget_eval_poly(inp_poly)
        output_poly_length = self.DEGREE * (len(inp_poly[0]) - 1) + 1
        out_sum = [Field(0) for _ in range(output_poly_length)]
        for i in range(self.count):
            start_index = i * self.subcircuit.ARITY
            end_index = (i + 1) * self.subcircuit.ARITY
            out_current = self.subcircuit.eval_poly(
                Field,
                inp_poly[start_index:end_index]
            )
            for j in range(output_poly_length):
                out_sum[j] += out_current[j]
        return poly_strip(Field, out_sum)


##
# TYPES
#

class Count(Valid):
    # Associated types
    Measurement = int  # `range(2)`
    AggResult = int
    Field = field.Field64

    # Associated parameters
    GADGETS = [Mul()]
    GADGET_CALLS = [1]
    MEAS_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1

    def eval(self, meas, joint_rand, _num_shares):
        self.check_valid_eval(meas, joint_rand)
        return self.GADGETS[0].eval(self.Field, [meas[0], meas[0]]) \
            - meas[0]

    def encode(self, measurement):
        if measurement not in [0, 1]:
            raise ValueError('measurement out of range')
        return [self.Field(measurement)]

    def truncate(self, meas):
        if len(meas) != 1:
            raise ValueError('incorrect encoded measurement length')
        return meas

    def decode(self, output, _num_measurements):
        return output[0].as_unsigned()


class Sum(Valid):
    # Associated types
    Measurement = int  # `range(2**self.bits)`
    AggResult = int
    Field = field.Field128

    # Associated parameters
    GADGETS = [Range2()]
    GADGET_CALLS = None  # Set by Sum.with_bits()
    MEAS_LEN = None  # Set by Sum.with_bits()
    JOINT_RAND_LEN = 1
    OUTPUT_LEN = 1

    def __init__(self, bits):
        """
        Instantiate an instace of the `Sum` circuit for measurements in range `[0,
        2^bits)`.
        """

        if 2 ** bits >= self.Field.MODULUS:
            raise ValueError('bit size exceeds field modulus')

        self.GADGET_CALLS = [bits]
        self.MEAS_LEN = bits

    def eval(self, meas, joint_rand, _num_shares):
        self.check_valid_eval(meas, joint_rand)
        out = self.Field(0)
        r = joint_rand[0]
        for b in meas:
            out += r * self.GADGETS[0].eval(self.Field, [b])
            r *= joint_rand[0]
        return out

    def encode(self, measurement):
        if 0 > measurement or measurement >= 2 ** self.MEAS_LEN:
            raise ValueError('measurement out of range')

        return self.Field.encode_into_bit_vector(measurement,
                                                 self.MEAS_LEN)

    def truncate(self, meas):
        return [self.Field.decode_from_bit_vector(meas)]

    def decode(self, output, _num_measurements):
        return output[0].as_unsigned()

    def test_vec_set_type_param(self, test_vec):
        test_vec['bits'] = int(self.MEAS_LEN)
        return ['bits']


class Histogram(Valid):
    # Operational parameters
    length = None  # Set by 'Histogram.with_params()`
    chunk_length = None  # Set by 'Histogram.with_params()`

    # Associated types
    Measurement = int  # `range(length)`
    AggResult = list[int]
    Field = field.Field128

    # Associated parameters
    GADGETS = None  # Set by `Histogram.with_params()`
    GADGET_CALLS = None  # Set by `Histogram.with_params()`
    MEAS_LEN = None  # Set by `Histogram.with_params()`
    JOINT_RAND_LEN = 2
    OUTPUT_LEN = None  # Set by `Histogram.with_params()`

    def __init__(self, length, chunk_length):
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
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [(length + chunk_length - 1) // chunk_length]
        self.MEAS_LEN = self.length
        self.OUTPUT_LEN = self.length

    def eval(self, meas, joint_rand, num_shares):
        self.check_valid_eval(meas, joint_rand)

        # Check that each bucket is one or zero.
        range_check = self.Field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.Field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.Field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            range_check += self.GADGETS[0].eval(self.Field, inputs)

        # Check that the buckets sum to 1.
        sum_check = -shares_inv
        for b in meas:
            sum_check += b

        out = joint_rand[1] * range_check + \
            joint_rand[1] ** 2 * sum_check
        return out

    def encode(self, measurement):
        encoded = [self.Field(0)] * self.length
        encoded[measurement] = self.Field(1)
        return encoded

    def truncate(self, meas):
        return meas

    def decode(self, output, _num_measurements):
        return [bucket_count.as_unsigned() for bucket_count in output]

    def test_vec_set_type_param(self, test_vec):
        test_vec['length'] = int(self.length)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'chunk_length']


class MultiHotHistogram(Valid):
    r"""
    A validity circuit that checks each Client's measurement is a bit vector
    with at most `max_count` number of 1s.

    In order to check the Client measurement `meas` has at most `max_count` 1s,
    we ask the Client to send an additional `bits_for_count` bits that
    encode the number of 1s in the measurement, with an offset. Specifically:
    - Let `bits_for_count = max_count.bit_length()`, i.e. the number of bits
      to represent `max_count`.
    - Let `offset = 2**bits_for_count - 1 - max_count`.
    - Client will encode `count = offset + \sum_i meas_i` in
      `bits_for_count` bits.
    - We can naturally bound `count` as the following:
      `0 <= count <= 2**bits_for_count - 1`, and therefore:
      `-offset <= \sum_i meas_i <= max_count`.
    - Since we also verify each `meas_i` is a bit, we can lower bound the
      summation by 0. Therefore, we will be able to verify
      `0 <= \sum_i meas_i <= max_count`.
    """
    # Operational parameters
    length = None  # Set by the constructor
    max_count = None  # Set by constructor
    chunk_length = None  # Set by constructor

    # Associated types
    Measurement = list[int]  # A vector of bits.
    AggResult = list[int]  # A vector of counts as unsigned integers.
    Field = field.Field128

    # Associated parameters
    GADGETS = None  # Set by constructor
    GADGET_CALLS = None  # Set by constructor
    MEAS_LEN = None  # Set by constructor
    JOINT_RAND_LEN = 2
    OUTPUT_LEN = None  # Set by constructor

    def __init__(self, length, max_count, chunk_length):
        """
        Instantiate an instance of the `MultiHotHistogram` circuit with the
        given length, max_count, and chunk_length.
        """
        if length <= 0:
            raise ValueError('invalid length')
        if max_count <= 0 or max_count > length:
            raise ValueError('invalid max_count')
        if chunk_length <= 0:
            raise ValueError('invalid chunk_length')

        # Compute the number of bits to represent `max_count`.
        self.bits_for_count = max_count.bit_length()
        self.offset = self.Field((1 << self.bits_for_count) - 1 - max_count)
        # Sanity check `offset + length` doesn't overflow field size,
        # because in validity circuit, we will compute `offset + \sum_i meas_i`.
        if self.Field.MODULUS - self.offset.as_unsigned() <= length:
            raise ValueError('length and max_count are too large '
                             'for the current field size')

        self.length = length
        self.max_count = max_count
        self.chunk_length = chunk_length
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        # The number of bit entries are `length + bits_for_count`,
        # so the number of gadget calls is equal to
        # `ceil((length + bits_for_count) / chunk_length)`.
        self.GADGET_CALLS = [
            (length + self.bits_for_count + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = self.length + self.bits_for_count
        self.OUTPUT_LEN = self.length

    def eval(self, meas, joint_rand, num_shares):
        self.check_valid_eval(meas, joint_rand)

        # Check that each bucket is one or zero.
        range_check = self.Field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.Field(num_shares).inv()
        for i in range(self.GADGET_CALLS[0]):
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.Field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            range_check += self.GADGETS[0].eval(self.Field, inputs)

        # Check that `offset` plus the sum of the buckets is equal to the
        # value claimed by the Client.
        count_check = self.offset * shares_inv
        for i in range(self.length):
            count_check += meas[i]
        count_check -= self.Field.decode_from_bit_vector(meas[self.length:])

        out = joint_rand[1] * range_check + \
            joint_rand[1] ** 2 * count_check
        return out

    def encode(self, measurement):
        if len(measurement) != self.length:
            raise ValueError('invalid Client measurement length')

        encoded = list(map(self.Field, measurement))
        # Encode the result of `offset + \sum_i measurement_i` into
        # `bits_for_count` bits.
        count = self.offset + sum(encoded, self.Field(0))
        encoded += self.Field.encode_into_bit_vector(
            count.as_unsigned(), self.bits_for_count
        )
        return encoded

    def truncate(self, meas):
        return meas[:self.length]

    def decode(self, output, _num_measurements):
        return [bucket_count.as_unsigned() for bucket_count in output]

    def test_vec_set_type_param(self, test_vec):
        test_vec['length'] = int(self.length)
        test_vec['max_count'] = int(self.max_count)
        test_vec['chunk_length'] = int(self.chunk_length)
        return ['length', 'max_count', 'chunk_length']


class SumVec(Valid):
    # Operational parameters
    length = None  # Set by constructor
    bits = None  # Set by constructor
    chunk_length = None  # Set by constructor

    # Associated types
    Measurement = list[int]
    AggResult = list[int]
    Field = field.Field128

    # Associated parameters
    GADGETS = None  # Set by constructor
    GADGET_CALLS = None  # Set by constructor
    MEAS_LEN = None  # Set by constructor
    JOINT_RAND_LEN = 1
    OUTPUT_LEN = None  # Set by constructor

    def __init__(self, length, bits, chunk_length):
        """
        Instantiate the `SumVec` circuit for measurements with `length`
        elements, each in the range `[0, 2^bits)`.
        """

        if 2 ** bits >= Sum.Field.MODULUS:
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
        self.GADGETS = [ParallelSum(Mul(), chunk_length)]
        self.GADGET_CALLS = [
            (length * bits + chunk_length - 1) // chunk_length
        ]
        self.MEAS_LEN = length * bits
        self.OUTPUT_LEN = length

    def eval(self, meas, joint_rand, num_shares):
        self.check_valid_eval(meas, joint_rand)

        out = self.Field(0)
        r = joint_rand[0]
        r_power = r
        shares_inv = self.Field(num_shares).inv()

        for i in range(self.GADGET_CALLS[0]):
            inputs = [None] * (2 * self.chunk_length)
            for j in range(self.chunk_length):
                index = i * self.chunk_length + j
                if index < len(meas):
                    meas_elem = meas[index]
                else:
                    meas_elem = self.Field(0)

                inputs[j * 2] = r_power * meas_elem
                inputs[j * 2 + 1] = meas_elem - shares_inv

                r_power *= r

            out += self.GADGETS[0].eval(self.Field, inputs)

        return out

    def encode(self, measurement):
        if len(measurement) != self.length:
            raise ValueError('incorrect measurement length')

        encoded = []
        for val in measurement:
            if val not in range(2**self.bits):
                raise ValueError('entry of measurement vector is out of range')

            encoded += self.Field.encode_into_bit_vector(val, self.bits)
        return encoded

    def truncate(self, meas):
        truncated = []
        for i in range(self.length):
            truncated.append(self.Field.decode_from_bit_vector(
                meas[i * self.bits: (i + 1) * self.bits]
            ))
        return truncated

    def decode(self, output, _num_measurements):
        return [x.as_unsigned() for x in output]

    def test_vec_set_type_param(self, test_vec):
        test_vec['length'] = self.length
        test_vec['bits'] = self.bits
        test_vec['chunk_length'] = self.chunk_length
        return ['length', 'bits', 'chunk_length']
