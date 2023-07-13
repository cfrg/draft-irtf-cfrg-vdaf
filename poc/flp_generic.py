"""A generic FLP based on {{BBCGGI19}}, Theorem 4.3."""

import field
from common import ERR_ABORT, ERR_INPUT, Unsigned, Vec, next_power_of_2
from field import poly_eval, poly_interp, poly_mul, poly_strip
from flp import Flp, run_flp


class Gadget:
    """A validity circuit gadget."""

    # Length of the input to the gadget.
    ARITY: Unsigned

    # Arithmetic degree of the circuit.
    DEGREE: Unsigned

    def eval(self, Field, inp):
        """Evaluate the gadget on a sequence of field elements."""
        raise NotImplementedError()

    def eval_poly(self, Field, inp_poly):
        """Evaluate the gadget on a sequence of polynomials over a field."""
        raise NotImplementedError()


class Valid:
    """
    A validity circuit.
    """

    # Generic parameters overwritten by a concrete validity circuit. `Field`
    # MUST be FFT-friendly.
    Measurement = None
    AggResult = None
    Field: field.FftField = None

    # Length of the input to the validity circuit.
    INPUT_LEN: Unsigned

    # Length of the random input of the validity circuit.
    JOINT_RAND_LEN: Unsigned

    # Length of the aggregateable output for this type.
    OUTPUT_LEN: Unsigned

    # The sequence of gadgets for this validity circuit.
    GADGETS: Vec[Gadget]

    # The number of times each gadget is called. This must have the same length
    # as `GADGETS`.
    GADGET_CALLS: Vec[Unsigned]

    @classmethod
    def prove_rand_len(Valid):
        """Length of the prover randomness."""
        return sum(map(lambda g: g.ARITY, Valid.GADGETS))

    @classmethod
    def query_rand_len(Valid):
        """Length of the query randomness."""
        return len(Valid.GADGETS)

    @classmethod
    def proof_len(Valid):
        """Length of the proof."""
        length = 0
        for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
            P = next_power_of_2(1 + g_calls)
            length += g.ARITY + g.DEGREE * (P - 1) + 1
        return length

    @classmethod
    def verifier_len(Valid):
        """Length of the verifier message."""
        length = 1
        for g in Valid.GADGETS:
            length += g.ARITY + 1
        return length

    @classmethod
    def encode(Valid, measurement: Measurement) -> Vec[Field]:
        """Encode a measurement as an input."""
        raise NotImplementedError()

    @classmethod
    def truncate(Valid, inp: Vec[Field]) -> Vec[Field]:
        """Truncate an input to the length of an aggregatable output."""
        raise NotImplementedError()

    @classmethod
    def decode(Valid, output: Vec[Field],
               num_measurements: Unsigned) -> AggResult:
        """Decode an aggregate result."""
        raise NotImplementedError()

    def eval(self,
             inp: Vec[Field],
             joint_rand: Vec[Field],
             num_shares: Unsigned):
        """Evaluate the circuit on the provided input and joint randomness."""
        raise NotImplementedError()

    @classmethod
    def test_vec_set_type_param(Valid, test_vec):
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Return the key that was set or `None` if `test_vec` was not
        modified.
        """
        return None


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


def prove_wrapped(Valid, prove_rand):
    if len(prove_rand) != Valid.prove_rand_len():
        raise ERR_INPUT

    wrapped_gadgets = []
    for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
        wire_seeds, prove_rand = prove_rand[:g.ARITY], prove_rand[g.ARITY:]
        wrapped = ProveGadget(Valid.Field, wire_seeds, g, g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(prove_rand) == 0
    valid = Valid()
    valid.GADGETS = wrapped_gadgets
    return valid


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


def query_wrapped(Valid, proof):
    if len(proof) != Valid.proof_len():
        raise ERR_INPUT

    wrapped_gadgets = []
    for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        gadget_poly_len = g.DEGREE * (P - 1) + 1
        wire_seeds, proof = proof[:g.ARITY], proof[g.ARITY:]
        gadget_poly, proof = proof[:gadget_poly_len], proof[gadget_poly_len:]
        wrapped = QueryGadget(Valid.Field,
                              wire_seeds,
                              gadget_poly,
                              g,
                              g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(proof) == 0
    valid = Valid()
    valid.GADGETS = wrapped_gadgets
    return valid


class FlpGeneric(Flp):
    """An FLP constructed from a validity circuit."""

    @classmethod
    def with_valid(FlpGeneric, TheValid):
        """Instantiate thie generic FLP the given validity circuit."""

        class NewFlpGeneric(FlpGeneric):
            Valid = TheValid
            Measurement = TheValid.Measurement
            AggResult = TheValid.AggResult
            Field = TheValid.Field
            PROVE_RAND_LEN = TheValid.prove_rand_len()
            QUERY_RAND_LEN = TheValid.query_rand_len()
            JOINT_RAND_LEN = TheValid.JOINT_RAND_LEN
            INPUT_LEN = TheValid.INPUT_LEN
            OUTPUT_LEN = TheValid.OUTPUT_LEN
            PROOF_LEN = TheValid.proof_len()
            VERIFIER_LEN = TheValid.verifier_len()
        return NewFlpGeneric

    @classmethod
    def prove(FlpGeneric, inp, prove_rand, joint_rand):
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget.
        valid = prove_wrapped(FlpGeneric.Valid, prove_rand)
        valid.eval(inp, joint_rand, 1)

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
            assert FlpGeneric.Field.GEN_ORDER % P == 0
            alpha = FlpGeneric.Field.gen() ** (FlpGeneric.Field.GEN_ORDER // P)
            wire_inp = [alpha ** k for k in range(P)]
            wire_polys = []
            for j in range(g.ARITY):
                wire_poly = poly_interp(FlpGeneric.Field, wire_inp, g.wire[j])
                wire_polys.append(wire_poly)

            # Compute the gadget polynomial.
            gadget_poly = g.eval_poly(FlpGeneric.Field, wire_polys)

            for j in range(g.ARITY):
                proof.append(g.wire[j][0])
            proof += gadget_poly

        return proof

    @classmethod
    def query(FlpGeneric, inp, proof, query_rand, joint_rand, num_shares):
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget. The gadget output is computed by
        # evaluating the gadget polynomial.
        valid = query_wrapped(FlpGeneric.Valid, proof)
        v = valid.eval(inp, joint_rand, num_shares)

        if len(query_rand) != FlpGeneric.Valid.query_rand_len():
            raise ERR_INPUT

        # Construct the verifier message.
        verifier = [v]
        for (g, t) in zip(valid.GADGETS, query_rand):
            P = len(g.wire[0])

            # Check if `t` is a degenerate point and abort if so.
            #
            # A degenerate point is one that was used as an input for
            # constructing the gadget polynomial. Using such a point would leak
            # an output of the gadget to the verifier.
            if t ** P == FlpGeneric.Field(1):
                raise ERR_ABORT

            # Compute the well-formedness test for the gadget polynomial.
            x = []
            wire_inp = [g.alpha ** k for k in range(P)]
            for j in range(g.ARITY):
                wire_poly = poly_interp(FlpGeneric.Field, wire_inp, g.wire[j])
                x.append(poly_eval(FlpGeneric.Field, wire_poly, t))

            y = poly_eval(FlpGeneric.Field, g.gadget_poly, t)

            verifier += x
            verifier.append(y)

        return verifier

    @classmethod
    def decide(FlpGeneric, verifier):
        if len(verifier) != FlpGeneric.Valid.verifier_len():
            raise ERR_INPUT

        # Check the output of the validity circuit.
        v, verifier = verifier[0], verifier[1:]
        if v != FlpGeneric.Field(0):
            return False

        # Check for well-formedness of each gadget polynomial.
        for g in FlpGeneric.Valid.GADGETS:
            x, verifier = verifier[:g.ARITY], verifier[g.ARITY:]
            y, verifier = verifier[0], verifier[1:]
            z = g.eval(FlpGeneric.Field, x)
            if z != y:
                return False

        assert len(verifier) == 0
        return True

    @classmethod
    def encode(FlpGeneric, measurement):
        return FlpGeneric.Valid.encode(measurement)

    @classmethod
    def truncate(FlpGeneric, inp):
        return FlpGeneric.Valid.truncate(inp)

    @classmethod
    def decode(FlpGeneric, output, num_measurements):
        return FlpGeneric.Valid.decode(output, num_measurements)

    @classmethod
    def test_vec_set_type_param(FlpGeneric, test_vec):
        return FlpGeneric.Valid.test_vec_set_type_param(test_vec)


##
# GADGETS
#

def check_gadget_eval(Gadget, inp):
    if len(inp) != Gadget.ARITY:
        raise ERR_INPUT


def check_gadget_eval_poly(Gadget, inp_poly):
    if len(inp_poly) != Gadget.ARITY:
        raise ERR_INPUT
    for j in range(len(inp_poly)):
        if len(inp_poly[j]) != len(inp_poly[0]):
            raise ERR_INPUT


class Mul(Gadget):
    ARITY = 2
    DEGREE = 2

    def eval(self, Field, inp):
        check_gadget_eval(self, inp)
        return inp[0] * inp[1]

    def eval_poly(self, Field, inp_poly):
        check_gadget_eval_poly(self, inp_poly)
        return poly_mul(Field, inp_poly[0], inp_poly[1])


class PolyEval(Gadget):
    # Operational parameters
    p = None

    ARITY = 1
    DEGREE = None  # Set by constructor

    def eval(self, Field, inp):
        check_gadget_eval(PolyEval, inp)
        p = list(map(lambda coeff: Field(coeff), self.p))
        return poly_eval(Field, p, inp[0])

    def eval_poly(self, Field, inp_poly):
        check_gadget_eval_poly(PolyEval, inp_poly)
        p = list(map(lambda coeff: Field(coeff), self.p))
        out = [Field(0) for _ in range(self.DEGREE * len(inp_poly[0]))]
        out[0] = p[0]
        x = inp_poly[0]
        for i in range(1, len(p)):
            for j in range(len(x)):
                out[j] += p[i] * x[j]
            x = poly_mul(Field, x, inp_poly[0])
        return poly_strip(Field, out)

    def __init__(self, p: Vec[int]):
        """
        Instantiate this gadget with the given polynomial. Note that this
        determines the field that may be used with this gadget.
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


##
# TYPES
#

def check_valid_eval(Valid, inp, joint_rand):
    if len(inp) != Valid.INPUT_LEN:
        raise ERR_INPUT
    if len(joint_rand) != Valid.JOINT_RAND_LEN:
        raise ERR_INPUT


class Count(Valid):
    # Associated types
    Measurement = Unsigned
    AggResult = Unsigned
    Field = field.Field64

    # Associated parameters
    GADGETS = [Mul()]
    GADGET_CALLS = [1]
    INPUT_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1

    def eval(self, inp, joint_rand, _num_shares):
        check_valid_eval(self, inp, joint_rand)
        return self.GADGETS[0].eval(self.Field, [inp[0], inp[0]]) - inp[0]

    @classmethod
    def encode(Count, measurement):
        if measurement not in [0, 1]:
            raise ERR_INPUT
        return [Count.Field(measurement)]

    @classmethod
    def truncate(Count, inp):
        if len(inp) != 1:
            raise ERR_INPUT
        return inp

    @classmethod
    def decode(Count, output, _num_measurements):
        return output[0].as_unsigned()


class Sum(Valid):
    # Associated types
    Measurement = Unsigned
    AggResult = Unsigned
    Field = field.Field128

    # Associated parametrs
    GADGETS = [PolyEval([0, -1, 1])]
    GADGET_CALLS = None  # Set by Sum.with_bits()
    INPUT_LEN = None    # Set by Sum.with_bits()
    JOINT_RAND_LEN = 1
    OUTPUT_LEN = 1

    def eval(self, inp, joint_rand, _num_shares):
        check_valid_eval(self, inp, joint_rand)
        out = self.Field(0)
        r = joint_rand[0]
        for b in inp:
            out += r * self.GADGETS[0].eval(self.Field, [b])
            r *= joint_rand[0]
        return out

    @classmethod
    def encode(Sum, measurement):
        if 0 > measurement or measurement >= 2 ** Sum.INPUT_LEN:
            raise ERR_INPUT

        encoded = []
        for l in range(Sum.INPUT_LEN):
            encoded.append(Sum.Field((measurement >> l) & 1))
        return encoded

    @classmethod
    def truncate(Sum, inp):
        decoded = Sum.Field(0)
        for (l, b) in enumerate(inp):
            w = Sum.Field(1 << l)
            decoded += w * b
        return [decoded]

    @classmethod
    def decode(Sum, output, _num_measurements):
        return output[0].as_unsigned()

    @classmethod
    def with_bits(Sum, bits):
        """
        Instantiate an instace of the `Sum` circuit for inputs in range `[0,
        2^bits)`.
        """

        if 2 ** bits >= Sum.Field.MODULUS:
            raise ValueError('bit size exceeds field modulus')

        class SumWithBits(Sum):
            GADGET_CALLS = [bits]
            INPUT_LEN = bits
        return SumWithBits

    @classmethod
    def test_vec_set_type_param(cls, test_vec):
        test_vec['bits'] = int(cls.INPUT_LEN)
        return 'bits'


class Histogram(Valid):
    # Operational parameters
    length = None  # Set by 'Histogram.with_length()`

    # Associated types
    Measurement = Unsigned
    AggResult = Vec[Unsigned]
    Field = field.Field128

    # Associated parametrs
    GADGETS = [PolyEval([0, -1, 1])]
    GADGET_CALLS = None  # Set by `Histogram.with_length()`
    INPUT_LEN = None  # Set by `Histogram.with_length()`
    JOINT_RAND_LEN = 2
    OUTPUT_LEN = None  # Set by `Histogram.with_length()`

    def eval(self, inp, joint_rand, num_shares):
        check_valid_eval(self, inp, joint_rand)

        # Check that each bucket is one or zero.
        range_check = self.Field(0)
        r = joint_rand[0]
        for b in inp:
            range_check += r * self.GADGETS[0].eval(self.Field, [b])
            r *= joint_rand[0]

        # Check that the buckets sum to 1.
        sum_check = -self.Field(1) * self.Field(num_shares).inv()
        for b in inp:
            sum_check += b

        out = joint_rand[1] * range_check + \
            joint_rand[1] ** 2 * sum_check
        return out

    @classmethod
    def encode(Histogram, measurement):
        encoded = [Histogram.Field(0)] * Histogram.length
        encoded[measurement] = Histogram.Field(1)
        return encoded

    @classmethod
    def truncate(Histogram, inp):
        return inp

    @classmethod
    def decode(Histogram, output, _num_measurements):
        return [bucket_count.as_unsigned() for bucket_count in output]

    @classmethod
    def with_length(Histogram, the_length):
        """
        Instantiate an instace of the `Histogram` circuit with the given
        length.
        """

        class HistogramWithLength(Histogram):
            length = the_length
            GADGET_CALLS = [the_length]
            INPUT_LEN = the_length
            OUTPUT_LEN = the_length
        return HistogramWithLength

    @classmethod
    def test_vec_set_type_param(cls, test_vec):
        test_vec['length'] = int(cls.length)
        return 'length'


##
# TESTS
#

class TestMultiGadget(Valid):
    # Associated types
    Field = field.Field64
    Measurement = Unsigned

    # Associated parameters
    GADGETS = [Mul(), Mul()]
    GADGET_CALLS = [1, 2]
    INPUT_LEN = 1
    JOINT_RAND_LEN = 0
    OUTPUT_LEN = 1

    def eval(self, inp, joint_rand, _num_shares):
        check_valid_eval(self, inp, joint_rand)
        # Not a very useful circuit, obviously. We just want to do something.
        x = self.GADGETS[0].eval(self.Field, [inp[0], inp[0]])
        y = self.GADGETS[1].eval(self.Field, [inp[0], x])
        z = self.GADGETS[1].eval(self.Field, [x, y])
        return z

    @classmethod
    def encode(Count, measurement):
        if measurement not in [0, 1]:
            raise ERR_INPUT
        return [Count.Field(measurement)]

    @classmethod
    def truncate(Count, inp):
        if len(inp) != 1:
            raise ERR_INPUT
        return inp


def test_gadget(g, Field, test_length):
    """
    Test for equivalence of `Gadget.eval()` and `Gadget.eval_poly()`.
    """
    inp_poly = []
    inp = []
    eval_at = Field.rand_vec(1)[0]
    for _ in range(g.ARITY):
        inp_poly.append(Field.rand_vec(test_length))
        inp.append(poly_eval(Field, inp_poly[-1], eval_at))
    out_poly = g.eval_poly(Field, inp_poly)

    want = g.eval(Field, inp)
    got = poly_eval(Field, out_poly, eval_at)
    assert got == want


def test_flp_generic(cls, test_cases):
    for (g, g_calls) in zip(cls.Valid.GADGETS, cls.Valid.GADGET_CALLS):
        test_gadget(g, cls.Field, next_power_of_2(g_calls + 1))

    for (i, (inp, expected_decision)) in enumerate(test_cases):
        assert len(inp) == cls.INPUT_LEN
        assert len(cls.truncate(inp)) == cls.OUTPUT_LEN

        # Evaluate validity circuit.
        joint_rand = cls.Field.rand_vec(cls.JOINT_RAND_LEN)
        v = cls.Valid().eval(inp, joint_rand, 1)
        if (v == cls.Field(0)) != expected_decision:
            print('{}: test {} failed: validity circuit returned {}'.format(
                cls.Valid.__name__, i, v))

        # Run the FLP.
        decision = run_flp(cls, inp, 2)
        if decision != expected_decision:
            print('{}: test {} failed: proof evaluation resulted in {}; want {}'.format(
                cls.Valid.__name__, i, decision, expected_decision))


class TestAverage(Sum):
    """
    Flp subclass that calculates the average of integers. The result is rounded
    down.
    """
    # Associated types
    AggResult = Unsigned

    @classmethod
    def decode(TestAverage_self, output, num_measurements):
        sum = super(TestAverage, TestAverage_self).decode(output,
                                                          num_measurements)
        return sum // num_measurements


if __name__ == '__main__':
    cls = FlpGeneric.with_valid(Count)
    test_flp_generic(cls, [
        (cls.encode(0), True),
        (cls.encode(1), True),
        ([cls.Field(1337)], False),
    ])

    test_gadget(PolyEval([0, -23, 1, 3]), field.Field128, 10)

    cls = FlpGeneric.with_valid(Sum.with_bits(10))
    test_flp_generic(cls, [
        (cls.encode(0), True),
        (cls.encode(100), True),
        (cls.encode(2 ** 10 - 1), True),
        (cls.Field.rand_vec(10), False),
    ])

    cls = FlpGeneric.with_valid(Histogram.with_length(4))
    test_flp_generic(cls, [
        (cls.encode(0), True),
        (cls.encode(1), True),
        (cls.encode(2), True),
        (cls.encode(3), True),
        ([cls.Field(0)] * 4, False),
        ([cls.Field(1)] * 4, False),
        (cls.Field.rand_vec(4), False),
    ])

    cls = FlpGeneric.with_valid(TestMultiGadget)
    test_flp_generic(cls, [
        (cls.encode(0), True),
    ])
