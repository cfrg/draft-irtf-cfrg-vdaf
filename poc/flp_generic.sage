# Fully linear proof (FLP) systems.

from copy import deepcopy
from sagelib.common import ERR_ABORT, ERR_VERIFY, Bool, Error, Unsigned, \
                           Vec, next_power_of_2
from sagelib.field import poly_eval, poly_interp, poly_mul
from sagelib.flp import Flp, run_flp
import sagelib.field as field


# A validity circuit gadget.
class Gadget:
    # Length of the input to the gadget.
    ARITY: Unsigned

    # Arithmetic degree of the circuit.
    DEGREE: Unsigned

    # Evaluate the gadget on a sequence of field elements.
    @classmethod
    def eval(Gadget, Field, inp):
        raise Error("eval() not implemented")

    # Evaluate the gadget on a sequence of polynomials over a fieldo.
    @classmethod
    def eval_poly(Gadget, Field, inp_poly):
        raise Error("eval_poly() not implemented")

# A validity circuit.
class Valid:
    # Generic parameters overwritten by a concrete validity circuit.
    Field = field.Field
    Measurement = None

    # Length of the input to the validity circuit.
    INPUT_LEN: Unsigned

    # Length of the random input of the validity circuit.
    RAND_LEN: Unsigned

    # Length of the aggregateable output for this type.
    OUTPUT_LEN: Unsigned

    # The sequence of gadgets for this validity circuit.
    GADGETS: Vec[Gadget]

    # The number of times each gadget is called. This must have the same length
    # as `GADGETS`.
    GADGET_CALLS: Vec[Unsigned]

    # Length of the prover randomness.
    @classmethod
    def prove_rand_len(Valid):
        return sum(map(lambda g: g.ARITY, Valid.GADGETS))

    # Length of the query randomness.
    @classmethod
    def query_rand_len(Valid):
        return len(Valid.GADGETS)

    # Length of the proof.
    @classmethod
    def proof_len(Valid):
        length = 0
        for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
            P = next_power_of_2(1 + g_calls)
            length += g.ARITY + g.DEGREE * (P - 1) + 1
        return length

    # Length of the verifier message.
    @classmethod
    def verifier_len(Valid):
        length = 1
        for g in Valid.GADGETS:
            length += g.ARITY + 1
        return length

    # Encode a measurement as an input.
    @classmethod
    def encode(Valid, measurement: Measurement) -> Vec[Field]:
        raise Error("encode() not implemented")

    # Truncate an input to the length of an aggregatable output.
    @classmethod
    def truncate(Valid, inp: Vec[Field]) -> Vec[Field]:
        raise Error("truncate() not implemented")

    # Evaluate the circuit on the provided input and joint randomness.
    def eval(self,
             inp: Vec[Field],
             joint_rand: Vec[Field],
             num_shares: Unsigned):
        raise Error("eval() not implemented")


class ProveGadget:

    def __init__(self, Gadget, Field, wire_seeds, num_calls):
        self.inner = Gadget
        self.ARITY = Gadget.ARITY
        self.DEGREE = Gadget.DEGREE
        self.wire = []
        P = next_power_of_2(1 + num_calls)
        for j in range(Gadget.ARITY):
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
        wrapped = ProveGadget(g, Valid.Field, wire_seeds, g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(prove_rand) == 0
    valid = Valid()
    valid.GADGETS = wrapped_gadgets
    valid.GADGET_CALLS = Valid.GADGET_CALLS
    return valid


class QueryGadget:

    def __init__(self, Gadget, Field, wire_seeds, gadget_poly, num_calls):
        self.inner = Gadget
        self.ARITY = Gadget.ARITY
        self.DEGREE = Gadget.DEGREE
        self.wire = []
        self.gadget_poly = gadget_poly
        P = next_power_of_2(1 + num_calls)
        for j in range(Gadget.ARITY):
            self.wire.append(Field.zeros(P))
            self.wire[j][0] = wire_seeds[j]
        self.alpha = Field.gen() ^ (Field.GEN_ORDER / P)
        self.k = 0

    def eval(self, Field, inp):
        self.k += 1
        for j in range(len(inp)):
            self.wire[j][self.k] = inp[j]
        return poly_eval(Field, self.gadget_poly, self.alpha^self.k)


def query_wrapped(Valid, proof):
    if len(proof) != Valid.proof_len():
        raise ERR_INPUT

    wrapped_gadgets = []
    for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        gadget_poly_len = g.ARITY + g.DEGREE * (P - 1) + 1
        wire_seeds, proof = proof[:g.ARITY], proof[g.ARITY:]
        gadget_poly, proof = proof[:gadget_poly_len], proof[gadget_poly_len:]
        wrapped = QueryGadget(g,
                              Valid.Field,
                              wire_seeds,
                              gadget_poly,
                              g_calls)
        wrapped_gadgets.append(wrapped)
    assert len(proof) == 0
    valid = Valid()
    valid.GADGETS = wrapped_gadgets
    valid.GADGET_CALLS = Valid.GADGET_CALLS
    return valid


# An FLP constructed from a validity circuit.
class FlpGeneric(Flp):
    # Instantiate thie generic FLP the given validity circuit.
    @classmethod
    def with_valid(FlpGeneric, Valid):
        new_cls = deepcopy(FlpGeneric)
        new_cls.Valid = Valid
        new_cls.Field = Valid.Field
        new_cls.Measurement = Valid.Measurement
        new_cls.JOINT_RAND_LEN = Valid.RAND_LEN
        new_cls.PROVE_RAND_LEN = Valid.prove_rand_len()
        new_cls.QUERY_RAND_LEN = Valid.query_rand_len()
        new_cls.PROOF_LEN = Valid.proof_len()
        return new_cls

    @classmethod
    def prove(FlpGeneric, inp, prove_rand, joint_rand):
        # Evaluate the validity circuit, recording the values of the input wires
        # for each call to each gadget.
        valid = prove_wrapped(FlpGeneric.Valid, prove_rand)
        valid.eval(inp, joint_rand, 1)

        # Construct the proof.
        proof = []
        for (g, g_calls) in zip(valid.GADGETS, valid.GADGET_CALLS):
            P = len(g.wire[0])

            # Compute the wire polynomials for this gadget.
            alpha = FlpGeneric.Field.gen()^(FlpGeneric.Field.GEN_ORDER / P)
            wire_inp = [alpha^k for k in range(P)]
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
        for (g, g_calls, t) in zip(valid.GADGETS,
                                   valid.GADGET_CALLS,
                                   query_rand):
            P = len(g.wire[0])

            # Check if `t` is a degenerate point and abort if so.
            #
            # A degenerate point is one that was used as an input for
            # constructing the gadget polynomial. Using such a point would laak
            # an output of the gadget to a distributed verifier.
            if t^P == FlpGeneric.Field(1):
                raise ERR_ABORT

            # Compute the well-formedness test for the gadget polynomial.
            x = []
            wire_inp = [g.alpha^k for k in range(P)]
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

        # Check the toutput of the vaidity circuit.
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

    @classmethod
    def eval(Gadget, Field, inp):
        check_gadget_eval(Gadget, inp)
        return inp[0] * inp[1]

    @classmethod
    def eval_poly(Gadget, Field, inp_poly):
        check_gadget_eval_poly(Gadget, inp_poly)
        return poly_mul(Field, inp_poly[0], inp_poly[1])


##
# TYPES
#

def check_valid_eval(Valid, inp, joint_rand):
    if len(inp) != Valid.INPUT_LEN:
        raise ERR_INPUT
    if len(joint_rand) != Valid.RAND_LEN:
        raise ERR_INPUT

class Count(Valid):
    Field = field.Field64
    Measurement = Unsigned

    GADGETS = [Mul]
    GADGET_CALLS = [2]
    INPUT_LEN = 1
    RAND_LEN = 1
    OUTPUT_LEN = 1

    def eval(self, inp, joint_rand, _num_shares):
        check_valid_eval(Count, inp, joint_rand)
        Mul = Count.GADGETS[0]
        return Mul.eval(self.Field, [inp[0], inp[0]]) - inp[0]

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


##
# TESTS
#


# Test for equivalence of `Gadget.eval()` and `Gadget.eval_poly()`.
def test_gadget(Gadget, Field, test_length):
    inp_poly = []
    inp = []
    eval_at = Field.rand_vec(1)[0]
    for _ in range(Gadget.ARITY):
        inp_poly.append(Field.rand_vec(test_length))
        inp.append(poly_eval(Field, inp_poly[-1], eval_at))
    out_poly = Gadget.eval_poly(Field, inp_poly)

    want = Gadget.eval(Field, inp)
    got = poly_eval(Field, out_poly, eval_at)
    assert got == want


def test_flp_generic(cls, test_cases):
    for (g, g_calls) in zip(cls.Valid.GADGETS, cls.Valid.GADGET_CALLS):
        test_gadget(g, cls.Field, next_power_of_2(g_calls + 1))

    for (i, (inp, expected_decision)) in enumerate(test_cases):
        # Evaluate validity circuit.
        joint_rand = cls.Field.rand_vec(cls.JOINT_RAND_LEN)
        v = cls.Valid().eval(inp, joint_rand, 1)
        if (v == cls.Field(0)) != expected_decision:
            print("test {} failed: validity circuit returned {}".format(i, v))

        # Run the FLP.
        decision = run_flp(cls, inp, 1)
        if decision != expected_decision:
            print("test {} failed: proof evaluation resulted in {}; want {}".format(
                i, decision, expected_decision))

if __name__ == "__main__":
    cls = FlpGeneric.with_valid(Count)
    test_flp_generic(cls, [
        (cls.encode(0), True),
        (cls.encode(1), True),
        ([field.Field64(1337)], False),
    ])
