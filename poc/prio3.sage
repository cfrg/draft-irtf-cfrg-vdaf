# The prio3 VDAF.

from copy import deepcopy
from typing import Tuple
from sagelib.common import ERR_DECODE, ERR_INPUT, ERR_VERIFY, Bytes, \
                           Unsigned, Vec, byte, gen_rand, vec_add, vec_sub, \
                           xor, zeros
from sagelib.vdaf import Vdaf, test_vdaf
import sagelib.flp as flp
import sagelib.prg as prg


# Base class for VDAFs based on prio3.
class Prio3(Vdaf):
    # Generic parameters. These values are overwritten by concrete
    # instantiations of prio3.
    Flp = flp.Flp
    Prg = prg.Prg

    # Associated parameters. A concrete instantiation of prio3 specifies SHARES
    # as a numbeer between 2 and 254.
    ROUNDS = 1

    # Associated types
    Measurement = Flp.Measurement
    OutShare = Vec[Flp.Field]
    AggShare = Vec[Flp.Field]
    AggResult = Vec[Unsigned]
    Prep = Tuple[Vec[Flp.Field],  # output share
                 Bytes,           # k_joint_rand
                 Bytes]           # outbound message

    @classmethod
    def setup(Prio3):
        k_query_init = gen_rand(Prio3.Prg.SEED_SIZE)
        verify_param = [(j, k_query_init) for j in range(Prio3.SHARES)]
        return (None, verify_param)

    # TODO If joint rand len is 0, then don't generate blind or hint. See
    # https://github.com/cjpatton/vdaf/issues/15.
    @classmethod
    def measurement_to_input_shares(Prio3, _public_param, measurement):
        inp = Prio3.Flp.encode(measurement)
        k_joint_rand = zeros(Prio3.Prg.SEED_SIZE)

        # Generate input shares.
        leader_input_share = inp
        k_helper_input_shares = []
        k_helper_blinds = []
        k_helper_hints = []
        for j in range(Prio3.SHARES-1):
            k_blind = gen_rand(Prio3.Prg.SEED_SIZE)
            k_share = gen_rand(Prio3.Prg.SEED_SIZE)
            helper_input_share = Prio3.Prg.expand_into_vec(
                Prio3.Flp.Field,
                k_share,
                b"input share",
                Prio3.Flp.INPUT_LEN
            )
            leader_input_share = vec_sub(leader_input_share,
                                         helper_input_share)
            encoded = Prio3.Flp.Field.encode_vec(helper_input_share)
            k_hint = Prio3.Prg.derive(k_blind, byte(j+1) + encoded)
            k_joint_rand = xor(k_joint_rand, k_hint)
            k_helper_input_shares.append(k_share)
            k_helper_blinds.append(k_blind)
            k_helper_hints.append(k_hint)
        k_leader_blind = gen_rand(Prio3.Prg.SEED_SIZE)
        encoded = Prio3.Flp.Field.encode_vec(leader_input_share)
        k_leader_hint = Prio3.Prg.derive(k_leader_blind, byte(0) + encoded)
        k_joint_rand = xor(k_joint_rand, k_leader_hint)

        # Finish joint randomness hints.
        for j in range(Prio3.SHARES-1):
            k_helper_hints[j] = xor(k_helper_hints[j], k_joint_rand)
        k_leader_hint = xor(k_leader_hint, k_joint_rand)

        # Generate the proof shares.
        prove_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            gen_rand(Prio3.Prg.SEED_SIZE),
            b"prove rand",
            Prio3.Flp.PROVE_RAND_LEN
        )
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            b"joint rand",
            Prio3.Flp.JOINT_RAND_LEN
        )
        proof = Prio3.Flp.prove(inp, prove_rand, joint_rand)
        leader_proof_share = proof
        k_helper_proof_shares = []
        for j in range(Prio3.SHARES-1):
            k_share = gen_rand(Prio3.Prg.SEED_SIZE)
            k_helper_proof_shares.append(k_share)
            helper_proof_share = Prio3.Prg.expand_into_vec(
                Prio3.Flp.Field,
                k_share,
                b"proof share",
                Prio3.Flp.PROOF_LEN
            )
            leader_proof_share = vec_sub(leader_proof_share,
                                         helper_proof_share)

        input_shares = []
        input_shares.append(Prio3.encode_leader_share(
            leader_input_share,
            leader_proof_share,
            k_leader_blind,
            k_leader_hint,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append(Prio3.encode_helper_share(
                k_helper_input_shares[j],
                k_helper_proof_shares[j],
                k_helper_blinds[j],
                k_helper_hints[j],
            ))
        return input_shares

    @classmethod
    def prep_init(Prio3, verify_param, _agg_param, nonce, input_share):
        (j, k_query_init) = verify_param

        (input_share, proof_share, k_blind, k_hint) = \
            Prio3.decode_leader_share(input_share) if j == 0 else \
            Prio3.decode_helper_share(input_share)

        out_share = Prio3.Flp.truncate(input_share)

        k_query_rand = Prio3.Prg.derive(k_query_init, byte(255) + nonce)
        query_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_query_rand,
            b"query rand",
            Prio3.Flp.QUERY_RAND_LEN
        )
        encoded = Prio3.Flp.Field.encode_vec(input_share)
        k_joint_rand_share = Prio3.Prg.derive(k_blind, byte(j) + encoded)
        k_joint_rand = xor(k_hint, k_joint_rand_share)
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            b"joint rand",
            Prio3.Flp.JOINT_RAND_LEN
        )
        verifier_share = Prio3.Flp.query(input_share,
                                         proof_share,
                                         query_rand,
                                         joint_rand,
                                         Prio3.SHARES)

        prep_msg = Prio3.encode_prepare_message(verifier_share,
                                                k_joint_rand_share)
        return (out_share, k_joint_rand, prep_msg)

    @classmethod
    def prep_next(Prio3, prep, inbound):
        (out_share, k_joint_rand, prep_msg) = prep

        if inbound is None:
            return (prep, prep_msg)

        (verifier, k_joint_rand_check) = \
            Prio3.decode_prepare_message(inbound)

        if k_joint_rand_check != k_joint_rand or \
                not Prio3.Flp.decide(verifier):
            raise ERR_VERIFY

        return out_share

    @classmethod
    def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
        verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
        k_joint_rand_check = zeros(Prio3.Prg.SEED_SIZE)
        for encoded in prep_shares:
            (verifier_share, k_joint_rand_share) = \
                Prio3.decode_prepare_message(encoded)

            verifier = vec_add(verifier, verifier_share)
            k_joint_rand_check = xor(k_joint_rand_check,
                                     k_joint_rand_share)

        return Prio3.encode_prepare_message(verifier, k_joint_rand_check)

    @classmethod
    def out_shares_to_agg_share(Prio3, _agg_param, out_shares):
        agg_share = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    @classmethod
    def agg_shares_to_result(Prio3, _agg_param, agg_shares):
        agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return list(map(lambda x: x.as_unsigned(), agg))

    @classmethod
    def encode_leader_share(Prio3,
                            input_share,
                            proof_share,
                            k_blind,
                            k_hint):
        encoded = Bytes()
        encoded += Prio3.Flp.Field.encode_vec(input_share)
        encoded += Prio3.Flp.Field.encode_vec(proof_share)
        encoded += k_blind
        encoded += k_hint
        return encoded

    @classmethod
    def decode_leader_share(Prio3, encoded):
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.INPUT_LEN
        encoded_input_share, encoded = encoded[:l], encoded[l:]
        input_share = Prio3.Flp.Field.decode_vec(encoded_input_share)
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.PROOF_LEN
        encoded_proof_share, encoded = encoded[:l], encoded[l:]
        proof_share = Prio3.Flp.Field.decode_vec(encoded_proof_share)
        l = Prio3.Prg.SEED_SIZE
        k_blind, encoded = encoded[:l], encoded[l:]
        k_hint, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (input_share, proof_share, k_blind, k_hint)

    @classmethod
    def encode_helper_share(Prio3,
                            k_input_share,
                            k_proof_share,
                            k_blind,
                            k_hint):
        encoded = Bytes()
        encoded += k_input_share
        encoded += k_proof_share
        encoded += k_blind
        encoded += k_hint
        return encoded

    @classmethod
    def decode_helper_share(Prio3, encoded):
        l = Prio3.Prg.SEED_SIZE
        k_input_share, encoded = encoded[:l], encoded[l:]
        input_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                              k_input_share,
                                              b"input share",
                                              Prio3.Flp.INPUT_LEN)
        k_proof_share, encoded = encoded[:l], encoded[l:]
        proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                              k_proof_share,
                                              b"proof share",
                                              Prio3.Flp.PROOF_LEN)
        k_blind, encoded = encoded[:l], encoded[l:]
        k_hint, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (input_share, proof_share, k_blind, k_hint)

    @classmethod
    def encode_prepare_message(Prio3, verifier, k_joint_rand):
        encoded = Bytes()
        encoded += Prio3.Flp.Field.encode_vec(verifier)
        encoded += k_joint_rand
        return encoded

    @classmethod
    def decode_prepare_message(Prio3, encoded):
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.VERIFIER_LEN
        encoded_verifier, encoded = encoded[:l], encoded[l:]
        verifier = Prio3.Flp.Field.decode_vec(encoded_verifier)
        l = Prio3.Prg.SEED_SIZE
        k_joint_rand, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (verifier, k_joint_rand)

    # Construct an inherited class with the specified number of shares.
    @classmethod
    def with_shares(cls, num_shares: Unsigned):
        if num_shares < 2 or num_shares > 254:
            raise ERR_INPUT
        new_cls = deepcopy(cls)
        new_cls.SHARES = num_shares
        return new_cls


##
# TESTS
#

class Prio3TestField128PrgAes128(Prio3):
    Flp = flp.FlpTestField128
    Prg = prg.PrgAes128


if __name__ == "__main__":
    test_vdaf(Prio3TestField128PrgAes128.with_shares(2),
              None,
              [1, 2, 3, 4, 4],
              [14])
