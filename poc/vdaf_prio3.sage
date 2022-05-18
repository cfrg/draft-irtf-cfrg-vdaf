# The prio3 VDAF.

from copy import deepcopy
from typing import Tuple
from sagelib.common import ERR_DECODE, ERR_INPUT, ERR_VERIFY, VERSION, \
                           TEST_VECTOR, Bytes, Unsigned, Vec, byte, \
                           gen_rand, vec_add, vec_sub, xor, zeros
from sagelib.vdaf import Vdaf, test_vdaf
import sagelib.flp as flp
import sagelib.flp_generic as flp_generic
import sagelib.prg as prg


# Base class for VDAFs based on prio3.
class Prio3(Vdaf):
    # Generic types provided by a concrete instance of `Prio3`
    Flp = flp.Flp
    Prg = prg.Prg

    # Parameters required by `Vdaf`
    VERIFY_KEY_SIZE = None # Set by the PRG
    ROUNDS = 1
    SHARES = None  # A number between `[0, 255)` set later

    # Types required by `Vdaf`
    Measurement = Flp.Measurement
    OutShare = Vec[Flp.Field]
    AggShare = Vec[Flp.Field]
    AggResult = Vec[Unsigned]
    Prep = Tuple[Vec[Flp.Field],  # output share
                 Bytes,           # k_joint_rand
                 Bytes]           # outbound message

    @classmethod
    def measurement_to_input_shares(Prio3, measurement):
        dst = VERSION + b" prio3"
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
                dst + byte(j+1),
                Prio3.Flp.INPUT_LEN
            )
            leader_input_share = vec_sub(leader_input_share,
                                         helper_input_share)
            encoded = Prio3.Flp.Field.encode_vec(helper_input_share)
            k_hint = Prio3.Prg.derive_seed(k_blind, byte(j+1) + encoded)
            k_joint_rand = xor(k_joint_rand, k_hint)
            k_helper_input_shares.append(k_share)
            k_helper_blinds.append(k_blind)
            k_helper_hints.append(k_hint)
        k_leader_blind = gen_rand(Prio3.Prg.SEED_SIZE)
        encoded = Prio3.Flp.Field.encode_vec(leader_input_share)
        k_leader_hint = Prio3.Prg.derive_seed(k_leader_blind, byte(0) + encoded)
        k_joint_rand = xor(k_joint_rand, k_leader_hint)

        # Finish joint randomness hints.
        for j in range(Prio3.SHARES-1):
            k_helper_hints[j] = xor(k_helper_hints[j], k_joint_rand)
        k_leader_hint = xor(k_leader_hint, k_joint_rand)

        # Generate the proof shares.
        prove_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            gen_rand(Prio3.Prg.SEED_SIZE),
            dst,
            Prio3.Flp.PROVE_RAND_LEN
        )
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            dst,
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
                dst + byte(j+1),
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

    # TODO We could shave off a couple of blockcipher calls if, instead of
    # deriving `k_query_rand`, we use `verify_key` to derive the query
    # randomness directly.
    @classmethod
    def prep_init(Prio3, verify_key, agg_id, _agg_param, nonce, input_share):
        dst = VERSION + b" prio3"

        (input_share, proof_share, k_blind, k_hint) = \
            Prio3.decode_leader_share(input_share) if agg_id == 0 else \
            Prio3.decode_helper_share(dst, agg_id, input_share)

        out_share = Prio3.Flp.truncate(input_share)

        k_query_rand = Prio3.Prg.derive_seed(verify_key, byte(255) + nonce)
        query_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_query_rand,
            dst,
            Prio3.Flp.QUERY_RAND_LEN
        )
        joint_rand, k_joint_rand, k_joint_rand_share = [], None, None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded = Prio3.Flp.Field.encode_vec(input_share)
            k_joint_rand_share = Prio3.Prg.derive_seed(
                k_blind, byte(agg_id) + encoded)
            k_joint_rand = xor(k_hint, k_joint_rand_share)
            joint_rand = Prio3.Prg.expand_into_vec(
                Prio3.Flp.Field,
                k_joint_rand,
                dst,
                Prio3.Flp.JOINT_RAND_LEN
            )
        verifier_share = Prio3.Flp.query(input_share,
                                         proof_share,
                                         query_rand,
                                         joint_rand,
                                         Prio3.SHARES)

        prep_msg = Prio3.encode_prep_share(verifier_share,
                                           k_joint_rand_share)
        return (out_share, k_joint_rand, prep_msg)

    @classmethod
    def prep_next(Prio3, prep, inbound):
        (out_share, k_joint_rand, prep_msg) = prep

        if inbound is None:
            return (prep, prep_msg)

        k_joint_rand_check = Prio3.decode_prep_msg(inbound)
        if k_joint_rand_check != k_joint_rand:
            raise ERR_VERIFY # joint randomness check failed

        return out_share

    @classmethod
    def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
        verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
        k_joint_rand_check = zeros(Prio3.Prg.SEED_SIZE)
        for encoded in prep_shares:
            (verifier_share, k_joint_rand_share) = \
                Prio3.decode_prep_share(encoded)

            verifier = vec_add(verifier, verifier_share)

            if Prio3.Flp.JOINT_RAND_LEN > 0:
                k_joint_rand_check = xor(k_joint_rand_check,
                                         k_joint_rand_share)

        if not Prio3.Flp.decide(verifier):
            raise ERR_VERIFY # proof verifier check failed

        return Prio3.encode_prep_msg(k_joint_rand_check)

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
        if Prio3.Flp.JOINT_RAND_LEN > 0:
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
        k_blind, k_hint = None, None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
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
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += k_blind
            encoded += k_hint
        return encoded

    @classmethod
    def decode_helper_share(Prio3, dst, agg_id, encoded):
        l = Prio3.Prg.SEED_SIZE
        k_input_share, encoded = encoded[:l], encoded[l:]
        input_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                                k_input_share,
                                                dst + byte(agg_id),
                                                Prio3.Flp.INPUT_LEN)
        k_proof_share, encoded = encoded[:l], encoded[l:]
        proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                                k_proof_share,
                                                dst + byte(agg_id),
                                                Prio3.Flp.PROOF_LEN)
        k_blind, k_hint = None, None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_blind, encoded = encoded[:l], encoded[l:]
            k_hint, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (input_share, proof_share, k_blind, k_hint)

    @classmethod
    def encode_prep_share(Prio3, verifier, k_joint_rand):
        encoded = Bytes()
        encoded += Prio3.Flp.Field.encode_vec(verifier)
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += k_joint_rand
        return encoded

    @classmethod
    def decode_prep_share(Prio3, encoded):
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.VERIFIER_LEN
        encoded_verifier, encoded = encoded[:l], encoded[l:]
        verifier = Prio3.Flp.Field.decode_vec(encoded_verifier)
        k_joint_rand = None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            l = Prio3.Prg.SEED_SIZE
            k_joint_rand, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (verifier, k_joint_rand)

    @classmethod
    def encode_prep_msg(Prio3, k_joint_rand_check):
        encoded = Bytes()
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += k_joint_rand_check
        return encoded

    @classmethod
    def decode_prep_msg(Prio3, encoded):
        k_joint_rand_check = None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            l = Prio3.Prg.SEED_SIZE
            k_joint_rand_check, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return k_joint_rand_check

    @classmethod
    def with_shares(cls, num_shares: Unsigned):
        if num_shares < 2 or num_shares > 254:
            raise ERR_INPUT
        new_cls = deepcopy(cls)
        new_cls.SHARES = num_shares
        return new_cls

    @classmethod
    def with_prg(cls, Prg):
        new_cls = deepcopy(cls)
        new_cls.Prg = Prg
        new_cls.VERIFY_KEY_SIZE = Prg.SEED_SIZE
        return new_cls

    @classmethod
    def with_flp(cls, Flp):
        new_cls = deepcopy(cls)
        new_cls.Flp = Flp
        return new_cls


##
# INSTANTIATIONS
#

class Prio3Aes128Count(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgAes128
    Flp = flp_generic.FlpGeneric.with_valid(flp_generic.Count)

    # Associated types.
    VERIFY_KEY_SIZE = prg.PrgAes128.SEED_SIZE

class Prio3Aes128Sum(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgAes128

    @classmethod
    def with_bits(cls, bits: Unsigned):
        new_cls = deepcopy(cls).with_prg(prg.PrgAes128)
        new_cls.Flp = flp_generic.FlpGeneric \
            .with_valid(flp_generic.Sum.with_bits(bits))
        return new_cls

class Prio3Aes128Histogram(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgAes128

    @classmethod
    def with_buckets(cls, buckets: Vec[Unsigned]):
        new_cls = deepcopy(cls).with_prg(prg.PrgAes128)
        new_cls.Flp = flp_generic.FlpGeneric \
            .with_valid(flp_generic.Histogram.with_buckets(buckets))
        return new_cls


##
# TESTS
#

if __name__ == "__main__":
    cls = Prio3 \
        .with_prg(prg.PrgAes128) \
        .with_flp(flp.FlpTestField128) \
        .with_shares(2)
    test_vdaf(cls, None, [1, 2, 3, 4, 4], [14])

    # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
    # generating the joint randomness.
    cls = Prio3 \
        .with_prg(prg.PrgAes128) \
        .with_flp(flp.FlpTestField128.with_joint_rand_len(0)) \
        .with_shares(2)
    test_vdaf(cls, None, [1, 2, 3, 4, 4], [14])

    cls = Prio3Aes128Count.with_shares(2)
    test_vdaf(cls, None, [0, 1, 1, 0, 1], [3])
    test_vdaf(cls, None, [1], [1], print_test_vector=TEST_VECTOR)

    cls = Prio3Aes128Sum.with_shares(2).with_bits(8)
    test_vdaf(cls, None, [0, 147, 1, 0, 11, 0], [159])
    test_vdaf(cls, None, [100], [100], print_test_vector=TEST_VECTOR)

    cls = Prio3Aes128Histogram.with_shares(2).with_buckets([1, 10, 100])
    test_vdaf(cls, None, [0], [1, 0, 0, 0])
    test_vdaf(cls, None, [5], [0, 1, 0, 0])
    test_vdaf(cls, None, [10], [0, 1, 0, 0])
    test_vdaf(cls, None, [15], [0, 0, 1, 0])
    test_vdaf(cls, None, [100], [0, 0, 1, 0])
    test_vdaf(cls, None, [101], [0, 0, 0, 1])
    test_vdaf(cls, None, [0, 1, 5, 10, 15, 100, 101, 101], [2, 2, 2, 2])
    test_vdaf(cls, None, [50], [0, 0, 1, 0], print_test_vector=TEST_VECTOR)
