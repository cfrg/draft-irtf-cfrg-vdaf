# The prio3 VDAF.

from typing import Tuple
from sagelib.common import ERR_DECODE, ERR_INPUT, ERR_VERIFY, TEST_VECTOR, \
                           Bytes, Unsigned, Vec, byte, concat, gen_rand, \
                           vec_add, vec_sub, zeros
from sagelib.vdaf import Vdaf, test_vdaf
import sagelib.flp as flp
import sagelib.flp_generic as flp_generic
import sagelib.prg as prg

DST_MEASUREMENT_SHARE = 1
DST_PROOF_SHARE = 2
DST_JOINT_RANDOMNESS = 3
DST_PROVE_RANDOMNESS = 4
DST_QUERY_RANDOMNESS = 5
DST_JOINT_RAND_SEED = 6
DST_JOINT_RAND_PART = 7

# Base class for VDAFs based on prio3.
class Prio3(Vdaf):
    # Generic types provided by a concrete instance of `Prio3`
    Flp = flp.Flp
    Prg = prg.Prg

    # Parameters required by `Vdaf`
    VERIFY_KEY_SIZE = None # Set by the PRG
    NONCE_SIZE = 16
    ROUNDS = 1
    SHARES = None  # A number between `[2, 256)` set later

    # Types required by `Vdaf`
    Measurement = Flp.Measurement
    OutShare = Vec[Flp.Field]
    AggResult = Flp.AggResult
    Prep = Tuple[Vec[Flp.Field],  # output share
                 Bytes,           # k_joint_rand
                 Bytes]           # outbound message

    @classmethod
    def measurement_to_input_shares(Prio3, measurement, nonce):
        inp = Prio3.Flp.encode(measurement)

        # Generate measurement shares.
        leader_meas_share = inp
        k_helper_meas_shares = []
        k_helper_blinds = []
        k_joint_rand_parts = []
        for j in range(Prio3.SHARES-1):
            k_blind = gen_rand(Prio3.Prg.SEED_SIZE)
            k_share = gen_rand(Prio3.Prg.SEED_SIZE)
            helper_meas_share = Prio3.Prg.expand_into_vec(
                Prio3.Flp.Field,
                k_share,
                Prio3.custom(DST_MEASUREMENT_SHARE),
                byte(j+1),
                Prio3.Flp.INPUT_LEN
            )
            leader_meas_share = vec_sub(leader_meas_share,
                                        helper_meas_share)
            encoded = Prio3.Flp.Field.encode_vec(helper_meas_share)
            k_joint_rand_part = Prio3.Prg.derive_seed(k_blind,
                Prio3.custom(DST_JOINT_RAND_PART),
                byte(j+1) + nonce + encoded)
            k_helper_meas_shares.append(k_share)
            k_helper_blinds.append(k_blind)
            k_joint_rand_parts.append(k_joint_rand_part)
        k_leader_blind = gen_rand(Prio3.Prg.SEED_SIZE)
        encoded = Prio3.Flp.Field.encode_vec(leader_meas_share)
        k_leader_joint_rand_part = Prio3.Prg.derive_seed(k_leader_blind,
            Prio3.custom(DST_JOINT_RAND_PART),
            byte(0) + nonce + encoded)
        k_joint_rand_parts.insert(0, k_leader_joint_rand_part)

        # Compute joint randomness seed.
        k_joint_rand = Prio3.joint_rand(k_joint_rand_parts)

        # Generate the proof shares.
        prove_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            gen_rand(Prio3.Prg.SEED_SIZE),
            Prio3.custom(DST_PROVE_RANDOMNESS),
            b'',
            Prio3.Flp.PROVE_RAND_LEN,
        )
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            Prio3.custom(DST_JOINT_RANDOMNESS),
            b'',
            Prio3.Flp.JOINT_RAND_LEN,
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
                Prio3.custom(DST_PROOF_SHARE),
                byte(j+1),
                Prio3.Flp.PROOF_LEN,
            )
            leader_proof_share = vec_sub(leader_proof_share,
                                         helper_proof_share)

        # Each Aggregator's input share contains its measurement share,
        # proof share, and blind. The public share contains the
        # Aggregators' joint randomness parts.
        input_shares = []
        input_shares.append(Prio3.encode_leader_share(
            leader_meas_share,
            leader_proof_share,
            k_leader_blind,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append(Prio3.encode_helper_share(
                k_helper_meas_shares[j],
                k_helper_proof_shares[j],
                k_helper_blinds[j],
            ))
        public_share = Prio3.encode_public_share(k_joint_rand_parts)
        return (public_share, input_shares)

    # Checks if `previous_agg_params` is empty, as input shares in Prio3 may
    # only be used once.
    def is_valid(agg_param, previous_agg_params):
        return len(previous_agg_params) == 0

    @classmethod
    def prep_init(Prio3, verify_key, agg_id, _agg_param,
                  nonce, public_share, input_share):
        k_joint_rand_parts = Prio3.decode_public_share(public_share)
        (meas_share, proof_share, k_blind) = \
            Prio3.decode_leader_share(input_share) if agg_id == 0 else \
            Prio3.decode_helper_share(agg_id, input_share)
        out_share = Prio3.Flp.truncate(meas_share)

        # Compute joint randomness.
        joint_rand = []
        k_corrected_joint_rand, k_joint_rand_part = None, None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded = Prio3.Flp.Field.encode_vec(meas_share)
            k_joint_rand_part = Prio3.Prg.derive_seed(k_blind,
                Prio3.custom(DST_JOINT_RAND_PART),
                byte(agg_id) + nonce + encoded)
            k_joint_rand_parts[agg_id] = k_joint_rand_part
            k_corrected_joint_rand = Prio3.joint_rand(k_joint_rand_parts)
            joint_rand = Prio3.Prg.expand_into_vec(
                Prio3.Flp.Field,
                k_corrected_joint_rand,
                Prio3.custom(DST_JOINT_RANDOMNESS),
                b'',
                Prio3.Flp.JOINT_RAND_LEN,
            )

        # Query the measurement and proof share.
        query_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            verify_key,
            Prio3.custom(DST_QUERY_RANDOMNESS),
            nonce,
            Prio3.Flp.QUERY_RAND_LEN,
        )
        verifier_share = Prio3.Flp.query(meas_share,
                                         proof_share,
                                         query_rand,
                                         joint_rand,
                                         Prio3.SHARES)

        prep_msg = Prio3.encode_prep_share(verifier_share,
                                           k_joint_rand_part)
        return (out_share, k_corrected_joint_rand, prep_msg)

    @classmethod
    def prep_next(Prio3, prep, inbound):
        (out_share, k_corrected_joint_rand, prep_msg) = prep

        if inbound is None:
            return (prep, prep_msg)

        k_joint_rand_check = Prio3.decode_prep_msg(inbound)
        if k_joint_rand_check != k_corrected_joint_rand:
            raise ERR_VERIFY # joint randomness check failed

        return out_share

    @classmethod
    def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
        verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
        k_joint_rand_parts = []
        for encoded in prep_shares:
            (verifier_share, k_joint_rand_part) = \
                Prio3.decode_prep_share(encoded)

            verifier = vec_add(verifier, verifier_share)

            if Prio3.Flp.JOINT_RAND_LEN > 0:
                k_joint_rand_parts.append(k_joint_rand_part)

        if not Prio3.Flp.decide(verifier):
            raise ERR_VERIFY # proof verifier check failed

        k_joint_rand_check = None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand_check = Prio3.joint_rand(k_joint_rand_parts)
        return Prio3.encode_prep_msg(k_joint_rand_check)

    @classmethod
    def out_shares_to_agg_share(Prio3, _agg_param, out_shares):
        agg_share = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return Prio3.Flp.Field.encode_vec(agg_share)

    @classmethod
    def agg_shares_to_result(Prio3, _agg_param,
                             agg_shares, num_measurements):
        agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for agg_share in agg_shares:
            agg = vec_add(agg, Prio3.Flp.Field.decode_vec(agg_share))
        return Prio3.Flp.decode(agg, num_measurements)

    # Derive the joint randomness seed from its parts.
    @classmethod
    def joint_rand(Prio3, k_joint_rand_parts):
        return Prio3.Prg.derive_seed(
            zeros(Prio3.Prg.SEED_SIZE),
            Prio3.custom(DST_JOINT_RAND_SEED),
            concat(k_joint_rand_parts),
        )

    @classmethod
    def encode_leader_share(Prio3,
                            meas_share,
                            proof_share,
                            k_blind):
        encoded = Bytes()
        encoded += Prio3.Flp.Field.encode_vec(meas_share)
        encoded += Prio3.Flp.Field.encode_vec(proof_share)
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += k_blind
        return encoded

    @classmethod
    def decode_leader_share(Prio3, encoded):
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.INPUT_LEN
        encoded_meas_share, encoded = encoded[:l], encoded[l:]
        meas_share = Prio3.Flp.Field.decode_vec(encoded_meas_share)
        l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.PROOF_LEN
        encoded_proof_share, encoded = encoded[:l], encoded[l:]
        proof_share = Prio3.Flp.Field.decode_vec(encoded_proof_share)
        l = Prio3.Prg.SEED_SIZE
        if Prio3.Flp.JOINT_RAND_LEN == 0:
            if len(encoded) != 0:
                raise ERR_DECODE
            return (meas_share, proof_share, None)
        k_blind, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (meas_share, proof_share, k_blind)

    @classmethod
    def encode_helper_share(Prio3,
                            k_meas_share,
                            k_proof_share,
                            k_blind):
        encoded = Bytes()
        encoded += k_meas_share
        encoded += k_proof_share
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += k_blind
        return encoded

    @classmethod
    def decode_helper_share(Prio3, agg_id, encoded):
        c_meas_share = Prio3.custom(DST_MEASUREMENT_SHARE)
        c_proof_share = Prio3.custom(DST_PROOF_SHARE)
        l = Prio3.Prg.SEED_SIZE
        k_meas_share, encoded = encoded[:l], encoded[l:]
        meas_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                               k_meas_share,
                                               c_meas_share,
                                               byte(agg_id),
                                               Prio3.Flp.INPUT_LEN)
        k_proof_share, encoded = encoded[:l], encoded[l:]
        proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                                k_proof_share,
                                                c_proof_share,
                                                byte(agg_id),
                                                Prio3.Flp.PROOF_LEN)
        if Prio3.Flp.JOINT_RAND_LEN == 0:
            if len(encoded) != 0:
                raise ERR_DECODE
            return (meas_share, proof_share, None)
        k_blind, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return (meas_share, proof_share, k_blind)

    @classmethod
    def encode_public_share(Prio3,
                            k_joint_rand_parts):
        encoded = Bytes()
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            encoded += concat(k_joint_rand_parts)
        return encoded

    @classmethod
    def decode_public_share(Prio3, encoded):
        l = Prio3.Prg.SEED_SIZE
        if Prio3.Flp.JOINT_RAND_LEN == 0:
            if len(encoded) != 0:
                raise ERR_DECODE
            return None
        k_joint_rand_parts = []
        for i in range(Prio3.SHARES):
            k_joint_rand_part, encoded = encoded[:l], encoded[l:]
            k_joint_rand_parts.append(k_joint_rand_part)
        if len(encoded) != 0:
            raise ERR_DECODE
        return k_joint_rand_parts

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
        if Prio3.Flp.JOINT_RAND_LEN == 0:
            if len(encoded) != 0:
                raise ERR_DECODE
            return (verifier, None)
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
        if Prio3.Flp.JOINT_RAND_LEN == 0:
            if len(encoded) != 0:
                raise ERR_DECODE
            return None
        l = Prio3.Prg.SEED_SIZE
        k_joint_rand_check, encoded = encoded[:l], encoded[l:]
        if len(encoded) != 0:
            raise ERR_DECODE
        return k_joint_rand_check

    @classmethod
    def with_shares(Prio3, num_shares):
        if num_shares < 2 or num_shares > 256:
            raise ERR_INPUT
        class Prio3WithShares(Prio3):
            SHARES = num_shares
        return Prio3WithShares

    @classmethod
    def with_prg(Prio3, ThePrg):
        class Prio3WithPrg(Prio3):
            Prg = ThePrg
            VERIFY_KEY_SIZE = ThePrg.SEED_SIZE
        return Prio3WithPrg

    @classmethod
    def with_flp(Prio3, TheFlp):
        class Prio3WithFlp(Prio3):
            Flp = TheFlp
        return Prio3WithFlp

    @classmethod
    def test_vec_set_type_param(Prio3, test_vec):
        return Prio3.Flp.test_vec_set_type_param(test_vec)


##
# INSTANTIATIONS
#

class Prio3Count(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3
    Flp = flp_generic.FlpGeneric.with_valid(flp_generic.Count)

    # Associated parameters.
    ID = 0x00000000
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE

class Prio3Sum(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3

    # Associated parameters.
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE
    ID = 0x00000001

    @classmethod
    def with_bits(Prio3Sum, bits: Unsigned):
        class Prio3SumWithBits(Prio3Sum):
            Flp = flp_generic.FlpGeneric \
                    .with_valid(flp_generic.Sum.with_bits(bits))
        return Prio3SumWithBits

class Prio3Histogram(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3

    # Associated parameters.
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE
    ID = 0x00000002

    @classmethod
    def with_buckets(Prio3Histogram, buckets: Vec[Unsigned]):
        class Prio3HistogramWithBuckets(Prio3Histogram):
            Flp = flp_generic.FlpGeneric \
                    .with_valid(flp_generic.Histogram.with_buckets(buckets))
        return Prio3HistogramWithBuckets


##
# TESTS
#

class TestPrio3Average(Prio3):
    '''
    A Prio3 instantiation to test use of num_measurements in the Valid
    class's decode() method.
    '''

    Prg = prg.PrgSha3
    # NOTE 0xFFFFFFFF is reserved for testing. If we decide to standardize this
    # Prio3 variant, then we'll need to pick a real codepoint for it.
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE

    @classmethod
    def with_bits(cls, bits: Unsigned):
        class TestPrio3AverageWithBits(TestPrio3Average):
            Flp = flp_generic.FlpGeneric \
                    .with_valid(flp_generic.TestAverage.with_bits(bits))
        return TestPrio3AverageWithBits


if __name__ == '__main__':
    num_shares = 2 # Must be in range `[2, 256)`

    cls = Prio3 \
        .with_prg(prg.PrgSha3) \
        .with_flp(flp.FlpTestField128) \
        .with_shares(num_shares)
    cls.ID = 0xFFFFFFFF
    test_vdaf(cls, None, [1, 2, 3, 4, 4], 14)

    # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
    # generating the joint randomness.
    cls = Prio3 \
        .with_prg(prg.PrgSha3) \
        .with_flp(flp.FlpTestField128.with_joint_rand_len(0)) \
        .with_shares(num_shares)
    cls.ID = 0xFFFFFFFF
    test_vdaf(cls, None, [1, 2, 3, 4, 4], 14)

    cls = Prio3Count.with_shares(num_shares)
    assert cls.ID == 0x00000000
    test_vdaf(cls, None, [0, 1, 1, 0, 1], 3)
    test_vdaf(cls, None, [1], 1, print_test_vec=TEST_VECTOR)

    cls = Prio3Sum.with_shares(num_shares).with_bits(8)
    assert cls.ID == 0x00000001
    test_vdaf(cls, None, [0, 147, 1, 0, 11, 0], 159)
    test_vdaf(cls, None, [100], 100, print_test_vec=TEST_VECTOR)

    cls = Prio3Histogram \
            .with_shares(num_shares) \
            .with_buckets([1, 10, 100])
    assert cls.ID == 0x00000002
    test_vdaf(cls, None, [0], [1, 0, 0, 0])
    test_vdaf(cls, None, [5], [0, 1, 0, 0])
    test_vdaf(cls, None, [10], [0, 1, 0, 0])
    test_vdaf(cls, None, [15], [0, 0, 1, 0])
    test_vdaf(cls, None, [100], [0, 0, 1, 0])
    test_vdaf(cls, None, [101], [0, 0, 0, 1])
    test_vdaf(cls, None, [0, 1, 5, 10, 15, 100, 101, 101], [2, 2, 2, 2])
    test_vdaf(cls, None, [50], [0, 0, 1, 0], print_test_vec=TEST_VECTOR)

    cls = TestPrio3Average.with_bits(3).with_shares(num_shares)
    test_vdaf(cls, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    # Test `is_valid` returns True on empty previous_agg_params, and False
    # otherwise.
    assert cls.is_valid(b"", [])
    assert not cls.is_valid(b"", [b""])
