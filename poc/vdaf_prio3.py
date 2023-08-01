"""The prio3 VDAF."""

from typing import Optional, Union

import flp
import flp_generic
import prg
from common import (ERR_INPUT, ERR_VERIFY, TEST_VECTOR, Unsigned, byte, concat,
                    front, vec_add, vec_sub, zeros)
from vdaf import Vdaf, test_vdaf

USAGE_MEAS_SHARE = 1
USAGE_PROOF_SHARE = 2
USAGE_JOINT_RANDOMNESS = 3
USAGE_PROVE_RANDOMNESS = 4
USAGE_QUERY_RANDOMNESS = 5
USAGE_JOINT_RAND_SEED = 6
USAGE_JOINT_RAND_PART = 7


class Prio3(Vdaf):
    """Base class for VDAFs based on prio3."""

    # Generic types provided by a concrete instance of `Prio3`
    Flp = flp.Flp
    Prg = prg.Prg

    # Parameters required by `Vdaf`
    VERIFY_KEY_SIZE = None  # Set by the PRG
    NONCE_SIZE = 16
    RAND_SIZE = None  # Computed from `Prg.SEED_SIZE` and `SHARES`
    ROUNDS = 1
    SHARES = None  # A number between `[2, 256)` set later

    # Types required by `Vdaf`
    Measurement = Flp.Measurement
    PublicShare = Optional[list[bytes]]  # joint randomness parts
    InputShare = tuple[
        Union[
            tuple[list[Flp.Field], list[Flp.Field]],  # leader
            tuple[bytes, bytes]                       # helper
        ],
        Optional[bytes],  # blind
    ]
    OutShare = list[Flp.Field]
    AggShare = list[Flp.Field]
    AggResult = Flp.AggResult
    PrepShare = tuple[list[Flp.Field],  # verifier share
                      Optional[bytes]]  # joint randomness part
    PrepState = tuple[list[Flp.Field],  # output share
                      Optional[bytes]]  # corrected joint randomness seed
    PrepMessage = Optional[bytes]       # joint randomness check

    @classmethod
    def shard(Prio3, measurement, nonce, rand):
        l = Prio3.Prg.SEED_SIZE
        seeds = [rand[i:i+l] for i in range(0, Prio3.RAND_SIZE, l)]

        meas = Prio3.Flp.encode(measurement)
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            return Prio3.shard_with_joint_rand(meas, nonce, seeds)
        else:
            return Prio3.shard_without_joint_rand(meas, seeds)

    def is_valid(agg_param, previous_agg_params):
        """
        Checks if `previous_agg_params` is empty, as input shares in Prio3 may
        only be used once.
        """
        return len(previous_agg_params) == 0

    @classmethod
    def prep_init(Prio3, verify_key, agg_id, _agg_param,
                  nonce, public_share, input_share):
        k_joint_rand_parts = public_share
        (meas_share, proof_share, k_blind) = \
            Prio3.expand_input_share(agg_id, input_share)
        out_share = Prio3.Flp.truncate(meas_share)

        # Compute the joint randomness.
        joint_rand = []
        k_corrected_joint_rand, k_joint_rand_part = None, None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand_part = Prio3.joint_rand_part(
                agg_id, k_blind, meas_share, nonce)
            k_joint_rand_parts[agg_id] = k_joint_rand_part
            k_corrected_joint_rand = Prio3.joint_rand_seed(
                k_joint_rand_parts)
            joint_rand = Prio3.joint_rand(k_corrected_joint_rand)

        # Query the measurement and proof share.
        query_rand = Prio3.query_rand(verify_key, nonce)
        verifier_share = Prio3.Flp.query(meas_share,
                                         proof_share,
                                         query_rand,
                                         joint_rand,
                                         Prio3.SHARES)

        prep_state = (out_share, k_corrected_joint_rand)
        prep_share = (verifier_share, k_joint_rand_part)
        return (prep_state, prep_share)

    @classmethod
    def prep_next(Prio3, prep, prep_msg):
        k_joint_rand = prep_msg
        (out_share, k_corrected_joint_rand) = prep

        # If joint randomness was used, check that the value computed by the
        # Aggregators matches the value indicated by the Client.
        if k_joint_rand != k_corrected_joint_rand:
            raise ERR_VERIFY  # joint randomness check failed

        return out_share

    @classmethod
    def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
        # Unshard the verifier shares into the verifier message.
        verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
        k_joint_rand_parts = []
        for (verifier_share, k_joint_rand_part) in prep_shares:
            verifier = vec_add(verifier, verifier_share)
            if Prio3.Flp.JOINT_RAND_LEN > 0:
                k_joint_rand_parts.append(k_joint_rand_part)

        # Verify that the proof is well-formed and the input is valid.
        if not Prio3.Flp.decide(verifier):
            raise ERR_VERIFY  # proof verifier check failed

        # Combine the joint randomness parts computed by the
        # Aggregators into the true joint randomness seed. This is
        # used in the last step.
        k_joint_rand = None
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand = Prio3.joint_rand_seed(k_joint_rand_parts)
        return k_joint_rand

    @classmethod
    def aggregate(Prio3, _agg_param, out_shares):
        agg_share = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    @classmethod
    def unshard(Prio3, _agg_param,
                agg_shares, num_measurements):
        agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return Prio3.Flp.decode(agg, num_measurements)

    # Auxiliary functions

    @classmethod
    def shard_without_joint_rand(Prio3, meas, seeds):
        k_helper_seeds, seeds = front((Prio3.SHARES-1) * 2, seeds)
        k_helper_meas_shares = [
            k_helper_seeds[i]
            for i in range(0, (Prio3.SHARES-1) * 2, 2)
        ]
        k_helper_proof_shares = [
            k_helper_seeds[i]
            for i in range(1, (Prio3.SHARES-1) * 2, 2)
        ]
        (k_prove,), seeds = front(1, seeds)

        # Shard the encoded measurement into shares.
        leader_meas_share = meas
        for j in range(Prio3.SHARES-1):
            leader_meas_share = vec_sub(
                leader_meas_share,
                Prio3.helper_meas_share(j+1, k_helper_meas_shares[j]),
            )

        # Generate the proof and shard it into proof shares.
        prove_rand = Prio3.prove_rand(k_prove)
        leader_proof_share = Prio3.Flp.prove(meas, prove_rand, [])
        for j in range(Prio3.SHARES-1):
            leader_proof_share = vec_sub(
                leader_proof_share,
                Prio3.helper_proof_share(j+1, k_helper_proof_shares[j]),
            )

        # Each Aggregator's input share contains its measurement share
        # and proof share.
        input_shares = []
        input_shares.append((
            leader_meas_share,
            leader_proof_share,
            None,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append((
                k_helper_meas_shares[j],
                k_helper_proof_shares[j],
                None,
            ))
        return (None, input_shares)

    @classmethod
    def shard_with_joint_rand(Prio3, meas, nonce, seeds):
        k_helper_seeds, seeds = front((Prio3.SHARES-1) * 3, seeds)
        k_helper_meas_shares = [
            k_helper_seeds[i]
            for i in range(0, (Prio3.SHARES-1) * 3, 3)
        ]
        k_helper_proof_shares = [
            k_helper_seeds[i]
            for i in range(1, (Prio3.SHARES-1) * 3, 3)
        ]
        k_helper_blinds = [
            k_helper_seeds[i]
            for i in range(2, (Prio3.SHARES-1) * 3, 3)
        ]
        (k_leader_blind,), seeds = front(1, seeds)
        (k_prove,), seeds = front(1, seeds)

        # Shard the encoded measurement into shares and compute the
        # joint randomness parts.
        leader_meas_share = meas
        k_joint_rand_parts = []
        for j in range(Prio3.SHARES-1):
            helper_meas_share = Prio3.helper_meas_share(
                j+1, k_helper_meas_shares[j])
            leader_meas_share = vec_sub(leader_meas_share,
                                        helper_meas_share)
            k_joint_rand_parts.append(Prio3.joint_rand_part(
                j+1, k_helper_blinds[j], helper_meas_share, nonce))
        k_joint_rand_parts.insert(0, Prio3.joint_rand_part(
            0, k_leader_blind, leader_meas_share, nonce))

        # Generate the proof and shard it into proof shares.
        prove_rand = Prio3.prove_rand(k_prove)
        joint_rand = Prio3.joint_rand(
            Prio3.joint_rand_seed(k_joint_rand_parts))
        leader_proof_share = Prio3.Flp.prove(meas, prove_rand, joint_rand)
        for j in range(Prio3.SHARES-1):
            leader_proof_share = vec_sub(
                leader_proof_share,
                Prio3.helper_proof_share(j+1, k_helper_proof_shares[j]),
            )

        # Each Aggregator's input share contains its measurement share,
        # proof share, and blind. The public share contains the
        # Aggregators' joint randomness parts.
        input_shares = []
        input_shares.append((
            leader_meas_share,
            leader_proof_share,
            k_leader_blind,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append((
                k_helper_meas_shares[j],
                k_helper_proof_shares[j],
                k_helper_blinds[j],
            ))
        return (k_joint_rand_parts, input_shares)

    @classmethod
    def helper_meas_share(Prio3, agg_id, k_share):
        return Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            Prio3.domain_separation_tag(USAGE_MEAS_SHARE),
            byte(agg_id),
            Prio3.Flp.MEAS_LEN,
        )

    @classmethod
    def helper_proof_share(Prio3, agg_id, k_share):
        return Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            Prio3.domain_separation_tag(USAGE_PROOF_SHARE),
            byte(agg_id),
            Prio3.Flp.PROOF_LEN,
        )

    @classmethod
    def expand_input_share(Prio3, agg_id, input_share):
        (meas_share, proof_share, k_blind) = input_share
        if agg_id > 0:
            meas_share = Prio3.helper_meas_share(agg_id, meas_share)
            proof_share = Prio3.helper_proof_share(agg_id, proof_share)
        return (meas_share, proof_share, k_blind)

    @classmethod
    def prove_rand(Prio3, k_prove):
        return Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_prove,
            Prio3.domain_separation_tag(USAGE_PROVE_RANDOMNESS),
            b'',
            Prio3.Flp.PROVE_RAND_LEN,
        )

    @classmethod
    def query_rand(Prio3, verify_key, nonce):
        return Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            verify_key,
            Prio3.domain_separation_tag(USAGE_QUERY_RANDOMNESS),
            nonce,
            Prio3.Flp.QUERY_RAND_LEN,
        )

    @classmethod
    def joint_rand_part(Prio3, agg_id, k_blind, meas_share, nonce):
        return Prio3.Prg.derive_seed(
            k_blind,
            Prio3.domain_separation_tag(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + Prio3.Flp.Field.encode_vec(meas_share),
        )

    @classmethod
    def joint_rand_seed(Prio3, k_joint_rand_parts):
        """Derive the joint randomness seed from its parts."""
        return Prio3.Prg.derive_seed(
            zeros(Prio3.Prg.SEED_SIZE),
            Prio3.domain_separation_tag(USAGE_JOINT_RAND_SEED),
            concat(k_joint_rand_parts),
        )

    @classmethod
    def joint_rand(Prio3, k_joint_rand_seed):
        """Derive the joint randomness from its seed."""
        return Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand_seed,
            Prio3.domain_separation_tag(USAGE_JOINT_RANDOMNESS),
            b'',
            Prio3.Flp.JOINT_RAND_LEN,
        )

    @classmethod
    def with_shares(Prio3, num_shares):
        assert Prio3.Prg is not None
        assert Prio3.Flp is not None
        if num_shares < 2 or num_shares > 256:
            raise ERR_INPUT
        rand_size = (1+2*(num_shares-1)) * Prio3.Prg.SEED_SIZE
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            rand_size += num_shares * Prio3.Prg.SEED_SIZE

        class Prio3WithShares(Prio3):
            SHARES = num_shares
            RAND_SIZE = rand_size
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

    @classmethod
    def test_vec_encode_input_share(Prio3, input_share):
        (meas_share, proof_share, k_blind) = input_share
        encoded = bytes()
        if type(meas_share) == list and type(proof_share) == list:  # leader
            encoded += Prio3.Flp.Field.encode_vec(meas_share)
            encoded += Prio3.Flp.Field.encode_vec(proof_share)
        elif type(meas_share) == bytes and type(proof_share) == bytes:  # helper
            encoded += meas_share
            encoded += proof_share
        if k_blind != None:  # joint randomness used
            encoded += k_blind
        return encoded

    @classmethod
    def test_vec_encode_public_share(Prio3, k_joint_rand_parts):
        encoded = bytes()
        if k_joint_rand_parts != None:  # joint randomness used
            encoded += concat(k_joint_rand_parts)
        return encoded

    @classmethod
    def test_vec_encode_agg_share(Prio3, agg_share):
        return Prio3.Flp.Field.encode_vec(agg_share)

    @classmethod
    def test_vec_encode_prep_share(Prio3, prep_share):
        (verifier_share, k_joint_rand_part) = prep_share
        encoded = bytes()
        encoded += Prio3.Flp.Field.encode_vec(verifier_share)
        if k_joint_rand_part != None:  # joint randomness used
            encoded += k_joint_rand_part
        return encoded

    @classmethod
    def test_vec_encode_prep_msg(Prio3, k_joint_rand):
        encoded = bytes()
        if k_joint_rand != None:  # joint randomness used
            encoded += k_joint_rand
        return encoded


##
# INSTANTIATIONS
#

class Prio3Count(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3
    Flp = flp_generic.FlpGeneric(flp_generic.Count())

    # Associated parameters.
    ID = 0x00000000
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE

    # Operational parameters.
    test_vec_name = 'Prio3Count'


class Prio3Sum(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3

    # Associated parameters.
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE
    ID = 0x00000001

    # Operational parameters.
    test_vec_name = 'Prio3Sum'

    @classmethod
    def with_bits(Prio3Sum, bits: Unsigned):
        class Prio3SumWithBits(Prio3Sum):
            Flp = flp_generic.FlpGeneric(flp_generic.Sum(bits))
        return Prio3SumWithBits


class Prio3Histogram(Prio3):
    # Generic types required by `Prio3`
    Prg = prg.PrgSha3

    # Associated parameters.
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE
    ID = 0x00000002

    # Operational parameters.
    test_vec_name = 'Prio3Histogram'

    @classmethod
    def with_length(Prio3Histogram, length: Unsigned):
        class Prio3HistogramWithLength(Prio3Histogram):
            Flp = flp_generic.FlpGeneric(flp_generic.Histogram(length))
        return Prio3HistogramWithLength


##
# TESTS
#

class TestPrio3Average(Prio3):
    """
    A Prio3 instantiation to test use of num_measurements in the Valid
    class's decode() method.
    """

    Prg = prg.PrgSha3
    # NOTE 0xFFFFFFFF is reserved for testing. If we decide to standardize this
    # Prio3 variant, then we'll need to pick a real codepoint for it.
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = prg.PrgSha3.SEED_SIZE

    @classmethod
    def with_bits(cls, bits: Unsigned):
        class TestPrio3AverageWithBits(TestPrio3Average):
            Flp = flp_generic.FlpGeneric(flp_generic.TestAverage(bits))
        return TestPrio3AverageWithBits


if __name__ == '__main__':
    num_shares = 2  # Must be in range `[2, 256)`

    cls = Prio3 \
        .with_prg(prg.PrgSha3) \
        .with_flp(flp.FlpTestField128()) \
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
    cls = Prio3Count.with_shares(3)
    test_vdaf(cls, None, [1], 1, print_test_vec=TEST_VECTOR,
              test_vec_instance=1)

    cls = Prio3Sum.with_bits(8).with_shares(num_shares)
    assert cls.ID == 0x00000001
    test_vdaf(cls, None, [0, 147, 1, 0, 11, 0], 159)
    test_vdaf(cls, None, [100], 100, print_test_vec=TEST_VECTOR)
    cls = Prio3Sum.with_bits(8).with_shares(3)
    test_vdaf(cls, None, [100], 100, print_test_vec=TEST_VECTOR,
              test_vec_instance=1)

    cls = Prio3Histogram \
        .with_length(4) \
        .with_shares(num_shares)
    assert cls.ID == 0x00000002
    test_vdaf(cls, None, [0], [1, 0, 0, 0])
    test_vdaf(cls, None, [1], [0, 1, 0, 0])
    test_vdaf(cls, None, [2], [0, 0, 1, 0])
    test_vdaf(cls, None, [3], [0, 0, 0, 1])
    test_vdaf(cls, None, [0, 0, 1, 1, 2, 2, 3, 3], [2, 2, 2, 2])
    test_vdaf(cls, None, [2], [0, 0, 1, 0], print_test_vec=TEST_VECTOR)
    cls = Prio3Histogram.with_length(4).with_shares(3)
    test_vdaf(cls, None, [2], [0, 0, 1, 0], print_test_vec=TEST_VECTOR,
              test_vec_instance=1)

    cls = TestPrio3Average.with_bits(3).with_shares(num_shares)
    test_vdaf(cls, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    # Test `is_valid` returns True on empty previous_agg_params, and False
    # otherwise.
    assert cls.is_valid(None, set([]))
    assert not cls.is_valid(None, set([None]))
