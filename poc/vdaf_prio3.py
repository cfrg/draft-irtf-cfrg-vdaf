"""The prio3 VDAF."""

from typing import Optional, Union

import flp
import flp_generic
import xof
from common import (ERR_INPUT, ERR_VERIFY, TEST_VECTOR, Unsigned, byte, concat,
                    front, vec_add, vec_sub, zeros)
from field import FftField, Field64, Field128
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
    Xof = xof.Xof

    # Parameters required by `Vdaf`
    VERIFY_KEY_SIZE = None  # Set by `Xof`
    NONCE_SIZE = 16
    RAND_SIZE = None  # Computed from `Xof.SEED_SIZE` and `SHARES`
    ROUNDS = 1
    SHARES = None  # A number between `[2, 256)` set later

    # Operational parameters
    PROOFS = 1  # Number of proofs, in range `[1, 256)`

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
        l = Prio3.Xof.SEED_SIZE
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
        (meas_share, proofs_share, k_blind) = \
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
            joint_rands = Prio3.joint_rands(k_corrected_joint_rand)

        # Query the measurement and proof share.
        query_rands = Prio3.query_rands(verify_key, nonce)
        verifiers_share = []
        for _ in range(Prio3.PROOFS):
            proof_share, proofs_share = front(
                Prio3.Flp.PROOF_LEN, proofs_share)
            query_rand, query_rands = front(
                Prio3.Flp.QUERY_RAND_LEN, query_rands)
            if Prio3.Flp.JOINT_RAND_LEN > 0:
                joint_rand, joint_rands = front(
                    Prio3.Flp.JOINT_RAND_LEN, joint_rands)
            verifiers_share += Prio3.Flp.query(meas_share,
                                               proof_share,
                                               query_rand,
                                               joint_rand,
                                               Prio3.SHARES)

        prep_state = (out_share, k_corrected_joint_rand)
        prep_share = (verifiers_share, k_joint_rand_part)
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
        verifiers = Prio3.Flp.Field.zeros(
            Prio3.Flp.VERIFIER_LEN * Prio3.PROOFS)
        k_joint_rand_parts = []
        for (verifiers_share, k_joint_rand_part) in prep_shares:
            verifiers = vec_add(verifiers, verifiers_share)
            if Prio3.Flp.JOINT_RAND_LEN > 0:
                k_joint_rand_parts.append(k_joint_rand_part)

        # Verify that each proof is well-formed and input is valid
        for _ in range(Prio3.PROOFS):
            verifier, verifiers = front(Prio3.Flp.VERIFIER_LEN, verifiers)
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
        k_helper_proofs_shares = [
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

        # Generate and shard each proof into shares.
        prove_rands = Prio3.prove_rands(k_prove)
        leader_proofs_share = []
        for _ in range(Prio3.PROOFS):
            prove_rand, prove_rands = front(
                Prio3.Flp.PROVE_RAND_LEN, prove_rands)
            leader_proofs_share += Prio3.Flp.prove(meas, prove_rand, [])
        for j in range(Prio3.SHARES-1):
            leader_proofs_share = vec_sub(
                leader_proofs_share,
                Prio3.helper_proofs_share(j+1, k_helper_proofs_shares[j]),
            )

        # Each Aggregator's input share contains its measurement share
        # and share of proof(s).
        input_shares = []
        input_shares.append((
            leader_meas_share,
            leader_proofs_share,
            None,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append((
                k_helper_meas_shares[j],
                k_helper_proofs_shares[j],
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
        k_helper_proofs_shares = [
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
        prove_rands = Prio3.prove_rands(k_prove)
        joint_rands = Prio3.joint_rands(
            Prio3.joint_rand_seed(k_joint_rand_parts))
        leader_proofs_share = []
        for _ in range(Prio3.PROOFS):
            prove_rand, prove_rands = front(
                Prio3.Flp.PROVE_RAND_LEN, prove_rands)
            joint_rand, joint_rands = front(
                Prio3.Flp.JOINT_RAND_LEN, joint_rands)
            leader_proofs_share += Prio3.Flp.prove(meas,
                                                   prove_rand, joint_rand)
        for j in range(Prio3.SHARES-1):
            leader_proofs_share = vec_sub(
                leader_proofs_share,
                Prio3.helper_proofs_share(j+1, k_helper_proofs_shares[j]),
            )

        # Each Aggregator's input share contains its measurement share,
        # share of proof(s), and blind. The public share contains the
        # Aggregators' joint randomness parts.
        input_shares = []
        input_shares.append((
            leader_meas_share,
            leader_proofs_share,
            k_leader_blind,
        ))
        for j in range(Prio3.SHARES-1):
            input_shares.append((
                k_helper_meas_shares[j],
                k_helper_proofs_shares[j],
                k_helper_blinds[j],
            ))
        return (k_joint_rand_parts, input_shares)

    @classmethod
    def helper_meas_share(Prio3, agg_id, k_share):
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            Prio3.domain_separation_tag(USAGE_MEAS_SHARE),
            byte(agg_id),
            Prio3.Flp.MEAS_LEN,
        )

    @classmethod
    def helper_proofs_share(Prio3, agg_id, k_share):
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            Prio3.domain_separation_tag(USAGE_PROOF_SHARE),
            byte(agg_id),
            Prio3.Flp.PROOF_LEN * Prio3.PROOFS,
        )

    @classmethod
    def expand_input_share(Prio3, agg_id, input_share):
        (meas_share, proofs_share, k_blind) = input_share
        if agg_id > 0:
            meas_share = Prio3.helper_meas_share(agg_id, meas_share)
            proofs_share = Prio3.helper_proofs_share(agg_id, proofs_share)
        return (meas_share, proofs_share, k_blind)

    @classmethod
    def prove_rands(Prio3, k_prove):
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            k_prove,
            Prio3.domain_separation_tag(USAGE_PROVE_RANDOMNESS),
            b'',
            Prio3.Flp.PROVE_RAND_LEN * Prio3.PROOFS,
        )

    @classmethod
    def query_rands(Prio3, verify_key, nonce):
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            verify_key,
            Prio3.domain_separation_tag(USAGE_QUERY_RANDOMNESS),
            nonce,
            Prio3.Flp.QUERY_RAND_LEN * Prio3.PROOFS,
        )

    @classmethod
    def joint_rand_part(Prio3, agg_id, k_blind, meas_share, nonce):
        return Prio3.Xof.derive_seed(
            k_blind,
            Prio3.domain_separation_tag(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + Prio3.Flp.Field.encode_vec(meas_share),
        )

    @classmethod
    def joint_rand_seed(Prio3, k_joint_rand_parts):
        """Derive the joint randomness seed from its parts."""
        return Prio3.Xof.derive_seed(
            zeros(Prio3.Xof.SEED_SIZE),
            Prio3.domain_separation_tag(USAGE_JOINT_RAND_SEED),
            concat(k_joint_rand_parts),
        )

    @classmethod
    def joint_rands(Prio3, k_joint_rand_seed):
        """Derive the joint randomness from its seed."""
        binder = b'' if Prio3.PROOFS == 1 else byte(Prio3.PROOFS)
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand_seed,
            Prio3.domain_separation_tag(USAGE_JOINT_RANDOMNESS),
            binder,
            Prio3.Flp.JOINT_RAND_LEN * Prio3.PROOFS,
        )

    @classmethod
    def with_shares(Prio3, num_shares):
        assert Prio3.Xof is not None
        assert Prio3.Flp is not None
        if num_shares < 2 or num_shares > 256:
            raise ERR_INPUT
        rand_size = (1+2*(num_shares-1)) * Prio3.Xof.SEED_SIZE
        if Prio3.Flp.JOINT_RAND_LEN > 0:
            rand_size += num_shares * Prio3.Xof.SEED_SIZE

        class Prio3WithShares(Prio3):
            SHARES = num_shares
            RAND_SIZE = rand_size
        return Prio3WithShares

    @classmethod
    def with_xof(Prio3, TheXof):
        class Prio3WithXof(Prio3):
            Xof = TheXof
            VERIFY_KEY_SIZE = TheXof.SEED_SIZE
        return Prio3WithXof

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
        (meas_share, proofs_share, k_blind) = input_share
        encoded = bytes()
        if type(meas_share) == list and type(proofs_share) == list:  # Leader
            assert len(proofs_share) == Prio3.Flp.PROOF_LEN * Prio3.PROOFS
            encoded += Prio3.Flp.Field.encode_vec(meas_share)
            encoded += Prio3.Flp.Field.encode_vec(proofs_share)
        elif type(meas_share) == bytes and type(proofs_share) == bytes:  # Helper
            encoded += meas_share
            encoded += proofs_share
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
        (verifiers_share, k_joint_rand_part) = prep_share
        encoded = bytes()
        assert len(verifiers_share) == Prio3.Flp.VERIFIER_LEN * Prio3.PROOFS
        encoded += Prio3.Flp.Field.encode_vec(verifiers_share)
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
    Xof = xof.XofTurboShake128
    Flp = flp_generic.FlpGeneric(flp_generic.Count())

    # Associated parameters.
    ID = 0x00000000
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE

    # Operational parameters.
    test_vec_name = 'Prio3Count'


class Prio3Sum(Prio3):
    # Generic types required by `Prio3`
    Xof = xof.XofTurboShake128

    # Associated parameters.
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE
    ID = 0x00000001

    # Operational parameters.
    test_vec_name = 'Prio3Sum'

    @classmethod
    def with_bits(Prio3Sum, bits: Unsigned):
        class Prio3SumWithBits(Prio3Sum):
            Flp = flp_generic.FlpGeneric(flp_generic.Sum(bits))
        return Prio3SumWithBits


class Prio3SumVec(Prio3):
    # Generic types required by `Prio3`
    Xof = xof.XofTurboShake128

    # Associated parameters.
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE
    ID = 0x00000002

    # Operational parameters.
    test_vec_name = 'Prio3SumVec'

    @classmethod
    def with_params(Prio3SumVec, length: Unsigned, bits: Unsigned,
                    chunk_length: Unsigned):
        class Prio3SumVecWithParams(Prio3SumVec):
            Flp = flp_generic.FlpGeneric(
                flp_generic.SumVec(length, bits, chunk_length)
            )
        return Prio3SumVecWithParams


class Prio3Histogram(Prio3):
    # Generic types required by `Prio3`
    Xof = xof.XofTurboShake128

    # Associated parameters.
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE
    ID = 0x00000003

    # Operational parameters.
    test_vec_name = 'Prio3Histogram'

    @classmethod
    def with_params(Prio3Histogram, length: Unsigned, chunk_length: Unsigned):
        class Prio3HistogramWithLength(Prio3Histogram):
            Flp = flp_generic.FlpGeneric(
                flp_generic.Histogram(length, chunk_length)
            )
        return Prio3HistogramWithLength


# Experimental multiproof variant of Prio3SumVec
class Prio3SumVecWithMultiproof(Prio3SumVec):
    # Operational parameters.
    test_vec_name = 'Prio3SumVecWithMultiproof'

    @staticmethod
    def is_recommended(valid_cls,
                       num_proofs: Unsigned,
                       f: FftField) -> bool:
        # TODO(issue#177) Decide how many proofs to use.
        if f == Field64:
            # the upper bound is due to the fact
            # we encode it using one byte in `joint_rands`
            return 2 <= num_proofs < 256
        elif f == Field128:
            return 1 <= num_proofs < 256
        return False

    @classmethod
    def with_params(cls,
                    length: Unsigned,
                    bits: Unsigned,
                    chunk_length: Unsigned,
                    num_proofs: Unsigned,
                    field: FftField):
        valid_cls = flp_generic.SumVec.with_field(field)
        if not cls.is_recommended(valid_cls, num_proofs, field):
            raise ValueError("parameters not recommended")

        class Prio3SumVecWithMultiproofAndParams(cls):
            # Associated parameters.
            ID = 0xFFFFFFFF
            PROOFS = num_proofs
            Flp = flp_generic.FlpGeneric(valid_cls(length, bits, chunk_length))
        return Prio3SumVecWithMultiproofAndParams


class Prio3MultiHotHistogram(Prio3):
    # Generic types required by `Prio3`
    Xof = xof.XofTurboShake128

    # Associated parameters.
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE
    # Private codepoint just for testing.
    ID = 0xFFFFFFFF

    # Operational parameters.
    test_vec_name = 'Prio3MultiHotHistogram'

    @classmethod
    def with_params(Prio3MultiHotHistogram,
                    length: Unsigned,
                    max_count: Unsigned,
                    chunk_length: Unsigned):
        class Prio3MultiHotHistogramWithParams(Prio3MultiHotHistogram):
            Flp = flp_generic.FlpGeneric(flp_generic.MultiHotHistogram(
                length, max_count, chunk_length
            ))
        return Prio3MultiHotHistogramWithParams


##
# TESTS
#

class TestPrio3Average(Prio3):
    """
    A Prio3 instantiation to test use of num_measurements in the Valid
    class's decode() method.
    """

    Xof = xof.XofTurboShake128
    # NOTE 0xFFFFFFFF is reserved for testing. If we decide to standardize this
    # Prio3 variant, then we'll need to pick a real codepoint for it.
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE

    @classmethod
    def with_bits(cls, bits: Unsigned):
        class TestPrio3AverageWithBits(TestPrio3Average):
            Flp = flp_generic.FlpGeneric(flp_generic.TestAverage(bits))
        return TestPrio3AverageWithBits


def _test_prio3sumvec(num_proofs: Unsigned, field: FftField):
    valid_cls = flp_generic.SumVec.with_field(field)
    assert Prio3SumVecWithMultiproof.is_recommended(
        valid_cls, num_proofs, field)

    cls = Prio3SumVecWithMultiproof \
        .with_params(10, 8, 9, num_proofs, field) \
        .with_shares(2)

    assert cls.ID == 0xFFFFFFFF
    assert cls.PROOFS == num_proofs

    test_vdaf(
        cls,
        None,
        [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
        [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
    )
    test_vdaf(
        cls,
        None,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        list(range(256, 266)),
        print_test_vec=TEST_VECTOR,
    )
    cls = Prio3SumVec.with_params(3, 16, 7).with_shares(3)
    test_vdaf(
        cls,
        None,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        [45328, 76286, 26980],
        print_test_vec=TEST_VECTOR,
        test_vec_instance=1,
    )


def test_prio3sumvec_with_multiproof():
    for n in range(2, 5):
        _test_prio3sumvec(num_proofs=n, field=Field64)


if __name__ == '__main__':
    num_shares = 2  # Must be in range `[2, 256)`

    cls = Prio3 \
        .with_xof(xof.XofTurboShake128) \
        .with_flp(flp.FlpTestField128()) \
        .with_shares(num_shares)
    cls.ID = 0xFFFFFFFF
    test_vdaf(cls, None, [1, 2, 3, 4, 4], 14)

    # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
    # generating the joint randomness.
    cls = Prio3 \
        .with_xof(xof.XofTurboShake128) \
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

    cls = Prio3SumVec.with_params(10, 8, 9).with_shares(2)
    assert cls.ID == 0x00000002
    test_vdaf(
        cls,
        None,
        [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
        [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
    )
    test_vdaf(
        cls,
        None,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        list(range(256, 266)),
        print_test_vec=TEST_VECTOR,
    )
    cls = Prio3SumVec.with_params(3, 16, 7).with_shares(3)
    test_vdaf(
        cls,
        None,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        [45328, 76286, 26980],
        print_test_vec=TEST_VECTOR,
        test_vec_instance=1,
    )

    cls = Prio3Histogram \
        .with_params(4, 2) \
        .with_shares(num_shares)
    assert cls.ID == 0x00000003
    test_vdaf(cls, None, [0], [1, 0, 0, 0])
    test_vdaf(cls, None, [1], [0, 1, 0, 0])
    test_vdaf(cls, None, [2], [0, 0, 1, 0])
    test_vdaf(cls, None, [3], [0, 0, 0, 1])
    test_vdaf(cls, None, [0, 0, 1, 1, 2, 2, 3, 3], [2, 2, 2, 2])
    test_vdaf(cls, None, [2], [0, 0, 1, 0], print_test_vec=TEST_VECTOR)
    cls = Prio3Histogram.with_params(11, 3).with_shares(3)
    test_vdaf(
        cls,
        None,
        [2],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        print_test_vec=TEST_VECTOR,
        test_vec_instance=1,
    )

    # Prio3MultiHotHistogram with length = 4, max_count = 2, chunk_length = 2.
    cls = Prio3MultiHotHistogram \
        .with_params(4, 2, 2) \
        .with_shares(num_shares)
    assert cls.ID == 0xFFFFFFFF
    test_vdaf(cls, None, [[0, 0, 0, 0]], [0, 0, 0, 0])
    test_vdaf(cls, None, [[0, 1, 0, 0]], [0, 1, 0, 0])
    test_vdaf(cls, None, [[0, 1, 1, 0]], [0, 1, 1, 0])
    test_vdaf(cls, None, [[0, 1, 1, 0], [0, 1, 0, 1]], [0, 2, 1, 1])
    test_vdaf(
        cls, None, [[0, 1, 1, 0]], [0, 1, 1, 0], print_test_vec=TEST_VECTOR
    )
    # Prio3MultiHotHistogram with length = 11, max_count = 5, chunk_length = 3.
    cls = Prio3MultiHotHistogram.with_params(11, 5, 3).with_shares(3)
    test_vdaf(
        cls,
        None,
        [[1] * 5 + [0] * 6],
        [1] * 5 + [0] * 6,
        print_test_vec=TEST_VECTOR,
        test_vec_instance=1,
    )

    cls = TestPrio3Average.with_bits(3).with_shares(num_shares)
    test_vdaf(cls, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    # Test `is_valid` returns True on empty previous_agg_params, and False
    # otherwise.
    assert cls.is_valid(None, set([]))
    assert not cls.is_valid(None, set([None]))

    test_prio3sumvec_with_multiproof()
