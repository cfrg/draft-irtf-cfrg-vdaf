"""The prio3 VDAF."""

import flp_generic
import xof
from common import byte, concat, front, vec_add, vec_sub, zeros
from vdaf import Vdaf

USAGE_MEAS_SHARE = 1
USAGE_PROOF_SHARE = 2
USAGE_JOINT_RANDOMNESS = 3
USAGE_PROVE_RANDOMNESS = 4
USAGE_QUERY_RANDOMNESS = 5
USAGE_JOINT_RAND_SEED = 6
USAGE_JOINT_RAND_PART = 7


class Prio3(Vdaf):
    """Base class for VDAFs based on prio3."""

    # TODO(issue #361) The following types are not enforceable by mypy.
    #
    # Generic types provided by a concrete instance of `Prio3`
    # Flp = flp.Flp
    # Xof = xof.Xof

    # Parameters required by `Vdaf`
    NONCE_SIZE = 16
    ROUNDS = 1

    # Operational parameters
    PROOFS = 1  # Number of proofs, in range `[1, 256)`

    # TODO(issue #361) The following type are not enforceable by mypy.
    #
    # Types required by `Vdaf`
    # Measurement = Flp.Measurement
    # PublicShare = Optional[list[bytes]]  # joint randomness parts
    # InputShare = tuple[
    #    Union[
    #        tuple[list[Flp.Field], list[Flp.Field]],  # leader
    #        tuple[bytes, bytes]                       # helper
    #    ],
    #    Optional[bytes],  # blind
    # ]
    # OutShare = list[Flp.Field]
    # AggShare = list[Flp.Field]
    # AggResult = Flp.AggResult
    # PrepShare = tuple[list[Flp.Field],  # verifier share
    #                  Optional[bytes]]  # joint randomness part
    # PrepState = tuple[list[Flp.Field],  # output share
    #                  Optional[bytes]]  # corrected joint randomness seed
    # PrepMessage = Optional[bytes]       # joint randomness check

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

        # If joint randomness was used, check that the value computed by
        # the Aggregators matches the value indicated by the Client.
        if k_joint_rand != k_corrected_joint_rand:
            raise ValueError('joint randomness check failed')

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
                raise ValueError('proof verifier check failed')

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
            byte(Prio3.PROOFS) + byte(agg_id),
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
            byte(Prio3.PROOFS),
            Prio3.Flp.PROVE_RAND_LEN * Prio3.PROOFS,
        )

    @classmethod
    def query_rands(Prio3, verify_key, nonce):
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            verify_key,
            Prio3.domain_separation_tag(USAGE_QUERY_RANDOMNESS),
            byte(Prio3.PROOFS) + nonce,
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
        return Prio3.Xof.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand_seed,
            Prio3.domain_separation_tag(USAGE_JOINT_RANDOMNESS),
            byte(Prio3.PROOFS),
            Prio3.Flp.JOINT_RAND_LEN * Prio3.PROOFS,
        )

    @classmethod
    def with_shares(Prio3, num_shares):
        assert Prio3.Xof is not None
        assert Prio3.Flp is not None
        if num_shares not in range(2, 256):
            raise ValueError('invalid number of shares')
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

    # TODO(issue #361) Enforce `bits: int`.
    @classmethod
    def with_bits(Prio3Sum, bits):
        """
        Set the range to `range(0, 2**bits)`.

        Pre-conditions:

            - `bits > 0`
        """
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

    # TODO(issue #361) Enforce that each parameter is an `int`.
    @classmethod
    def with_params(Prio3SumVec, length, bits, chunk_length):
        """
        Set the circuit parameters.

        Pre-conditions:

            - `length > 0`
            - `bits > 0`
            - `chunk_length > 0`
        """
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

    # TODO(issue #361) Enforce that each parameter is an `int`.
    @classmethod
    def with_params(Prio3Histogram, length, chunk_length):
        """
        Set the circuit parameters.

        Pre-conditions:

            - `length > 0`
            - `chunk_length > 0`
        """
        class Prio3HistogramWithLength(Prio3Histogram):
            Flp = flp_generic.FlpGeneric(
                flp_generic.Histogram(length, chunk_length)
            )
        return Prio3HistogramWithLength


class Prio3SumVecWithMultiproof(Prio3SumVec):
    """Experimental multiproof variant of Prio3SumVec."""

    # Operational parameters.
    test_vec_name = 'Prio3SumVecWithMultiproof'

    # TODO(issue #361) Enforce that each parameter is an `int` except `field`,
    # which should be a `type[Field]`.
    @classmethod
    def with_params(cls, length, bits, chunk_length, num_proofs, field):
        """
        Set the circuit parameters, the number of proofs to generate, and the field.

        Pre-conditions:

            - `length > 0`
            - `bits > 0`
            - `chunk_length > 0`
            - `0 < num_proofs` and `num_proofs < 256`
            - `field` is a sub-class of `FftField`.
        """
        valid_cls = flp_generic.SumVec.with_field(field)

        class Prio3SumVecWithMultiproofAndParams(cls):
            # Associated parameters.
            ID = 0xFFFFFFFF
            PROOFS = num_proofs
            Flp = flp_generic.FlpGeneric(valid_cls(length, bits, chunk_length))
        return Prio3SumVecWithMultiproofAndParams


class Prio3MultihotCountVec(Prio3):
    # Generic types required by `Prio3`
    Xof = xof.XofTurboShake128

    # Associated parameters.
    VERIFY_KEY_SIZE = xof.XofTurboShake128.SEED_SIZE
    ID = 0x00000004

    # Operational parameters.
    test_vec_name = 'Prio3MultihotCountVec'

    # TODO(issue #361) Enforce that each parameter is an `int`.
    @classmethod
    def with_params(cls, length, max_weight, chunk_length):
        """
        Set the circuit parameters.

        Pre-conditions:

            - `length > 0`
            - `max_weight > 0`
            - `chunk_length > 0`
        """
        class Prio3MultihotCountVecWithParams(cls):
            Flp = flp_generic.FlpGeneric(flp_generic.MultihotCountVec(
                length, max_weight, chunk_length
            ))
        return Prio3MultihotCountVecWithParams
