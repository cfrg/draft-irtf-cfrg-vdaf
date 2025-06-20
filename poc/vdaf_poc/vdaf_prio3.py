"""The Prio3 VDAF."""

from abc import abstractmethod
from typing import Any, Generic, Optional, TypeAlias, TypeVar

from vdaf_poc import flp_bbcggi19
from vdaf_poc.common import byte, concat, front, vec_add, vec_sub, zeros
from vdaf_poc.field import Field64, Field128, NttField
from vdaf_poc.flp import Flp
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.xof import Xof, XofTurboShake128

USAGE_MEAS_SHARE = 1
USAGE_PROOF_SHARE = 2
USAGE_JOINT_RANDOMNESS = 3
USAGE_PROVE_RANDOMNESS = 4
USAGE_QUERY_RANDOMNESS = 5
USAGE_JOINT_RAND_SEED = 6
USAGE_JOINT_RAND_PART = 7

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)

Prio3InputShare: TypeAlias = \
    tuple[  # leader input share
        list[F],  # measurement share
        list[F],  # proof share
        Optional[bytes],  # joint randomness blind
    ] | \
    tuple[  # helper input share
        bytes,  # measurement and proof share seed
        Optional[bytes],  # joint randomness blind
    ]
Prio3PrepState: TypeAlias = tuple[
    list[F],  # output share
    Optional[bytes],  # corrected joint randomness seed
]
Prio3PrepShare: TypeAlias = tuple[
    list[F],  # verifier share
    Optional[bytes],  # joint randomness part
]


class Prio3(
        Generic[Measurement, AggResult, F],
        Vdaf[
            Measurement,
            None,  # AggParam
            Optional[list[bytes]],  # PublicShare
            Prio3InputShare[F],  # InputShare
            list[F],  # OutShare
            list[F],  # AggShare
            AggResult,
            Prio3PrepState[F],  # PrepState
            Prio3PrepShare[F],  # PrepShare
            Optional[bytes],  # PrepMessage, joint randomness seed check
        ]):
    """Base class for VDAFs based on Prio3."""

    NONCE_SIZE = 16
    ROUNDS = 1

    xof: type[Xof]
    PROOFS: int  # Number of proofs, in the range `[1, 256)`

    @abstractmethod
    def __init__(
            self,
            shares: int,
            flp: Flp[Measurement, AggResult, F],
            num_proofs: int):
        assert self.ID is not None
        assert self.xof is not None
        assert self.VERIFY_KEY_SIZE is not None
        assert flp is not None
        if shares not in range(2, 256):
            raise ValueError('invalid number of shares')

        self.SHARES = shares
        self.PROOFS = num_proofs
        self.flp = flp

        rand_size = shares * self.xof.SEED_SIZE
        if flp.JOINT_RAND_LEN > 0:
            rand_size += shares * self.xof.SEED_SIZE
        self.RAND_SIZE = rand_size

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{prio3-eval-input}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def shard(
            self,
            ctx: bytes,
            measurement: Measurement,
            nonce: bytes,
            rand: bytes) -> tuple[
                Optional[list[bytes]],
                list[Prio3InputShare]]:
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("incorrect size of random bytes argument")

        l = self.xof.SEED_SIZE
        seeds = [rand[i:i + l] for i in range(0, self.RAND_SIZE, l)]

        meas = self.flp.encode(measurement)
        if self.flp.JOINT_RAND_LEN > 0:
            return self.shard_with_joint_rand(ctx, meas, nonce, seeds)
        else:
            return self.shard_without_joint_rand(ctx, meas, seeds)

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{prio3-validity-scope}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def is_valid(
            self,
            _agg_param: None,
            previous_agg_params: list[None]) -> bool:
        return len(previous_agg_params) == 0

    # NOTE: The prep_init(), prep_shares_to_prep(), and prep_next()
    # methods are excerpted in the document, de-indented, as figure
    # {{prio3-prep-state}}. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid
    # warnings from xml2rfc.
    # ===================================================================
    def prep_init(
            self,
            verify_key: bytes,
            ctx: bytes,
            agg_id: int,
            _agg_param: None,
            nonce: bytes,
            public_share: Optional[list[bytes]],
            input_share: Prio3InputShare[F]) -> tuple[
                Prio3PrepState[F],
                Prio3PrepShare[F]]:
        joint_rand_parts = public_share
        (meas_share, proofs_share, blind) = \
            self.expand_input_share(ctx, agg_id, input_share)
        out_share = self.flp.truncate(meas_share)

        # Compute the joint randomness.
        joint_rand: list[F] = []
        corrected_joint_rand_seed, joint_rand_part = None, None
        if self.flp.JOINT_RAND_LEN > 0:
            assert blind is not None
            assert joint_rand_parts is not None
            joint_rand_part = self.joint_rand_part(
                ctx, agg_id, blind, meas_share, nonce)
            joint_rand_parts = list(joint_rand_parts)
            joint_rand_parts[agg_id] = joint_rand_part
            corrected_joint_rand_seed = self.joint_rand_seed(
                ctx, joint_rand_parts)
            joint_rands = self.joint_rands(
                ctx, corrected_joint_rand_seed)

        # Query the measurement and proof(s) share(s).
        query_rands = self.query_rands(verify_key, ctx, nonce)
        verifiers_share = []
        for _ in range(self.PROOFS):
            proof_share, proofs_share = front(
                self.flp.PROOF_LEN, proofs_share)
            query_rand, query_rands = front(
                self.flp.QUERY_RAND_LEN, query_rands)
            if self.flp.JOINT_RAND_LEN > 0:
                joint_rand, joint_rands = front(
                    self.flp.JOINT_RAND_LEN, joint_rands)
            verifiers_share += self.flp.query(
                meas_share,
                proof_share,
                query_rand,
                joint_rand,
                self.SHARES,
            )

        prep_state = (out_share, corrected_joint_rand_seed)
        prep_share = (verifiers_share, joint_rand_part)
        return (prep_state, prep_share)

    def prep_shares_to_prep(
            self,
            ctx: bytes,
            _agg_param: None,
            prep_shares: list[Prio3PrepShare[F]]) -> Optional[bytes]:
        # Unshard each set of verifier shares into each verifier message.
        verifiers = self.flp.field.zeros(
            self.flp.VERIFIER_LEN * self.PROOFS)
        joint_rand_parts = []
        for (verifiers_share, joint_rand_part) in prep_shares:
            verifiers = vec_add(verifiers, verifiers_share)
            if self.flp.JOINT_RAND_LEN > 0:
                assert joint_rand_part is not None
                joint_rand_parts.append(joint_rand_part)

        # Verify that each proof is well-formed and input is valid.
        for _ in range(self.PROOFS):
            verifier, verifiers = front(self.flp.VERIFIER_LEN, verifiers)
            if not self.flp.decide(verifier):
                raise ValueError('proof verifier check failed')

        # Combine the joint randomness parts computed by the
        # Aggregators into the true joint randomness seed. This is
        # used in the last step.
        joint_rand_seed = None
        if self.flp.JOINT_RAND_LEN > 0:
            joint_rand_seed = self.joint_rand_seed(ctx, joint_rand_parts)
        return joint_rand_seed

    def prep_next(
        self,
        _ctx: bytes,
        prep_state: Prio3PrepState[F],
        prep_msg: Optional[bytes]
    ) -> tuple[Prio3PrepState[F], Prio3PrepShare[F]] | list[F]:
        joint_rand_seed = prep_msg
        (out_share, corrected_joint_rand_seed) = prep_state

        # If joint randomness was used, check that the value computed by
        # the Aggregators matches the value indicated by the Client.
        if joint_rand_seed != corrected_joint_rand_seed:
            raise ValueError('joint randomness check failed')

        return out_share

    # NOTE: Methods `agg_init()`, `agg_update()`, and `merge()` are
    # excerpted in the document, de-indented, as figure
    # {{prio3-out2agg}}. The width should be limited to 69 columns after
    # de-indenting, or 73 columns before de-indenting, to avoid warnings
    # from xml2rfc.
    # ===================================================================
    def agg_init(self, _agg_param: None) -> list[F]:
        return self.flp.field.zeros(self.flp.OUTPUT_LEN)

    def agg_update(self,
                   _agg_param: None,
                   agg_share: list[F],
                   out_share: list[F]) -> list[F]:
        return vec_add(agg_share, out_share)

    def merge(self,
              _agg_param: None,
              agg_shares: list[list[F]]) -> list[F]:
        agg = self.agg_init(None)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return agg

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{prio3-agg-output}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def unshard(
            self,
            _agg_param: None,
            agg_shares: list[list[F]],
            num_measurements: int) -> AggResult:
        agg = self.merge(None, agg_shares)
        return self.flp.decode(agg, num_measurements)

    # Auxiliary functions

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{prio3-shard-without-joint-rand}}. Its width should be
    # limited to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def shard_without_joint_rand(
            self,
            ctx: bytes,
            meas: list[F],
            seeds: list[bytes]) -> tuple[
                Optional[list[bytes]],
                list[Prio3InputShare[F]]]:
        helper_shares, seeds = front(self.SHARES - 1, seeds)
        (prove_seed,), seeds = front(1, seeds)

        # Shard the encoded measurement into shares.
        leader_meas_share = meas
        for j in range(self.SHARES - 1):
            leader_meas_share = vec_sub(
                leader_meas_share,
                self.helper_meas_share(ctx, j + 1, helper_shares[j]),
            )

        # Generate and shard each proof into shares.
        prove_rands = self.prove_rands(ctx, prove_seed)
        leader_proofs_share = []
        for _ in range(self.PROOFS):
            prove_rand, prove_rands = front(
                self.flp.PROVE_RAND_LEN, prove_rands)
            leader_proofs_share += self.flp.prove(meas, prove_rand, [])
        for j in range(self.SHARES - 1):
            leader_proofs_share = vec_sub(
                leader_proofs_share,
                self.helper_proofs_share(
                    ctx,
                    j + 1,
                    helper_shares[j],
                ),
            )

        # Each Aggregator's input share contains its measurement share
        # and its share of the proof(s).
        input_shares: list[Prio3InputShare[F]] = []
        input_shares.append((
            leader_meas_share,
            leader_proofs_share,
            None,
        ))
        for j in range(self.SHARES - 1):
            input_shares.append((
                helper_shares[j],
                None,
            ))
        return (None, input_shares)

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{prio3-shard-with-joint-rand}}. Its width should be limited
    # to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def shard_with_joint_rand(
            self,
            ctx: bytes,
            meas: list[F],
            nonce: bytes,
            seeds: list[bytes]) -> tuple[
                Optional[list[bytes]],
                list[Prio3InputShare[F]]]:
        helper_seeds, seeds = front((self.SHARES - 1) * 2, seeds)
        helper_shares = [
            helper_seeds[i]
            for i in range(0, (self.SHARES - 1) * 2, 2)
        ]
        helper_blinds = [
            helper_seeds[i]
            for i in range(1, (self.SHARES - 1) * 2, 2)
        ]
        (leader_blind, prove_seed), seeds = front(2, seeds)

        # Shard the encoded measurement into shares and compute the
        # joint randomness parts.
        leader_meas_share = meas
        joint_rand_parts = []
        for j in range(self.SHARES - 1):
            helper_meas_share = self.helper_meas_share(
                ctx, j + 1, helper_shares[j])
            leader_meas_share = vec_sub(leader_meas_share,
                                        helper_meas_share)
            joint_rand_parts.append(self.joint_rand_part(
                ctx, j + 1, helper_blinds[j],
                helper_meas_share, nonce))
        joint_rand_parts.insert(0, self.joint_rand_part(
            ctx, 0, leader_blind, leader_meas_share, nonce))

        # Generate each proof and shard it into proof shares.
        prove_rands = self.prove_rands(ctx, prove_seed)
        joint_rands = self.joint_rands(
            ctx, self.joint_rand_seed(ctx, joint_rand_parts))
        leader_proofs_share = []
        for _ in range(self.PROOFS):
            prove_rand, prove_rands = front(
                self.flp.PROVE_RAND_LEN, prove_rands)
            joint_rand, joint_rands = front(
                self.flp.JOINT_RAND_LEN, joint_rands)
            leader_proofs_share += self.flp.prove(
                meas,
                prove_rand,
                joint_rand,
            )
        for j in range(self.SHARES - 1):
            leader_proofs_share = vec_sub(
                leader_proofs_share,
                self.helper_proofs_share(
                    ctx,
                    j + 1,
                    helper_shares[j],
                ),
            )

        # Each Aggregator's input share contains its measurement share,
        # share of proof(s), and blind. The public share contains the
        # Aggregators' joint randomness parts.
        input_shares: list[Prio3InputShare[F]] = []
        input_shares.append((
            leader_meas_share,
            leader_proofs_share,
            leader_blind,
        ))
        for j in range(self.SHARES - 1):
            input_shares.append((
                helper_shares[j],
                helper_blinds[j],
            ))
        return (joint_rand_parts, input_shares)

    # NOTE: The helper_meas_share(), helper_proofs_share(),
    # expand_input_share(), prove_rands(), query_rands(),
    # joint_rand_part(), joint_rand_seed(), and joint_rands() methods are
    # excerpted in the document, de-indented. Their width should be
    # limited to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def helper_meas_share(
            self,
            ctx: bytes,
            agg_id: int,
            share: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.flp.field,
            share,
            self.domain_separation_tag(USAGE_MEAS_SHARE, ctx),
            byte(agg_id),
            self.flp.MEAS_LEN,
        )

    def helper_proofs_share(
            self,
            ctx: bytes,
            agg_id: int,
            share: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.flp.field,
            share,
            self.domain_separation_tag(USAGE_PROOF_SHARE, ctx),
            byte(self.PROOFS) + byte(agg_id),
            self.flp.PROOF_LEN * self.PROOFS,
        )

    def expand_input_share(
            self,
            ctx: bytes,
            agg_id: int,
            input_share: Prio3InputShare[F]) -> tuple[
                list[F],
                list[F],
                Optional[bytes]]:
        if agg_id > 0:
            assert len(input_share) == 2
            (share, blind) = input_share
            meas_share = self.helper_meas_share(ctx, agg_id, share)
            proofs_share = self.helper_proofs_share(ctx, agg_id, share)
        else:
            assert len(input_share) == 3
            (meas_share, proofs_share, blind) = input_share
        return (meas_share, proofs_share, blind)

    def prove_rands(self, ctx: bytes, prove_seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.flp.field,
            prove_seed,
            self.domain_separation_tag(USAGE_PROVE_RANDOMNESS, ctx),
            byte(self.PROOFS),
            self.flp.PROVE_RAND_LEN * self.PROOFS,
        )

    def query_rands(
            self,
            verify_key: bytes,
            ctx: bytes,
            nonce: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.flp.field,
            verify_key,
            self.domain_separation_tag(USAGE_QUERY_RANDOMNESS, ctx),
            byte(self.PROOFS) + nonce,
            self.flp.QUERY_RAND_LEN * self.PROOFS,
        )

    def joint_rand_part(
            self,
            ctx: bytes,
            agg_id: int,
            blind: bytes,
            meas_share: list[F],
            nonce: bytes) -> bytes:
        return self.xof.derive_seed(
            blind,
            self.domain_separation_tag(USAGE_JOINT_RAND_PART, ctx),
            byte(agg_id) + nonce + self.flp.field.encode_vec(meas_share),
        )

    def joint_rand_seed(self,
                        ctx: bytes,
                        joint_rand_parts: list[bytes]) -> bytes:
        """Derive the joint randomness seed from its parts."""
        return self.xof.derive_seed(
            zeros(self.xof.SEED_SIZE),
            self.domain_separation_tag(USAGE_JOINT_RAND_SEED, ctx),
            concat(joint_rand_parts),
        )

    def joint_rands(self,
                    ctx: bytes,
                    joint_rand_seed: bytes) -> list[F]:
        """Derive the joint randomness from its seed."""
        return self.xof.expand_into_vec(
            self.flp.field,
            joint_rand_seed,
            self.domain_separation_tag(USAGE_JOINT_RANDOMNESS, ctx),
            byte(self.PROOFS),
            self.flp.JOINT_RAND_LEN * self.PROOFS,
        )

    def encode_agg_param(self, agg_param: None) -> bytes:
        return b""

    def decode_agg_param(self, encoded: bytes) -> None:
        if encoded != b"":
            raise ValueError("invalid encoded aggregation parameter")

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        return self.flp.test_vec_set_type_param(test_vec)

    def encode_input_share(self, input_share: Prio3InputShare[F]) -> bytes:
        encoded = bytes()
        if len(input_share) == 3:  # Leader
            (meas_share, proofs_share, blind) = input_share
            assert len(proofs_share) == self.flp.PROOF_LEN * self.PROOFS
            encoded += self.flp.field.encode_vec(meas_share)
            encoded += self.flp.field.encode_vec(proofs_share)
        elif len(input_share) == 2:  # Helper
            (share, blind) = input_share
            encoded += share
        if blind is not None:  # joint randomness used
            encoded += blind
        return encoded

    def decode_input_share(self, agg_id: int, encoded: bytes) -> Prio3InputShare[F]:
        input_share: Prio3InputShare[F]
        if agg_id == 0:
            meas_bytes, encoded = front(
                self.flp.field.ENCODED_SIZE * self.flp.MEAS_LEN,
                encoded,
            )
            proofs_bytes, encoded = front(
                self.flp.field.ENCODED_SIZE * self.flp.PROOF_LEN * self.PROOFS,
                encoded,
            )
            meas = self.flp.field.decode_vec(meas_bytes)
            proofs = self.flp.field.decode_vec(proofs_bytes)
            if self.flp.JOINT_RAND_LEN > 0:
                blind, encoded = front(self.xof.SEED_SIZE, encoded)
            else:
                blind = None
            input_share = (meas, proofs, blind)
        else:
            share, encoded = front(self.xof.SEED_SIZE, encoded)
            if self.flp.JOINT_RAND_LEN > 0:
                blind, encoded = front(self.xof.SEED_SIZE, encoded)
            else:
                blind = None
            input_share = (share, blind)
        if len(encoded) != 0:
            raise ValueError("input share is too long")
        return input_share

    def encode_public_share(self, public_share: Optional[list[bytes]]) -> bytes:
        joint_rand_parts = public_share
        encoded = bytes()
        if joint_rand_parts is not None:  # joint randomness used
            encoded += concat(joint_rand_parts)
        return encoded

    def decode_public_share(self, encoded: bytes) -> Optional[list[bytes]]:
        if self.flp.JOINT_RAND_LEN == 0:
            return None
        joint_rand_parts = []
        for _ in range(self.SHARES):
            joint_rand_part, encoded = front(self.xof.SEED_SIZE, encoded)
            joint_rand_parts.append(joint_rand_part)
        if len(encoded) != 0:
            raise ValueError("public share is too long")
        return joint_rand_parts

    def encode_agg_share(self, agg_share: list[F]) -> bytes:
        return self.flp.field.encode_vec(agg_share)

    def decode_agg_share(self, _agg_param: None, encoded: bytes) -> list[F]:
        return self.flp.field.decode_vec(encoded)

    def encode_prep_share(self, prep_share: Prio3PrepShare[F]) -> bytes:
        (verifiers_share, joint_rand_part) = prep_share
        encoded = bytes()
        assert len(verifiers_share) == self.flp.VERIFIER_LEN * self.PROOFS
        encoded += self.flp.field.encode_vec(verifiers_share)
        if joint_rand_part is not None:  # joint randomness used
            encoded += joint_rand_part
        return encoded

    def decode_prep_share(self, prep_state: Prio3PrepState[F], encoded: bytes) -> Prio3PrepShare[F]:
        verifiers_share_bytes, encoded = front(
            self.flp.field.ENCODED_SIZE * self.flp.VERIFIER_LEN * self.PROOFS,
            encoded,
        )
        verifiers_share = self.flp.field.decode_vec(verifiers_share_bytes)
        if self.flp.JOINT_RAND_LEN > 0:
            joint_rand_part, encoded = front(self.xof.SEED_SIZE, encoded)
        else:
            joint_rand_part = None
        if len(encoded) != 0:
            raise ValueError("prepare share is too long")
        return (verifiers_share, joint_rand_part)

    def encode_prep_msg(self, prep_message: Optional[bytes]) -> bytes:
        joint_rand_seed = prep_message
        encoded = bytes()
        if joint_rand_seed is not None:  # joint randomness used
            encoded += joint_rand_seed
        return encoded

    def decode_prep_msg(self, _prep_state: Prio3PrepState[F], encoded: bytes) -> Optional[bytes]:
        if len(encoded) == 0:
            return None
        return encoded

    def encode_out_share(self, out_share: list[F]) -> bytes:
        return self.flp.field.encode_vec(out_share)

    def decode_out_share(self, _agg_param: None, encoded: bytes) -> list[F]:
        return self.flp.field.decode_vec(encoded)


##
# INSTANTIATIONS
#

class Prio3Count(Prio3[int, int, Field64]):
    ID = 0x00000001
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3Count'

    def __init__(self, shares: int):
        flp = flp_bbcggi19.FlpBBCGGI19[int, int, Field64](
            flp_bbcggi19.Count(Field64)
        )
        super().__init__(shares, flp, 1)


class Prio3Sum(Prio3[int, int, Field64]):
    ID = 0x00000002
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3Sum'

    def __init__(self, shares: int, max_measurement: int):
        flp = flp_bbcggi19.FlpBBCGGI19[int, int, Field64](
            flp_bbcggi19.Sum(Field64, max_measurement)
        )
        super().__init__(shares, flp, 1)


class Prio3SumVec(Prio3[list[int], list[int], Field128]):
    ID = 0x00000003
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3SumVec'

    def __init__(self, shares: int, length: int, bits: int, chunk_length: int):
        flp = flp_bbcggi19.FlpBBCGGI19[list[int], list[int], Field128](
            flp_bbcggi19.SumVec(Field128, length, bits, chunk_length)
        )
        super().__init__(shares, flp, 1)


class Prio3Histogram(Prio3[int, list[int], Field128]):
    ID = 0x00000004
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3Histogram'

    def __init__(self, shares: int, length: int, chunk_length: int):
        flp = flp_bbcggi19.FlpBBCGGI19[int, list[int], Field128](
            flp_bbcggi19.Histogram(Field128, length, chunk_length)
        )
        super().__init__(shares, flp, 1)


class Prio3SumVecWithMultiproof(Prio3[list[int], list[int], F], Generic[F]):
    """Experimental multiproof variant of Prio3SumVec."""

    ID = 0xFFFFFFFF
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3SumVecWithMultiproof'

    def __init__(
            self,
            shares: int,
            field: type[F],
            num_proofs: int,
            length: int,
            bits: int,
            chunk_length: int):
        flp = flp_bbcggi19.FlpBBCGGI19[list[int], list[int], F](
            flp_bbcggi19.SumVec(
                field,
                length,
                bits,
                chunk_length,
            )
        )
        super().__init__(
            shares,
            flp,
            num_proofs,
        )


class Prio3MultihotCountVec(Prio3[list[bool], list[int], Field128]):
    ID = 0x00000005
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Prio3MultihotCountVec'

    def __init__(
            self,
            shares: int,
            length: int,
            max_weight: int,
            chunk_length: int):
        flp = flp_bbcggi19.FlpBBCGGI19(
            flp_bbcggi19.MultihotCountVec(
                Field128, length, max_weight, chunk_length
            )
        )
        super().__init__(shares, flp, 1)
