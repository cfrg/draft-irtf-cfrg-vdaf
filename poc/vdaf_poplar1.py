"""The Poplar1 VDAF."""

from __future__ import annotations

from typing import Optional

import idpf
import idpf_poplar
import xof
from common import (ERR_INPUT, ERR_VERIFY, Bytes, Unsigned, byte,
                    from_be_bytes, front, to_be_bytes, vec_add, vec_sub)
from vdaf import Vdaf

USAGE_SHARD_RAND = 1
USAGE_CORR_INNER = 2
USAGE_CORR_LEAF = 3
USAGE_VERIFY_RAND = 4


class Poplar1(Vdaf):
    # Types provided by a concrete instadce of `Poplar1`.
    Idpf = idpf.Idpf
    Xof = xof.Xof

    # Parameters required by `Vdaf`.
    ID = 0x00001000
    VERIFY_KEY_SIZE = None  # Set by Idpf.Xof
    RAND_SIZE = None  # Set by Idpf.Xof
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 2

    # Types required by `Vdaf`.
    Measurement = Unsigned
    AggParam = tuple[Unsigned, tuple[Unsigned, ...]]
    PublicShare = bytes  # IDPF public share
    InputShare = tuple[
        bytes,                  # IDPF key
        bytes,                  # corr seed
        list[Idpf.FieldInner],  # inner corr randomness
        list[Idpf.FieldLeaf],   # leaf corr randomness
    ]
    OutShare = Idpf.FieldVec
    AggShare = Idpf.FieldVec
    AggResult = list[Unsigned]
    PrepState = tuple[bytes,          # sketch round
                      Idpf.FieldVec]  # output (and sketch) share
    PrepShare = Idpf.FieldVec
    PrepMessage = Optional[Idpf.FieldVec]

    # Operational parameters.
    test_vec_name = 'Poplar1'

    @classmethod
    def shard(Poplar1, measurement, nonce, rand):
        l = Poplar1.Xof.SEED_SIZE

        # Split the random input into the random input for IDPF key
        # generation, correlated randomness, and sharding.
        if len(rand) != Poplar1.RAND_SIZE:
            raise ERR_INPUT  # unexpected length for random input
        idpf_rand, rand = front(Poplar1.Idpf.RAND_SIZE, rand)
        seeds = [rand[i:i+l] for i in range(0, 3*l, l)]
        corr_seed, seeds = front(2, seeds)
        (k_shard,), seeds = front(1, seeds)

        xof = Poplar1.Xof(
            k_shard,
            Poplar1.domain_separation_tag(USAGE_SHARD_RAND),
            nonce,
        )

        # Construct the IDPF values for each level of the IDPF tree.
        # Each "data" value is 1; in addition, the Client generates
        # a random "authenticator" value used by the Aggregators to
        # compute the sketch during preparation. This sketch is used
        # to verify the one-hotness of their output shares.
        beta_inner = [
            [Poplar1.Idpf.FieldInner(1), k]
            for k in xof.next_vec(Poplar1.Idpf.FieldInner,
                                  Poplar1.Idpf.BITS - 1)
        ]
        beta_leaf = [Poplar1.Idpf.FieldLeaf(1)] + \
            xof.next_vec(Poplar1.Idpf.FieldLeaf, 1)

        # Generate the IDPF keys.
        (public_share, keys) = Poplar1.Idpf.gen(measurement,
                                                beta_inner,
                                                beta_leaf,
                                                nonce,
                                                idpf_rand)

        # Generate correlated randomness used by the Aggregators to
        # compute a sketch over their output shares. Seeds are used to
        # encode shares of the `(a, b, c)` triples. (See [BBCGGI21,
        # Appendix C.4].)
        corr_offsets = vec_add(
            Poplar1.Xof.expand_into_vec(
                Poplar1.Idpf.FieldInner,
                corr_seed[0],
                Poplar1.domain_separation_tag(USAGE_CORR_INNER),
                byte(0) + nonce,
                3 * (Poplar1.Idpf.BITS-1),
            ),
            Poplar1.Xof.expand_into_vec(
                Poplar1.Idpf.FieldInner,
                corr_seed[1],
                Poplar1.domain_separation_tag(USAGE_CORR_INNER),
                byte(1) + nonce,
                3 * (Poplar1.Idpf.BITS-1),
            ),
        )
        corr_offsets += vec_add(
            Poplar1.Xof.expand_into_vec(
                Poplar1.Idpf.FieldLeaf,
                corr_seed[0],
                Poplar1.domain_separation_tag(USAGE_CORR_LEAF),
                byte(0) + nonce,
                3,
            ),
            Poplar1.Xof.expand_into_vec(
                Poplar1.Idpf.FieldLeaf,
                corr_seed[1],
                Poplar1.domain_separation_tag(USAGE_CORR_LEAF),
                byte(1) + nonce,
                3,
            ),
        )

        # For each level of the IDPF tree, shares of the `(A, B)`
        # pairs are computed from the corresponding `(a, b, c)`
        # triple and authenticator value `k`.
        corr_inner = [[], []]
        for level in range(Poplar1.Idpf.BITS):
            Field = Poplar1.Idpf.current_field(level)
            k = beta_inner[level][1] if level < Poplar1.Idpf.BITS - 1 \
                else beta_leaf[1]
            (a, b, c), corr_offsets = corr_offsets[:3], corr_offsets[3:]
            A = -Field(2) * a + k
            B = a ** 2 + b - a * k + c
            corr1 = xof.next_vec(Field, 2)
            corr0 = vec_sub([A, B], corr1)
            if level < Poplar1.Idpf.BITS - 1:
                corr_inner[0] += corr0
                corr_inner[1] += corr1
            else:
                corr_leaf = [corr0, corr1]

        # Each input share consists of the Aggregator's IDPF key
        # and a share of the correlated randomness.
        input_shares = list(zip(keys, corr_seed, corr_inner, corr_leaf))
        return (public_share, input_shares)

    @classmethod
    def is_valid(Poplar1, agg_param, previous_agg_params):
        """
        Checks that levels are increasing between calls, and also enforces that
        the prefixes at each level are suffixes of the previous level's
        prefixes.
        """
        if len(previous_agg_params) < 1:
            return True

        (level, prefixes) = agg_param
        (last_level, last_prefixes) = previous_agg_params[-1]
        # The empty prefix 0 is always there.
        last_prefixes_set = set(list(last_prefixes))

        # Check that level increased.
        if level <= last_level:
            return False

        # Check that prefixes are suffixes of the last level's prefixes,
        # unless the last level was 0 (and therefore had no prefixes).
        if last_level > 0:
            for (i, prefix) in enumerate(prefixes):
                last_prefix = Poplar1.get_ancestor(prefix, level, last_level)
                if last_prefix not in last_prefixes_set:
                    # Current prefix not a suffix of last level's prefixes.
                    return False
        return True

    @classmethod
    def prep_init(Poplar1, verify_key, agg_id, agg_param,
                  nonce, public_share, input_share):
        (level, prefixes) = agg_param
        (key, corr_seed, corr_inner, corr_leaf) = input_share
        Field = Poplar1.Idpf.current_field(level)

        # Ensure that candidate prefixes are all unique and appear in
        # lexicographic order.
        for i in range(1, len(prefixes)):
            if prefixes[i-1] >= prefixes[i]:
                raise ERR_INPUT  # out-of-order prefix

        # Evaluate the IDPF key at the given set of prefixes.
        value = Poplar1.Idpf.eval(
            agg_id, public_share, key, level, prefixes, nonce)

        # Get shares of the correlated randomness for computing the
        # Aggregator's share of the sketch for the given level of the IDPF
        # tree.
        if level < Poplar1.Idpf.BITS - 1:
            corr_xof = Poplar1.Xof(
                corr_seed,
                Poplar1.domain_separation_tag(USAGE_CORR_INNER),
                byte(agg_id) + nonce,
            )
            # Fast-forward the XOF state to the current level.
            corr_xof.next_vec(Field, 3 * level)
        else:
            corr_xof = Poplar1.Xof(
                corr_seed,
                Poplar1.domain_separation_tag(USAGE_CORR_LEAF),
                byte(agg_id) + nonce,
            )
        (a_share, b_share, c_share) = corr_xof.next_vec(Field, 3)
        (A_share, B_share) = corr_inner[2*level:2*(level+1)] \
            if level < Poplar1.Idpf.BITS - 1 else corr_leaf

        # Compute the Aggregator's first round of the sketch. These are
        # called the "masked input values" [BBCGGI21, Appendix C.4].
        verify_rand_xof = Poplar1.Xof(
            verify_key,
            Poplar1.domain_separation_tag(USAGE_VERIFY_RAND),
            nonce + to_be_bytes(level, 2),
        )
        verify_rand = verify_rand_xof.next_vec(Field, len(prefixes))
        sketch_share = [a_share, b_share, c_share]
        out_share = []
        for (i, r) in enumerate(verify_rand):
            [data_share, auth_share] = value[i]
            sketch_share[0] += data_share * r
            sketch_share[1] += data_share * r ** 2
            sketch_share[2] += auth_share * r
            out_share.append(data_share)

        prep_mem = [A_share, B_share, Field(agg_id)] + out_share
        return ((b'sketch round 1', level, prep_mem),
                sketch_share)

    @classmethod
    def prep_next(Poplar1, prep_state, prep_msg):
        prev_sketch = prep_msg
        (step, level, prep_mem) = prep_state
        Field = Poplar1.Idpf.current_field(level)

        if step == b'sketch round 1':
            if prev_sketch == None:
                prev_sketch = Field.zeros(3)
            elif len(prev_sketch) != 3:
                raise ERR_INPUT  # prep message malformed
            (A_share, B_share, agg_id), prep_mem = \
                prep_mem[:3], prep_mem[3:]
            sketch_share = [
                agg_id * (prev_sketch[0] ** 2
                          - prev_sketch[1]
                          - prev_sketch[2])
                + A_share * prev_sketch[0]
                + B_share
            ]
            return ((b'sketch round 2', level, prep_mem),
                    sketch_share)

        elif step == b'sketch round 2':
            if prev_sketch == None:
                return prep_mem  # Output shares
            else:
                raise ERR_INPUT  # prep message malformed

        raise ERR_INPUT  # unexpected input

    @classmethod
    def prep_shares_to_prep(Poplar1, agg_param, prep_shares):
        if len(prep_shares) != 2:
            raise ERR_INPUT  # unexpected number of prep shares
        (level, _) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        sketch = vec_add(prep_shares[0], prep_shares[1])
        if len(sketch) == 3:
            return sketch
        elif len(sketch) == 1:
            if sketch == Field.zeros(1):
                # In order to reduce communication overhead, let `None`
                # denote a successful sketch verification.
                return None
            else:
                raise ERR_VERIFY  # sketch verification failed
        else:
            raise ERR_INPUT  # unexpected input length

    @classmethod
    def aggregate(Poplar1, agg_param, out_shares):
        (level, prefixes) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        agg_share = Field.zeros(len(prefixes))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    @classmethod
    def unshard(Poplar1, agg_param,
                agg_shares, _num_measurements):
        (level, prefixes) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        agg = Field.zeros(len(prefixes))
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return list(map(lambda x: x.as_unsigned(), agg))

    @classmethod
    def encode_agg_param(Poplar1, level, prefixes):
        if level > 2 ** 16 - 1:
            raise ERR_INPUT  # level too deep
        if len(prefixes) > 2 ** 32 - 1:
            raise ERR_INPUT  # too many prefixes
        encoded = Bytes()
        encoded += to_be_bytes(level, 2)
        encoded += to_be_bytes(len(prefixes), 4)
        packed = 0
        for (i, prefix) in enumerate(prefixes):
            packed |= prefix << ((level+1) * i)
        l = ((level+1) * len(prefixes) + 7) // 8
        encoded += to_be_bytes(packed, l)
        return encoded

    @classmethod
    def decode_agg_param(Poplar1, encoded):
        encoded_level, encoded = encoded[:2], encoded[2:]
        level = from_be_bytes(encoded_level)
        encoded_prefix_count, encoded = encoded[:4], encoded[4:]
        prefix_count = from_be_bytes(encoded_prefix_count)
        l = ((level+1) * prefix_count + 7) // 8
        encoded_packed, encoded = encoded[:l], encoded[l:]
        packed = from_be_bytes(encoded_packed)
        prefixes = []
        m = 2 ** (level+1) - 1
        for i in range(prefix_count):
            prefixes.append(packed >> ((level+1) * i) & m)
        if len(encoded) != 0:
            raise ERR_INPUT
        return (level, tuple(prefixes))

    @classmethod
    def with_bits(Poplar1, bits: Unsigned):
        TheIdpf = idpf_poplar.IdpfPoplar \
            .with_value_len(2) \
            .with_bits(bits)
        TheXof = xof.XofTurboShake128

        class Poplar1WithBits(Poplar1):
            Idpf = TheIdpf
            Xof = TheXof
            VERIFY_KEY_SIZE = TheXof.SEED_SIZE
            RAND_SIZE = 3*TheXof.SEED_SIZE + TheIdpf.RAND_SIZE
            test_vec_name = 'Poplar1'
        return Poplar1WithBits

    @classmethod
    def test_vec_set_type_param(cls, test_vec):
        test_vec['bits'] = int(cls.Idpf.BITS)
        return ['bits']

    @classmethod
    def test_vec_encode_input_share(Poplar1, input_share):
        (key, seed, inner, leaf) = input_share
        encoded = bytes()
        encoded += key
        encoded += seed
        encoded += Poplar1.Idpf.FieldInner.encode_vec(inner)
        encoded += Poplar1.Idpf.FieldLeaf.encode_vec(leaf)
        return encoded

    @classmethod
    def test_vec_encode_public_share(Poplar1, public_share):
        return public_share

    @classmethod
    def test_vec_encode_agg_share(Poplar1, agg_share):
        return encode_idpf_field_vec(agg_share)

    @classmethod
    def test_vec_encode_prep_share(Poplar1, prep_share):
        return encode_idpf_field_vec(prep_share)

    @classmethod
    def test_vec_encode_prep_msg(Poplar1, prep_message):
        if prep_message != None:
            return encode_idpf_field_vec(prep_message)
        return b''


def encode_idpf_field_vec(vec):
    encoded = bytes()
    if len(vec) > 0:
        Field = vec[0].__class__
        encoded += Field.encode_vec(vec)
    return encoded


def get_ancestor(input, this_level, last_level):
    """
    Helper function to determine the prefix of `input` at `last_level`.
    """
    return input >> (this_level - last_level)