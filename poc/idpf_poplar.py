"""An IDPF based on the construction of [BBCGGI21, Section 6]."""

import itertools

import field
from common import format_dst, vec_add, vec_neg, vec_sub, xor
from field import Field2
from idpf import Idpf
from xof import XofFixedKeyAes128


class IdpfPoplar(Idpf):
    """
    An IDPF based on the construction of [BBCGI21, Section 6]. It is identical
    except that the output shares may be tuples rather than single field
    elements. In particular, the value of `VALUE_LEN` may be any positive
    integer.
    """

    # Parameters required by `Vdaf`.
    SHARES = 2
    KEY_SIZE = XofFixedKeyAes128.SEED_SIZE
    RAND_SIZE = 2 * XofFixedKeyAes128.SEED_SIZE
    FieldInner = field.Field64
    FieldLeaf = field.Field255

    # Operational parameters.
    test_vec_name = 'IdpfPoplar'

    @classmethod
    def gen(IdpfPoplar, alpha, beta_inner, beta_leaf, binder, rand):
        if alpha not in range(2**IdpfPoplar.BITS):
            raise ValueError("alpha out of range")
        if len(beta_inner) != IdpfPoplar.BITS - 1:
            raise ValueError("incorrect beta_inner length")
        if len(rand) != IdpfPoplar.RAND_SIZE:
            raise ValueError("incorrect rand size")

        init_seed = [
            rand[:XofFixedKeyAes128.SEED_SIZE],
            rand[XofFixedKeyAes128.SEED_SIZE:],
        ]

        seed = init_seed.copy()
        ctrl = [Field2(0), Field2(1)]
        correction_words = []
        for level in range(IdpfPoplar.BITS):
            Field = IdpfPoplar.current_field(level)
            keep = (alpha >> (IdpfPoplar.BITS - level - 1)) & 1
            lose = 1 - keep
            bit = Field2(keep)

            (s0, t0) = IdpfPoplar.extend(seed[0], binder)
            (s1, t1) = IdpfPoplar.extend(seed[1], binder)
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = (
                t0[0] + t1[0] + bit + Field2(1),
                t0[1] + t1[1] + bit,
            )

            x0 = xor(s0[keep], ctrl[0].conditional_select(seed_cw))
            x1 = xor(s1[keep], ctrl[1].conditional_select(seed_cw))
            (seed[0], w0) = IdpfPoplar.convert(level, x0, binder)
            (seed[1], w1) = IdpfPoplar.convert(level, x1, binder)
            ctrl[0] = t0[keep] + ctrl[0] * ctrl_cw[keep]
            ctrl[1] = t1[keep] + ctrl[1] * ctrl_cw[keep]

            b = beta_inner[level] if level < IdpfPoplar.BITS-1 \
                else beta_leaf
            if len(b) != IdpfPoplar.VALUE_LEN:
                raise ValueError("length of beta must match the value length")

            w_cw = vec_add(vec_sub(b, w0), w1)
            # Implementation note: Here we negate the correction word if
            # the control bit `ctrl[1]` is set. We avoid branching on the
            # value in order to reduce leakage via timing side channels.
            mask = Field(1) - Field(2) * Field(ctrl[1].as_unsigned())
            for i in range(len(w_cw)):
                w_cw[i] *= mask

            correction_words.append((seed_cw, ctrl_cw, w_cw))

        public_share = IdpfPoplar.encode_public_share(correction_words)
        return (public_share, init_seed)

    @classmethod
    def eval(IdpfPoplar, agg_id, public_share, init_seed,
             level, prefixes, binder):
        if agg_id not in range(IdpfPoplar.SHARES):
            raise ValueError('aggregator id out of range')
        if level not in range(IdpfPoplar.BITS):
            raise ValueError('level out of range')
        if len(set(prefixes)) != len(prefixes):
            raise ValueError('prefixes must be unique')

        correction_words = IdpfPoplar.decode_public_share(public_share)
        out_share = []
        for prefix in prefixes:
            if prefix not in range(2**(level+1)):
                raise ValueError('prefix out of range')

            # The Aggregator's output share is the value of a node of
            # the IDPF tree at the given `level`. The node's value is
            # computed by traversing the path defined by the candidate
            # `prefix`. Each node in the tree is represented by a seed
            # (`seed`) and a set of control bits (`ctrl`).
            seed = init_seed
            ctrl = Field2(agg_id)
            for current_level in range(level+1):
                bit = (prefix >> (level - current_level)) & 1

                # Implementation note: Typically the current round of
                # candidate prefixes would have been derived from
                # aggregate results computed during previous rounds. For
                # example, when using `IdpfPoplar` to compute heavy
                # hitters, a string whose hit count exceeded the given
                # threshold in the last round would be the prefix of each
                # `prefix` in the current round. (See [BBCGGI21,
                # Section 5.1].) In this case, part of the path would
                # have already been traversed.
                #
                # Re-computing nodes along previously traversed paths is
                # wasteful. Implementations can eliminate this added
                # complexity by caching nodes (i.e., `(seed, ctrl)`
                # pairs) output by previous calls to `eval_next()`.
                (seed, ctrl, y) = IdpfPoplar.eval_next(
                    seed,
                    ctrl,
                    correction_words[current_level],
                    current_level,
                    bit,
                    binder,
                )
            out_share.append(y if agg_id == 0 else vec_neg(y))
        return out_share

    @classmethod
    def eval_next(IdpfPoplar, prev_seed, prev_ctrl,
                  correction_word, level, bit, binder):
        """
        Compute the next node in the IDPF tree along the path determined by
        a candidate prefix. The next node is determined by `bit`, the bit of
        the prefix corresponding to the next level of the tree.

        TODO Consider implementing some version of the optimization
        discussed at the end of [BBCGGI21, Appendix C.2]. This could on
        average reduce the number of AES calls by a constant factor.
        """

        Field = IdpfPoplar.current_field(level)
        (seed_cw, ctrl_cw, w_cw) = correction_word
        (s, t) = IdpfPoplar.extend(prev_seed, binder)
        s[0] = xor(s[0], prev_ctrl.conditional_select(seed_cw))
        s[1] = xor(s[1], prev_ctrl.conditional_select(seed_cw))
        t[0] += ctrl_cw[0] * prev_ctrl
        t[1] += ctrl_cw[1] * prev_ctrl

        next_ctrl = t[bit]
        (next_seed, y) = IdpfPoplar.convert(level, s[bit], binder)
        # Implementation note: Here we add the correction word to the
        # output if `next_ctrl` is set. We avoid branching on the value of
        # the control bit in order to reduce side channel leakage.
        mask = Field(next_ctrl.as_unsigned())
        for i in range(len(y)):
            y[i] += w_cw[i] * mask

        return (next_seed, next_ctrl, y)

    @classmethod
    def extend(IdpfPoplar, seed, binder):
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 0), binder)
        s = [
            bytearray(xof.next(XofFixedKeyAes128.SEED_SIZE)),
            bytearray(xof.next(XofFixedKeyAes128.SEED_SIZE)),
        ]
        # Use the least significant bits as the control bit correction,
        # and then zero it out. This gives effectively 127 bits of
        # security, but reduces the number of AES calls needed by 1/3.
        t = [Field2(s[0][0] & 1), Field2(s[1][0] & 1)]
        s[0][0] &= 0xFE
        s[1][0] &= 0xFE
        return (s, t)

    @classmethod
    def convert(IdpfPoplar, level, seed, binder):
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 1), binder)
        next_seed = xof.next(XofFixedKeyAes128.SEED_SIZE)
        Field = IdpfPoplar.current_field(level)
        w = xof.next_vec(Field, IdpfPoplar.VALUE_LEN)
        return (next_seed, w)

    @classmethod
    def encode_public_share(IdpfPoplar, correction_words):
        encoded = bytes()
        control_bits = list(itertools.chain.from_iterable(
            cw[1] for cw in correction_words
        ))
        encoded += pack_bits(control_bits)
        for (level, (seed_cw, _, w_cw)) \
                in enumerate(correction_words):
            Field = IdpfPoplar.current_field(level)
            encoded += seed_cw
            encoded += Field.encode_vec(w_cw)
        return encoded

    @classmethod
    def decode_public_share(IdpfPoplar, encoded):
        l = (2*IdpfPoplar.BITS + 7) // 8
        encoded_ctrl, encoded = encoded[:l], encoded[l:]
        control_bits = unpack_bits(encoded_ctrl, 2 * IdpfPoplar.BITS)
        correction_words = []
        for level in range(IdpfPoplar.BITS):
            Field = IdpfPoplar.current_field(level)
            ctrl_cw = (
                control_bits[level * 2],
                control_bits[level * 2 + 1],
            )
            l = XofFixedKeyAes128.SEED_SIZE
            seed_cw, encoded = encoded[:l], encoded[l:]
            l = Field.ENCODED_SIZE * IdpfPoplar.VALUE_LEN
            encoded_w_cw, encoded = encoded[:l], encoded[l:]
            w_cw = Field.decode_vec(encoded_w_cw)
            correction_words.append((seed_cw, ctrl_cw, w_cw))
        if len(encoded) != 0:
            raise ValueError('trailing bytes')
        return correction_words

    @classmethod
    def with_bits(cls, bits: int):
        """
        Set `BITS`.

        Pre-conditions:

            - `bits > 0`
        """
        assert bits > 0

        class IdpfPoplarWithBits(cls):
            BITS = bits
        return IdpfPoplarWithBits

    @classmethod
    def with_value_len(cls, value_len):
        """
        Set `VALUE_LEN`.

        Pre-conditions:

            - `value_len > 0`
        """
        assert value_len > 0

        class IdpfPoplarWithValueLen(cls):
            VALUE_LEN = value_len
        return IdpfPoplarWithValueLen


def pack_bits(bits: list[Field2]) -> bytes:
    byte_len = (len(bits) + 7) // 8
    packed = [int(0)] * byte_len
    for i, bit in enumerate(bits):
        packed[i // 8] |= bit.as_unsigned() << (i % 8)
    return bytes(packed)


def unpack_bits(packed: bytes, length: int) -> list[Field2]:
    bits = []
    for i in range(length):
        bits.append(Field2(
            (packed[i // 8] >> (i % 8)) & 1
        ))
    leftover_bits = packed[-1] >> (
        (length + 7) % 8 + 1
    )
    if (length + 7) // 8 != len(packed) or leftover_bits != 0:
        raise ValueError('trailing bits')
    return bits
