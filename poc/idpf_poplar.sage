# An IDPF based on the construction of [BBCGGI21, Section 6].

import itertools
from sagelib.common import \
    ERR_DECODE, \
    ERR_INPUT, \
    TEST_VECTOR, \
    VERSION, \
    Bytes, \
    Error, \
    Unsigned, \
    Vec, \
    byte, \
    format_custom, \
    vec_add, \
    vec_neg, \
    vec_sub, \
    xor
from sagelib.field import Field2
from sagelib.idpf import Idpf, gen_test_vec, test_idpf, test_idpf_exhaustive
import sagelib.field as field
from sagelib.prg import PrgFixedKeyAes128


# An IDPF based on the construction of [BBCGI21, Section 6]. It is identical
# except that the output shares may be tuples rather than single field elements.
# In particular, the value of `VALUE_LEN` may be any positive integer.
class IdpfPoplar(Idpf):
    # Parameters required by `Vdaf`.
    SHARES = 2
    KEY_SIZE = PrgFixedKeyAes128.SEED_SIZE
    RAND_SIZE = 2 * PrgFixedKeyAes128.SEED_SIZE
    FieldInner = field.Field64
    FieldLeaf = field.Field255

    # Operational parameters.
    test_vec_name = 'IdpfPoplar'

    @classmethod
    def gen(IdpfPoplar, alpha, beta_inner, beta_leaf, binder, rand):
        if alpha >= 2^IdpfPoplar.BITS:
            raise ERR_INPUT # alpha too long
        if len(beta_inner) != IdpfPoplar.BITS - 1:
            raise ERR_INPUT # beta_inner vector is the wrong size
        if len(rand) != IdpfPoplar.RAND_SIZE:
            raise ERR_INPUT # unexpected length for random coins

        init_seed = [
            rand[:PrgFixedKeyAes128.SEED_SIZE],
            rand[PrgFixedKeyAes128.SEED_SIZE:],
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
                raise ERR_INPUT # beta too long or too short

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
        if agg_id >= IdpfPoplar.SHARES:
            raise ERR_INPUT # invalid aggregator ID
        if level >= IdpfPoplar.BITS:
            raise ERR_INPUT # level too deep
        if len(set(prefixes)) != len(prefixes):
            raise ERR_INPUT # candidate prefixes are non-unique

        correction_words = IdpfPoplar.decode_public_share(public_share)
        out_share = []
        for prefix in prefixes:
            if prefix >= 2^(level+1):
                raise ERR_INPUT # prefix too long

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
                (seed, ctrl, y) = IdpfPoplar.eval_next(seed, ctrl,
                    correction_words[current_level], current_level, bit, binder)
            out_share.append(y if agg_id == 0 else vec_neg(y))
        return out_share

    # Compute the next node in the IDPF tree along the path determined by
    # a candidate prefix. The next node is determined by `bit`, the bit
    # of the prefix corresponding to the next level of the tree.
    #
    # TODO Consider implementing some version of the optimization
    # discussed at the end of [BBCGGI21, Appendix C.2]. This could on
    # average reduce the number of AES calls by a constant factor.
    @classmethod
    def eval_next(IdpfPoplar, prev_seed, prev_ctrl,
                  correction_word, level, bit, binder):
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
        prg = PrgFixedKeyAes128(seed, format_custom(1, 0, 0), binder)
        s = [
            prg.next(PrgFixedKeyAes128.SEED_SIZE),
            prg.next(PrgFixedKeyAes128.SEED_SIZE),
        ]
        b = prg.next(1)[0]
        t = [Field2(b & 1), Field2((b >> 1) & 1)]
        return (s, t)

    @classmethod
    def convert(IdpfPoplar, level, seed, binder):
        prg = PrgFixedKeyAes128(seed, format_custom(1, 0, 1), binder)
        next_seed = prg.next(PrgFixedKeyAes128.SEED_SIZE)
        Field = IdpfPoplar.current_field(level)
        w = prg.next_vec(Field, IdpfPoplar.VALUE_LEN)
        return (next_seed, w)

    @classmethod
    def encode_public_share(IdpfPoplar, correction_words):
        encoded = Bytes()
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
        l = floor((2*IdpfPoplar.BITS + 7) / 8)
        encoded_ctrl, encoded = encoded[:l], encoded[l:]
        control_bits = unpack_bits(encoded_ctrl, 2 * IdpfPoplar.BITS)
        correction_words = []
        for level in range(IdpfPoplar.BITS):
            Field = IdpfPoplar.current_field(level)
            ctrl_cw = (
                control_bits[level * 2],
                control_bits[level * 2 + 1],
            )
            l = PrgFixedKeyAes128.SEED_SIZE
            seed_cw, encoded = encoded[:l], encoded[l:]
            l = Field.ENCODED_SIZE * IdpfPoplar.VALUE_LEN
            encoded_w_cw, encoded = encoded[:l], encoded[l:]
            w_cw = Field.decode_vec(encoded_w_cw)
            correction_words.append((seed_cw, ctrl_cw, w_cw))
        if len(encoded) != 0:
            raise ERR_DECODE
        return correction_words

    @classmethod
    def with_bits(IdpfPoplar, bits: Unsigned):
        if bits == 0:
            raise ERR_INPUT # number of bits must be positive
        class IdpfPoplarWithBits(IdpfPoplar):
            BITS = bits
        return IdpfPoplarWithBits

    @classmethod
    def with_value_len(IdpfPoplar, value_len: Unsigned):
        if value_len == 0:
            raise ERR_INPUT # value length must be positive
        class IdpfPoplarWithValueLen(IdpfPoplar):
            VALUE_LEN = value_len
        return IdpfPoplarWithValueLen


def pack_bits(bits: Vec[Field2]) -> Bytes:
    byte_len = (len(bits) + 7) // 8
    packed = [int(0)] * byte_len
    for i, bit in enumerate(bits):
        packed[i // 8] |= bit.as_unsigned() << (i % 8)
    return Bytes(packed)


def unpack_bits(packed_bits: Bytes, length: Unsigned) -> Vec[Field2]:
    bits = []
    for i in range(length):
        bits.append(Field2(
            (packed_bits[i // 8] >> (i % 8)) & 1
        ))
    leftover_bits = packed_bits[-1] >> (
        (length + 7) % 8 + 1
    )
    if (length + 7) // 8 != len(packed_bits) or leftover_bits != 0:
        raise ERR_DECODE
    return bits


if __name__ == '__main__':
    cls = IdpfPoplar \
                .with_value_len(2)
    if TEST_VECTOR:
        gen_test_vec(cls.with_bits(10), 0, 0)
    test_idpf(cls.with_bits(16), 0b1111000011110000, 15, [0b1111000011110000])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 14, [0b111100001111000])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 13, [0b11110000111100])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 12, [0b1111000011110])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 11, [0b111100001111])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 10, [0b11110000111])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 5, [0b111100])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 4, [0b11110])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 3, [0b1111])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 2, [0b111])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 1, [0b11])
    test_idpf(cls.with_bits(16), 0b1111000011110000, 0, [0b1])
    test_idpf(cls.with_bits(1000), 0, 999, [0])
    test_idpf_exhaustive(cls.with_bits(1), 0)
    test_idpf_exhaustive(cls.with_bits(1), 1)
    test_idpf_exhaustive(cls.with_bits(8), 91)
