# An IDPF based on the construction of [BBCGGI21, Section 6].

from copy import deepcopy
from sagelib.common import ERR_DECODE, ERR_INPUT, I2OSP, OS2IP, VERSION, \
                           Bytes, Error, Unsigned, Vec, byte, gen_rand, \
                           vec_add, vec_neg, vec_sub, xor
from sagelib.field import Field2
from sagelib.idpf import Idpf, test_idpf, test_idpf_exhaustive
import sagelib.field as field
import sagelib.prg as prg


# An IDPF based on the construction of [BBCGI21, Section 6]. It is identical
# except that the output shares may be tuples rather than single field elements.
# In particular, the value of `VALUE_LEN` may be any positive integer.
class IdpfPoplar(Idpf):
    # Generic parameters set by a concrete instance of this IDPF.
    Prg: prg.Prg = None

    # Parameters required by `Vdaf`.
    SHARES = 2
    FieldInner = field.Field64
    FieldLeaf = field.Field255

    @classmethod
    def gen(IpdfPoplar, alpha, beta_inner, beta_leaf):
        if alpha >= 2^IdpfPoplar.BITS:
            raise ERR_INPUT # alpha too long
        if len(beta_inner) != IdpfPoplar.BITS - 1:
            raise ERR_INPUT # beta_inner vector is the wrong size

        init_seed = [
            gen_rand(IdpfPoplar.Prg.SEED_SIZE),
            gen_rand(IdpfPoplar.Prg.SEED_SIZE),
        ]

        seed = init_seed.copy()
        ctrl = [Field2(0), Field2(1)]
        correction_words = []
        for level in range(IdpfPoplar.BITS):
            keep = (alpha >> (IdpfPoplar.BITS - level - 1)) & 1
            lose = 1 - keep
            bit = Field2(keep)

            (s0, t0) = IdpfPoplar.extend(seed[0])
            (s1, t1) = IdpfPoplar.extend(seed[1])
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = (
                t0[0] + t1[0] + bit + Field2(1),
                t0[1] + t1[1] + bit,
            )

            x0 = xor(s0[keep], seed_cw) if ctrl[0] == Field2(1) \
                    else s0[keep]
            x1 = xor(s1[keep], seed_cw) if ctrl[1] == Field2(1) \
                    else s1[keep]
            (seed[0], w0) = IdpfPoplar.convert(level, x0)
            (seed[1], w1) = IdpfPoplar.convert(level, x1)
            ctrl[0] = t0[keep] + ctrl[0] * ctrl_cw[keep]
            ctrl[1] = t1[keep] + ctrl[1] * ctrl_cw[keep]

            b = beta_inner[level] if level < IdpfPoplar.BITS-1 \
                    else beta_leaf
            if len(b) != IdpfPoplar.VALUE_LEN:
                raise ERR_INPUT # beta too long or too short

            w_cw = vec_add(vec_sub(b, w0), w1)
            if ctrl[1] == Field2(1):
                w_cw = vec_neg(w_cw)
            correction_words.append((seed_cw, ctrl_cw, w_cw))

        public_share = IdpfPoplar.encode_public_share(correction_words)
        return (public_share, init_seed)

    @classmethod
    def eval(IdpfPoplar, agg_id, public_share, init_seed,
             level, prefixes):
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
                    correction_words[current_level], current_level, bit)
            out_share.append(y if agg_id == 0 else vec_neg(y))
        return out_share

    # Compute the next node in the IDPF tree along the path determined by
    # a candidiate prefix. The next node is determined by `bit`, the bit
    # of the prefix corresponding to the next level of the tree.
    #
    # TODO Consider implementing some version of the optimization
    # discussed at the end of [BBCGGI21, Appendix C.2]. This could on
    # average reduce the number of AES calls by a constant factor.
    @classmethod
    def eval_next(IdpfPoplar, prev_seed, prev_ctrl,
                  correction_word, level, bit):
        (seed_cw, ctrl_cw, w_cw) = correction_word
        (s, t) = IdpfPoplar.extend(prev_seed)
        if prev_ctrl == Field2(1):
            s[0] = xor(s[0], seed_cw)
            s[1] = xor(s[1], seed_cw)
            t[0] = t[0] + ctrl_cw[0]
            t[1] = t[1] + ctrl_cw[1]

        next_ctrl = t[bit]
        (next_seed, y) = IdpfPoplar.convert(level, s[bit])
        if next_ctrl == Field2(1):
            y = vec_add(y, w_cw)
        return (next_seed, next_ctrl, y)

    @classmethod
    def extend(IdpfPoplar, seed):
        dst = VERSION + b' idpf poplar extend'
        prg = IdpfPoplar.Prg(seed, dst)
        s = [
            prg.next(IdpfPoplar.Prg.SEED_SIZE),
            prg.next(IdpfPoplar.Prg.SEED_SIZE),
        ]
        b = OS2IP(prg.next(1))
        t = [Field2(b & 1), Field2((b >> 1) & 1)]
        return (s, t)

    @classmethod
    def convert(IdpfPoplar, level, seed):
        dst = VERSION + b' idpf poplar convert'
        prg = IdpfPoplar.Prg(seed, dst)
        next_seed = prg.next(IdpfPoplar.Prg.SEED_SIZE)
        Field = IdpfPoplar.current_field(level)
        w = prg.next_vec(Field, IdpfPoplar.VALUE_LEN)
        return (next_seed, w)

    @classmethod
    def encode_public_share(IdpfPoplar, correction_words):
        encoded = Bytes()
        packed_ctrl = 0
        for (level, (_, ctrl_cw, _)) \
            in enumerate(correction_words):
            packed_ctrl |= ctrl_cw[0].as_unsigned() << (2*level)
            packed_ctrl |= ctrl_cw[1].as_unsigned() << (2*level+1)
        l = floor((2*IdpfPoplar.BITS + 7) / 8)
        encoded += I2OSP(packed_ctrl, l)
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
        packed_ctrl = OS2IP(encoded_ctrl)
        correction_words = []
        for level in range(IdpfPoplar.BITS):
            Field = IdpfPoplar.current_field(level)
            ctrl_cw = (Field2(packed_ctrl & 1),
                       Field2((packed_ctrl >> 1) & 1))
            packed_ctrl >>= 2
            l = IdpfPoplar.Prg.SEED_SIZE
            seed_cw, encoded = encoded[:l], encoded[l:]
            l = Field.ENCODED_SIZE * IdpfPoplar.VALUE_LEN
            encoded_w_cw, encoded = encoded[:l], encoded[l:]
            w_cw = Field.decode_vec(encoded_w_cw)
            correction_words.append((seed_cw, ctrl_cw, w_cw))
        if len(encoded) != 0:
            raise ERR_DECODE
        return correction_words

    @classmethod
    def with_prg(IdpfPoplar, Prg):
        new_cls = deepcopy(IdpfPoplar)
        new_cls.Prg = Prg
        new_cls.KEY_SIZE = Prg.SEED_SIZE
        return new_cls

    @classmethod
    def with_bits(IdpfPoplar, bits: Unsigned):
        if bits == 0:
            raise ERR_INPUT # number of bits must be positive
        new_cls = deepcopy(IdpfPoplar)
        new_cls.BITS = bits
        return new_cls

    @classmethod
    def with_value_len(IdpfPoplar, value_len: Unsigned):
        if value_len == 0:
            raise ERR_INPUT # value length must be positive
        new_cls = deepcopy(IdpfPoplar)
        new_cls.VALUE_LEN = value_len
        return new_cls


if __name__ == '__main__':
    cls = IdpfPoplar \
                .with_prg(prg.PrgAes128) \
                .with_value_len(2)
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
