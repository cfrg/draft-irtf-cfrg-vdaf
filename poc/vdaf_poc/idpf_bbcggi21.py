"""The IDPF of {{BBCGGI21}}, Section 6."""

import itertools
from typing import Sequence, TypeAlias, cast

from vdaf_poc.common import format_dst, vec_add, vec_neg, vec_sub, xor
from vdaf_poc.field import Field, Field2, Field64, Field255
from vdaf_poc.idpf import Idpf
from vdaf_poc.xof import Xof, XofFixedKeyAes128, XofTurboShake128

# This file, and vdaf_poplar1.py, make extensive use of `typing.cast()`. This
# acts like the identity function at runtime. During static analysis, it gives
# us an escape hatch to override the results of type inference. Static analysis
# tools will ignore the type of the value that is passed in, and instead assume
# that the output of `cast()` has the type given in the first argument.
#
# This is necessary primarily because we have many unions of `Field64` and
# `Field255`, instances of those classes, or lists thereof. Without the casts,
# we would get warnings on arithmetic between objects of such union types,
# because `mypy`'s analysis conservatively assumes that we could have objects
# of different field classes on either side (though that doesn't happen in
# practice). Casting unions of specific fields to their superclass avoids such
# errors, and then casting back to union types lets us keep precise return
# types, which aids with self-documentation.

FieldVec: TypeAlias = list[Field64] | list[Field255]
CorrectionWord: TypeAlias = tuple[bytes, tuple[Field2, Field2], FieldVec]


class IdpfBBCGGI21(Idpf[Field64, Field255, list[CorrectionWord]]):
    """
    The IDPF of {{BBCGGI21}}, Section 6. It is identical except that the output
    shares may be tuples rather than single field elements. In particular, the
    value of `VALUE_LEN` may be any positive integer.
    """

    SHARES = 2
    KEY_SIZE = XofFixedKeyAes128.SEED_SIZE
    RAND_SIZE = 2 * XofFixedKeyAes128.SEED_SIZE
    NONCE_SIZE = XofFixedKeyAes128.SEED_SIZE
    field_inner = Field64
    field_leaf = Field255

    # Name of the IDPF, for use in test vector filenames.
    test_vec_name = 'IdpfBBCGGI21'

    def __init__(self, value_len: int, bits: int):
        """
        Construct the IDPF with the given parameters.

        Arguments:
        value_len -- The length of field element vectors output from the IDPF
        bits -- the length of bit strings that the IDPF accepts as inputs

        Preconditions:
        `value > 0`
        `bits > 0`
        """
        assert value_len > 0
        assert bits > 0
        self.VALUE_LEN = value_len
        self.BITS = bits

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{idpf-poplar-gen}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def gen(
            self,
            alpha: int,
            beta_inner: list[list[Field64]],
            beta_leaf: list[Field255],
            nonce: bytes,
            rand: bytes) -> tuple[list[CorrectionWord], list[bytes]]:
        if alpha not in range(2 ** self.BITS):
            raise ValueError("alpha out of range")
        if len(beta_inner) != self.BITS - 1:
            raise ValueError("incorrect beta_inner length")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("incorrect rand size")
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")

        key = [
            rand[:XofFixedKeyAes128.SEED_SIZE],
            rand[XofFixedKeyAes128.SEED_SIZE:],
        ]

        seed = key.copy()
        ctrl = [Field2(0), Field2(1)]
        public_share = []
        for level in range(self.BITS):
            field: type[Field]
            field = cast(type[Field], self.current_field(level))
            keep = (alpha >> (self.BITS - level - 1)) & 1
            lose = 1 - keep
            bit = Field2(keep)

            (s0, t0) = self.extend(level, seed[0], nonce)
            (s1, t1) = self.extend(level, seed[1], nonce)
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = (
                t0[0] + t1[0] + bit + Field2(1),
                t0[1] + t1[1] + bit,
            )

            x0 = xor(s0[keep], ctrl[0].conditional_select(seed_cw))
            x1 = xor(s1[keep], ctrl[1].conditional_select(seed_cw))
            (seed[0], w0) = self.convert(level, x0, nonce)
            (seed[1], w1) = self.convert(level, x1, nonce)
            ctrl[0] = t0[keep] + ctrl[0] * ctrl_cw[keep]
            ctrl[1] = t1[keep] + ctrl[1] * ctrl_cw[keep]

            if level < self.BITS - 1:
                b = cast(list[Field], beta_inner[level])
            else:
                b = cast(list[Field], beta_leaf)
            if len(b) != self.VALUE_LEN:
                raise ValueError(
                    "length of beta must match the value length"
                )

            w_cw = vec_add(vec_sub(b, w0), w1)
            # Implementation note: here we negate the correction word if
            # the control bit `ctrl[1]` is set. We avoid branching on the
            # value in order to reduce leakage via timing side channels.
            mask = field(1) - field(2) * field(ctrl[1].as_unsigned())
            for i in range(len(w_cw)):
                w_cw[i] *= mask

            public_share.append((seed_cw, ctrl_cw, w_cw))
        return (public_share, key)

    # NOTE: The eval() and eval_next(), and prep_shares_to_prep() methods
    # are excerpted in the document, de-indented, as figure
    # {{idpf-poplar-eval}}. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid
    # warnings from xml2rfc.
    # ===================================================================
    def eval(
            self,
            agg_id: int,
            public_share: list[CorrectionWord],
            key: bytes,
            level: int,
            prefixes: Sequence[int],
            nonce: bytes) -> list[list[Field64]] | list[list[Field255]]:
        if agg_id not in range(self.SHARES):
            raise ValueError('aggregator id out of range')
        if level not in range(self.BITS):
            raise ValueError('level out of range')
        if len(set(prefixes)) != len(prefixes):
            raise ValueError('prefixes must be unique')

        out_share = []
        for prefix in prefixes:
            if prefix not in range(2 ** (level + 1)):
                raise ValueError('prefix out of range')

            # The Aggregator's output share is the value of a node of
            # the IDPF tree at the given `level`. The node's value is
            # computed by traversing the path defined by the candidate
            # `prefix`. Each node in the tree is represented by a seed
            # (`seed`) and a control bit (`ctrl`).
            seed = key
            ctrl = Field2(agg_id)
            y: FieldVec
            for current_level in range(level + 1):
                bit = (prefix >> (level - current_level)) & 1

                # Implementation note: typically the current round of
                # candidate prefixes would have been derived from
                # aggregate results computed during previous rounds.
                # For example, when using the IDPF to compute heavy
                # hitters, a string whose hit count exceeded the
                # given threshold in the last round would be the
                # prefix of each `prefix` in the current round. (See
                # [BBCGGI21, Section 5.1].) In this case, part of the
                # path would have already been traversed.
                #
                # Re-computing nodes along previously traversed paths is
                # wasteful. Implementations can eliminate this added
                # complexity by caching nodes (i.e., `(seed, ctrl)`
                # pairs) output by previous calls to `eval_next()`.
                (seed, ctrl, y) = self.eval_next(
                    seed,
                    ctrl,
                    public_share[current_level],
                    current_level,
                    bit,
                    nonce,
                )
            if agg_id == 0:
                out_share.append(cast(list[Field], y))
            else:
                out_share.append(vec_neg(cast(list[Field], y)))
        return cast(
            list[list[Field64]] | list[list[Field255]],
            out_share,
        )

    def eval_next(
            self,
            prev_seed: bytes,
            prev_ctrl: Field2,
            correction_word: CorrectionWord,
            level: int,
            bit: int,
            nonce: bytes) -> tuple[bytes, Field2, FieldVec]:
        """
        Compute the next node in the IDPF tree along the path determined
        by a candidate prefix. The next node is determined by `bit`, the
        bit of the prefix corresponding to the next level of the tree.
        """

        field = self.current_field(level)
        seed_cw = correction_word[0]
        ctrl_cw = correction_word[1]
        w_cw = cast(list[Field], correction_word[2])
        (s, t) = self.extend(level, prev_seed, nonce)
        s[0] = xor(s[0], prev_ctrl.conditional_select(seed_cw))
        s[1] = xor(s[1], prev_ctrl.conditional_select(seed_cw))
        t[0] += ctrl_cw[0] * prev_ctrl
        t[1] += ctrl_cw[1] * prev_ctrl

        next_ctrl = t[bit]
        convert_output = self.convert(level, s[bit], nonce)
        next_seed = convert_output[0]
        y = cast(list[Field], convert_output[1])
        # Implementation note: here we add the correction word to the
        # output if `next_ctrl` is set. We avoid branching on the value
        # of the control bit in order to reduce side channel leakage.
        mask = cast(Field, field(next_ctrl.as_unsigned()))
        for i in range(len(y)):
            y[i] += w_cw[i] * mask

        return (next_seed, next_ctrl, cast(FieldVec, y))

    # NOTE: The extend(), convert(), and current_xof() methods are excerpted in
    # the document, de-indented, as figure {{idpf-poplar-helpers}}. Their width
    # should be limited to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def extend(
            self,
            level: int,
            seed: bytes,
            nonce: bytes) -> tuple[list[bytes], list[Field2]]:
        xof = self.current_xof(level, seed, format_dst(1, 0, 0), nonce)
        s = [
            bytearray(xof.next(self.KEY_SIZE)),
            bytearray(xof.next(self.KEY_SIZE)),
        ]
        # Use the least significant bits as the control bit correction,
        # and then zero it out. This gives effectively 127 bits of
        # security, but reduces the number of AES calls needed by 1/3.
        t = [Field2(s[0][0] & 1), Field2(s[1][0] & 1)]
        s[0][0] &= 0xFE
        s[1][0] &= 0xFE
        return ([bytes(s[0]), bytes(s[1])], t)

    def convert(
            self,
            level: int,
            seed: bytes,
            nonce: bytes) -> tuple[bytes, FieldVec]:
        xof = self.current_xof(level, seed, format_dst(1, 0, 1), nonce)
        next_seed = xof.next(self.KEY_SIZE)
        field = self.current_field(level)
        w = xof.next_vec(field, self.VALUE_LEN)
        return (next_seed, cast(FieldVec, w))

    def current_xof(self,
                    level: int,
                    seed: bytes,
                    dst: bytes,
                    nonce: bytes) -> Xof:
        if level < self.BITS-1:
            return XofFixedKeyAes128(seed, dst, nonce)
        return XofTurboShake128(seed, dst, nonce)

    def encode_public_share(
            self,
            public_share: list[CorrectionWord]) -> bytes:
        encoded = bytes()
        control_bits = list(itertools.chain.from_iterable(
            cw[1] for cw in public_share
        ))
        encoded += pack_bits(control_bits)
        for (level, (seed_cw, _, w_cw)) \
                in enumerate(public_share):
            field = cast(type[Field], self.current_field(level))
            encoded += seed_cw
            encoded += field.encode_vec(cast(list[Field], w_cw))
        return encoded

    def decode_public_share(
            self,
            encoded: bytes) -> list[CorrectionWord]:
        l = (2 * self.BITS + 7) // 8
        encoded_ctrl, encoded = encoded[:l], encoded[l:]
        control_bits = unpack_bits(encoded_ctrl, 2 * self.BITS)
        public_share = []
        for level in range(self.BITS):
            field = self.current_field(level)
            ctrl_cw = (
                control_bits[level * 2],
                control_bits[level * 2 + 1],
            )
            l = XofFixedKeyAes128.SEED_SIZE
            seed_cw, encoded = encoded[:l], encoded[l:]
            l = field.ENCODED_SIZE * self.VALUE_LEN
            encoded_w_cw, encoded = encoded[:l], encoded[l:]
            w_cw = field.decode_vec(encoded_w_cw)
            public_share.append((seed_cw, ctrl_cw, w_cw))
        if len(encoded) != 0:
            raise ValueError('trailing bytes')
        return public_share

    def test_vec_encode_public_share(self, public_share: list[CorrectionWord]) -> bytes:
        return self.encode_public_share(public_share)


def pack_bits(control_bits: list[Field2]) -> bytes:
    packed_len = (len(control_bits) + 7) // 8
    # NOTE: The following is excerpted in the document, de-indented. Thee width
    # should be limited to 69 columns after de-indenting, or 73 columns before,
    # to avoid warnings from xml2rfc.
    # ===================================================================
    packed_control_buf = [int(0)] * packed_len
    for i, bit in enumerate(control_bits):
        packed_control_buf[i // 8] |= bit.as_unsigned() << (i % 8)
    packed_control_bits = bytes(packed_control_buf)
    # NOTE: End of exerpt.
    return packed_control_bits


def unpack_bits(packed_control_bits: bytes, length: int) -> list[Field2]:
    # NOTE: The following is excerpted in the document, de-indented. Thee width
    # should be limited to 69 columns after de-indenting, or 73 columns before,
    # to avoid warnings from xml2rfc.
    # ===================================================================
    control_bits = []
    for i in range(length):
        control_bits.append(Field2(
            (packed_control_bits[i // 8] >> (i % 8)) & 1
        ))
    leftover_bits = packed_control_bits[-1] >> (
        (length + 7) % 8 + 1
    )
    if (length + 7) // 8 != len(packed_control_bits) or \
            leftover_bits != 0:
        raise ValueError('trailing bits')
    # NOTE: End of exerpt.
    return control_bits
