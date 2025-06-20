"""The IDPF of {{BBCGGI21}}, Section 6."""

import itertools
from typing import Sequence, TypeAlias, cast

from vdaf_poc.common import format_dst, front, vec_add, vec_neg, vec_sub, xor
from vdaf_poc.field import Field, Field64, Field255
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
CorrectionWord: TypeAlias = tuple[bytes, tuple[bool, bool], FieldVec]


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
            alpha: tuple[bool, ...],
            beta_inner: list[list[Field64]],
            beta_leaf: list[Field255],
            ctx: bytes,
            nonce: bytes,
            rand: bytes) -> tuple[list[CorrectionWord], list[bytes]]:
        if len(alpha) != self.BITS:
            raise ValueError("incorrect alpha length")
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
        ctrl = [False, True]
        public_share = []
        for level in range(self.BITS):
            bit = alpha[level]
            keep = int(bit)
            lose = 1 - keep

            (s0, t0) = self.extend(level, seed[0], ctx, nonce)
            (s1, t1) = self.extend(level, seed[1], ctx, nonce)
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = (
                t0[0] ^ t1[0] ^ (not bit),
                t0[1] ^ t1[1] ^ bit,
            )

            # Implementation note: these conditional XORs and
            # input-dependent array indices should be replaced with
            # constant-time selects in practice in order to reduce
            # leakage via timing side channels.
            if ctrl[0]:
                x0 = xor(s0[keep], seed_cw)
                ctrl[0] = t0[keep] ^ ctrl_cw[keep]
            else:
                x0 = s0[keep]
                ctrl[0] = t0[keep]
            if ctrl[1]:
                x1 = xor(s1[keep], seed_cw)
                ctrl[1] = t1[keep] ^ ctrl_cw[keep]
            else:
                x1 = s1[keep]
                ctrl[1] = t1[keep]
            (seed[0], w0) = self.convert(level, x0, ctx, nonce)
            (seed[1], w1) = self.convert(level, x1, ctx, nonce)

            if level < self.BITS - 1:
                b = cast(list[Field], beta_inner[level])
            else:
                b = cast(list[Field], beta_leaf)
            if len(b) != self.VALUE_LEN:
                raise ValueError(
                    "length of beta must match the value length"
                )

            w_cw = vec_add(vec_sub(b, w0), w1)
            # Implementation note: this conditional negation should be
            # replaced with a constant time select or a constant time
            # multiplication in practice in order to reduce leakage via
            # timing side channels.
            if ctrl[1]:
                for i in range(len(w_cw)):
                    w_cw[i] = -w_cw[i]

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
            prefixes: Sequence[tuple[bool, ...]],
            ctx: bytes,
            nonce: bytes) -> list[list[Field64]] | list[list[Field255]]:
        if agg_id not in range(self.SHARES):
            raise ValueError('aggregator id out of range')
        if level not in range(self.BITS):
            raise ValueError('level out of range')
        if len(set(prefixes)) != len(prefixes):
            raise ValueError('prefixes must be unique')

        out_share = []
        for prefix in prefixes:
            if len(prefix) != level + 1:
                raise ValueError('incorrect prefix length')

            # The Aggregator's output share is the value of a node of
            # the IDPF tree at the given `level`. The node's value is
            # computed by traversing the path defined by the candidate
            # `prefix`. Each node in the tree is represented by a seed
            # (`seed`) and a control bit (`ctrl`).
            seed = key
            ctrl = bool(agg_id)
            y: FieldVec
            for current_level in range(level + 1):
                bit = int(prefix[current_level])

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
                    ctx,
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
            prev_ctrl: bool,
            correction_word: CorrectionWord,
            level: int,
            bit: int,
            ctx: bytes,
            nonce: bytes) -> tuple[bytes, bool, FieldVec]:
        """
        Compute the next node in the IDPF tree along the path determined
        by a candidate prefix. The next node is determined by `bit`, the
        bit of the prefix corresponding to the next level of the tree.
        """

        seed_cw = correction_word[0]
        ctrl_cw = correction_word[1]
        w_cw = cast(list[Field], correction_word[2])
        (s, t) = self.extend(level, prev_seed, ctx, nonce)

        # Implementation note: these conditional operations and
        # input-dependent array indices should be replaced with
        # constant-time selects in practice in order to reduce leakage
        # via timing side channels.
        if prev_ctrl:
            s[0] = xor(s[0], seed_cw)
            s[1] = xor(s[1], seed_cw)
            t[0] ^= ctrl_cw[0]
            t[1] ^= ctrl_cw[1]

        next_ctrl = t[bit]
        convert_output = self.convert(level, s[bit], ctx, nonce)
        next_seed = convert_output[0]
        y = cast(list[Field], convert_output[1])
        # Implementation note: this conditional addition should be
        # replaced with a constant-time select in practice in order to
        # reduce leakage via timing side channels.
        if next_ctrl:
            for i in range(len(y)):
                y[i] += w_cw[i]

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
            ctx: bytes,
            nonce: bytes) -> tuple[list[bytes], list[bool]]:
        xof = self.current_xof(
            level,
            seed,
            format_dst(1, 0, 0) + ctx,
            nonce,
        )
        s = [
            bytearray(xof.next(self.KEY_SIZE)),
            bytearray(xof.next(self.KEY_SIZE)),
        ]
        # Use the least significant bits as the control bit correction,
        # and then zero it out. This gives effectively 127 bits of
        # security, but reduces the number of AES calls needed by 1/3.
        t = [bool(s[0][0] & 1), bool(s[1][0] & 1)]
        s[0][0] &= 0xFE
        s[1][0] &= 0xFE
        return ([bytes(s[0]), bytes(s[1])], t)

    def convert(
            self,
            level: int,
            seed: bytes,
            ctx: bytes,
            nonce: bytes) -> tuple[bytes, FieldVec]:
        xof = self.current_xof(
            level,
            seed,
            format_dst(1, 0, 1) + ctx,
            nonce,
        )
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
        (seeds, ctrl, payloads) = zip(*public_share)
        encoded = bytes()
        encoded += pack_bits(list(itertools.chain.from_iterable(ctrl)))
        for seed in seeds:
            encoded += seed
        for payload in payloads[:-1]:
            encoded += self.field_inner.encode_vec(payload)
        encoded += self.field_leaf.encode_vec(payloads[-1])
        return encoded

    def decode_public_share(
            self,
            encoded: bytes) -> list[CorrectionWord]:
        ctrl = []
        (encoded_ctrl, encoded) = front((2 * self.BITS + 7) // 8, encoded)
        flattened_ctrl = unpack_bits(encoded_ctrl, 2 * self.BITS)
        for level in range(self.BITS):
            ctrl.append((
                flattened_ctrl[2 * level],
                flattened_ctrl[2 * level + 1],
            ))
        seeds = []
        for _ in range(self.BITS):
            (seed, encoded) = front(self.KEY_SIZE, encoded)
            seeds.append(seed)
        payloads = []
        for level in range(self.BITS):
            field = self.current_field(level)
            (encoded_payload, encoded) = front(
                field.ENCODED_SIZE * self.VALUE_LEN,
                encoded)
            payload = field.decode_vec(encoded_payload)
            payloads.append(payload)
        if len(encoded) != 0:
            raise ValueError('trailing bytes')
        return list(zip(seeds, ctrl, payloads))


def pack_bits(control_bits: list[bool]) -> bytes:
    packed_len = (len(control_bits) + 7) // 8
    # NOTE: The following is excerpted in the document, de-indented. Thee width
    # should be limited to 69 columns after de-indenting, or 73 columns before,
    # to avoid warnings from xml2rfc.
    # ===================================================================
    packed_control_buf = [int(0)] * packed_len
    for i, bit in enumerate(control_bits):
        packed_control_buf[i // 8] |= bit << (i % 8)
    packed_control_bits = bytes(packed_control_buf)
    # NOTE: End of exerpt.
    return packed_control_bits


def unpack_bits(packed_control_bits: bytes, length: int) -> list[bool]:
    # NOTE: The following is excerpted in the document, de-indented. Thee width
    # should be limited to 69 columns after de-indenting, or 73 columns before,
    # to avoid warnings from xml2rfc.
    # ===================================================================
    control_bits = []
    for i in range(length):
        control_bits.append(bool(
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
