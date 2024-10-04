import itertools
import unittest
from functools import reduce
from typing import Sequence, cast

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.field import Field
from vdaf_poc.idpf import Idpf
from vdaf_poc.idpf_bbcggi21 import CorrectionWord, IdpfBBCGGI21


class TestIdpfBBCGGI21(unittest.TestCase):
    def run_idpf_test(self, idpf: Idpf, alpha: tuple[bool, ...], level: int, prefixes: Sequence[tuple[bool, ...]]) -> None:
        """
        Generate a set of IDPF keys and evaluate them on the given set of prefix.
        """
        ctx = b'some context'
        beta_inner = [[idpf.field_inner(1)] * idpf.VALUE_LEN] * (idpf.BITS - 1)
        beta_leaf = [idpf.field_leaf(1)] * idpf.VALUE_LEN

        # Generate the IDPF keys.
        rand = gen_rand(idpf.RAND_SIZE)
        nonce = gen_rand(idpf.NONCE_SIZE)
        (public_share, keys) = idpf.gen(
            alpha, beta_inner, beta_leaf, ctx, nonce, rand)

        out = [idpf.current_field(level).zeros(idpf.VALUE_LEN)] * len(prefixes)
        for agg_id in range(idpf.SHARES):
            out_share = idpf.eval(
                agg_id, public_share, keys[agg_id], level, prefixes, ctx, nonce)
            for i in range(len(prefixes)):
                out[i] = vec_add(out[i], out_share[i])

        for (got, prefix) in zip(out, prefixes):
            if idpf.is_prefix(prefix, alpha, level):
                if level < idpf.BITS - 1:
                    want = beta_inner[level]
                else:
                    want = beta_leaf
            else:
                want = idpf.current_field(level).zeros(idpf.VALUE_LEN)

            self.assertEqual(got, want)

    def run_idpf_exhaustive_test(self, idpf: Idpf, alpha: tuple[bool, ...]) -> None:
        """Generate a set of IDPF keys and test every possible output."""

        # Generate random outputs with which to program the IDPF.
        beta_inner = []
        for _ in range(idpf.BITS - 1):
            beta_inner.append(idpf.field_inner.rand_vec(idpf.VALUE_LEN))
        beta_leaf = idpf.field_leaf.rand_vec(idpf.VALUE_LEN)

        # Generate the IDPF keys.
        rand = gen_rand(idpf.RAND_SIZE)
        ctx = b'some context'
        nonce = gen_rand(idpf.NONCE_SIZE)
        (public_share, keys) = idpf.gen(
            alpha, beta_inner, beta_leaf, ctx, nonce, rand)

        # Evaluate the IDPF at every node of the tree.
        for level in range(idpf.BITS):
            prefixes = tuple(itertools.product(
                *[(False, True)] * (level + 1)
            ))

            out_shares = []
            for agg_id in range(idpf.SHARES):
                out_shares.append(
                    idpf.eval(agg_id, public_share,
                              keys[agg_id], level, prefixes, ctx, nonce))

            # Check that each set of output shares for each prefix sums up to the
            # correct value.
            for i, prefix in enumerate(prefixes):
                got = reduce(lambda x, y: vec_add(x, y),
                             map(lambda x: x[i], out_shares))

                if idpf.is_prefix(prefix, alpha, level):
                    if level < idpf.BITS - 1:
                        want = beta_inner[level]
                    else:
                        want = beta_leaf
                else:
                    want = idpf.current_field(level).zeros(idpf.VALUE_LEN)

                self.assertEqual(got, want)

    def test(self) -> None:
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            15,
            (int_to_bit_string(0b1111000011110000, 16),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            14,
            (int_to_bit_string(0b111100001111000, 15),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            13,
            (int_to_bit_string(0b11110000111100, 14),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            12,
            (int_to_bit_string(0b1111000011110, 13),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            11,
            (int_to_bit_string(0b111100001111, 12),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            10,
            (int_to_bit_string(0b11110000111, 11),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            5,
            (int_to_bit_string(0b111100, 6),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            4,
            (int_to_bit_string(0b11110, 5),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            3,
            (int_to_bit_string(0b1111, 4),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            2,
            (int_to_bit_string(0b111, 3),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            1,
            (int_to_bit_string(0b11, 2),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            int_to_bit_string(0b1111000011110000, 16),
            0,
            (int_to_bit_string(0b1, 1),),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 1000),
            tuple([False] * 1000),
            999,
            (tuple([False] * 1000),),
        )
        self.run_idpf_exhaustive_test(
            IdpfBBCGGI21(2, 1),
            (False,),
        )
        self.run_idpf_exhaustive_test(
            IdpfBBCGGI21(2, 1),
            (True,),
        )
        self.run_idpf_exhaustive_test(
            IdpfBBCGGI21(2, 8),
            int_to_bit_string(91, 8),
        )

    def test_index_encoding(self) -> None:
        """
        Ensure that the IDPF index is encoded in big-endian byte order.
        """
        idpf = IdpfBBCGGI21(1, 32)
        ctx = b'some context'
        nonce = gen_rand(idpf.NONCE_SIZE)

        def shard(s: bytes) -> tuple[list[CorrectionWord], list[bytes]]:
            alpha = bytes_to_bit_string(s)
            beta_inner = [[idpf.field_inner(1)]] * (idpf.BITS - 1)
            beta_leaf = [idpf.field_leaf(1)]
            rand = gen_rand(idpf.RAND_SIZE)
            return idpf.gen(alpha, beta_inner, beta_leaf, ctx, nonce, rand)

        for (alpha_str, prefix, level) in [
            (
                b"\x01\x02\x03\x04",
                int_to_bit_string(0x010203, 24),
                23,
            ),
            (
                b"abcd",
                int_to_bit_string(0x61626364, 32),
                31,
            )
        ]:
            (public_share, keys) = shard(alpha_str)
            out_share_0 = cast(list[list[Field]], idpf.eval(
                0, public_share, keys[0], level, (prefix,), ctx, nonce))
            out_share_1 = cast(list[list[Field]], idpf.eval(
                1, public_share, keys[1], level, (prefix,), ctx, nonce))
            out = vec_add(out_share_0[0], out_share_1[0])[0]
            self.assertEqual(out.as_unsigned(), 1)

    def test_is_prefix(self) -> None:
        idpf = IdpfBBCGGI21(1, 8)
        self.assertTrue(idpf.is_prefix(
            int_to_bit_string(0b1, 1),
            int_to_bit_string(0b11000001, 8),
            0,
        ))
        self.assertTrue(idpf.is_prefix(
            int_to_bit_string(0b11, 2),
            int_to_bit_string(0b11000001, 8),
            1,
        ))
        self.assertTrue(idpf.is_prefix(
            int_to_bit_string(0b110, 3),
            int_to_bit_string(0b11000001, 8),
            2,
        ))
        self.assertTrue(idpf.is_prefix(
            int_to_bit_string(0b1100, 4),
            int_to_bit_string(0b11000001, 8),
            3,
        ))
        self.assertFalse(idpf.is_prefix(
            int_to_bit_string(0b111, 3),
            int_to_bit_string(0b11000001, 8),
            2,
        ))
        self.assertFalse(idpf.is_prefix(
            int_to_bit_string(0b1101, 4),
            int_to_bit_string(0b11000001, 8),
            3,
        ))

    def test_public_share_roundtrip(self) -> None:
        idpf = IdpfBBCGGI21(1, 32)
        alpha = bytes_to_bit_string(b"cool")
        beta_inner = [[idpf.field_inner(23)]] * (idpf.BITS - 1)
        beta_leaf = [idpf.field_leaf(97)]
        ctx = b'some context'
        nonce = gen_rand(idpf.NONCE_SIZE)
        rand = gen_rand(idpf.RAND_SIZE)
        (public_share, _keys) = idpf.gen(
            alpha, beta_inner, beta_leaf, ctx, nonce, rand)
        self.assertEqual(
            idpf.decode_public_share(idpf.encode_public_share(public_share)),
            public_share,
        )


def bytes_to_bit_string(s: bytes) -> tuple[bool, ...]:
    return tuple(itertools.chain.from_iterable(
        (
            byte & 0x80 != 0,
            byte & 0x40 != 0,
            byte & 0x20 != 0,
            byte & 0x10 != 0,
            byte & 0x08 != 0,
            byte & 0x04 != 0,
            byte & 0x02 != 0,
            byte & 0x01 != 0,
        ) for byte in s
    ))


def int_to_bit_string(value: int, length: int) -> tuple[bool, ...]:
    return tuple(
        (value >> (length - 1 - i)) & 1 != 0 for i in range(length)
    )
