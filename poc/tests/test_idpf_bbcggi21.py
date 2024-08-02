import unittest
from functools import reduce
from typing import Sequence, cast

from vdaf_poc.common import from_be_bytes, gen_rand, vec_add
from vdaf_poc.field import Field
from vdaf_poc.idpf import Idpf
from vdaf_poc.idpf_bbcggi21 import IdpfBBCGGI21


class TestIdpfBBCGGI21(unittest.TestCase):
    def run_idpf_test(self, idpf: Idpf, alpha: int, level: int, prefixes: Sequence[int]) -> None:
        """
        Generate a set of IDPF keys and evaluate them on the given set of prefix.
        """
        beta_inner = [[idpf.field_inner(1)] * idpf.VALUE_LEN] * (idpf.BITS - 1)
        beta_leaf = [idpf.field_leaf(1)] * idpf.VALUE_LEN

        # Generate the IDPF keys.
        rand = gen_rand(idpf.RAND_SIZE)
        nonce = gen_rand(idpf.NONCE_SIZE)
        (public_share, keys) = idpf.gen(
            alpha, beta_inner, beta_leaf, nonce, rand)

        out = [idpf.current_field(level).zeros(idpf.VALUE_LEN)] * len(prefixes)
        for agg_id in range(idpf.SHARES):
            out_share = idpf.eval(
                agg_id, public_share, keys[agg_id], level, prefixes, nonce)
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

    def run_idpf_exhaustive_test(self, idpf: Idpf, alpha: int) -> None:
        """Generate a set of IDPF keys and test every possible output."""

        # Generate random outputs with which to program the IDPF.
        beta_inner = []
        for _ in range(idpf.BITS - 1):
            beta_inner.append(idpf.field_inner.rand_vec(idpf.VALUE_LEN))
        beta_leaf = idpf.field_leaf.rand_vec(idpf.VALUE_LEN)

        # Generate the IDPF keys.
        rand = gen_rand(idpf.RAND_SIZE)
        nonce = gen_rand(idpf.NONCE_SIZE)
        (public_share, keys) = idpf.gen(
            alpha, beta_inner, beta_leaf, nonce, rand)

        # Evaluate the IDPF at every node of the tree.
        for level in range(idpf.BITS):
            prefixes = tuple(range(2 ** level))

            out_shares = []
            for agg_id in range(idpf.SHARES):
                out_shares.append(
                    idpf.eval(agg_id, public_share,
                              keys[agg_id], level, prefixes, nonce))

            # Check that each set of output shares for each prefix sums up to the
            # correct value.
            for prefix in prefixes:
                got = reduce(lambda x, y: vec_add(x, y),
                             map(lambda x: x[prefix], out_shares))

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
            0b1111000011110000,
            15,
            (0b1111000011110000,),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            0b1111000011110000,
            14,
            (0b111100001111000,),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            0b1111000011110000,
            13,
            (0b11110000111100,),
        )
        self.run_idpf_test(
            IdpfBBCGGI21(2, 16),
            0b1111000011110000,
            12,
            (0b1111000011110,),
        )
        self.run_idpf_test(IdpfBBCGGI21(2, 16), 0b1111000011110000,
                           11, (0b111100001111,))
        self.run_idpf_test(IdpfBBCGGI21(2, 16), 0b1111000011110000,
                           10, (0b11110000111,))
        self.run_idpf_test(IdpfBBCGGI21(
            2, 16), 0b1111000011110000, 5, (0b111100,))
        self.run_idpf_test(IdpfBBCGGI21(
            2, 16), 0b1111000011110000, 4, (0b11110,))
        self.run_idpf_test(IdpfBBCGGI21(
            2, 16), 0b1111000011110000, 3, (0b1111,))
        self.run_idpf_test(IdpfBBCGGI21(
            2, 16), 0b1111000011110000, 2, (0b111,))
        self.run_idpf_test(IdpfBBCGGI21(2, 16), 0b1111000011110000, 1, (0b11,))
        self.run_idpf_test(IdpfBBCGGI21(2, 16), 0b1111000011110000, 0, (0b1,))
        self.run_idpf_test(IdpfBBCGGI21(2, 1000), 0, 999, (0,))
        self.run_idpf_exhaustive_test(IdpfBBCGGI21(2, 1), 0)
        self.run_idpf_exhaustive_test(IdpfBBCGGI21(2, 1), 1)
        self.run_idpf_exhaustive_test(IdpfBBCGGI21(2, 8), 91)

    def test_index_encoding(self) -> None:
        """
        Ensure that the IDPF index is encoded in big-endian byte order.
        """
        idpf = IdpfBBCGGI21(1, 32)
        nonce = gen_rand(idpf.NONCE_SIZE)

        def shard(s: bytes) -> tuple[bytes, list[bytes]]:
            alpha = from_be_bytes(s)
            beta_inner = [[idpf.field_inner(1)]] * (idpf.BITS - 1)
            beta_leaf = [idpf.field_leaf(1)]
            rand = gen_rand(idpf.RAND_SIZE)
            return idpf.gen(alpha, beta_inner, beta_leaf, nonce, rand)

        for (alpha_str, alpha, level) in [
            (
                b"\x01\x02\x03\x04",
                0x010203,
                23,
            ),
            (
                b"abcd",
                0x61626364,
                31,
            )
        ]:
            (public_share, keys) = shard(alpha_str)
            out_share_0 = cast(list[list[Field]], idpf.eval(
                0, public_share, keys[0], level, (alpha,), nonce))
            out_share_1 = cast(list[list[Field]], idpf.eval(
                1, public_share, keys[1], level, (alpha,), nonce))
            out = vec_add(out_share_0[0], out_share_1[0])[0]
            self.assertEqual(out.as_unsigned(), 1)

    def test_is_prefix(self) -> None:
        idpf = IdpfBBCGGI21(1, 8)
        self.assertTrue(idpf.is_prefix(0b1, 0b11000001, 0))
        self.assertTrue(idpf.is_prefix(0b11, 0b11000001, 1))
        self.assertTrue(idpf.is_prefix(0b110, 0b11000001, 2))
        self.assertTrue(idpf.is_prefix(0b1100, 0b11000001, 3))
        self.assertFalse(idpf.is_prefix(0b111, 0b11000001, 2))
        self.assertFalse(idpf.is_prefix(0b1101, 0b11000001, 3))
