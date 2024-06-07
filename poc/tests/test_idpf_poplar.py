import unittest

from common import TEST_VECTOR, from_be_bytes, gen_rand, vec_add
from idpf_poplar import IdpfPoplar
from tests.idpf import gen_test_vec, test_idpf, test_idpf_exhaustive


class TestIdpfPoplar(unittest.TestCase):
    def test_idpfpoplar(self):
        cls = IdpfPoplar.with_value_len(2)

        if TEST_VECTOR:
            gen_test_vec(cls.with_bits(10), 0, 0)
        test_idpf(
            cls.with_bits(16),
            0b1111000011110000,
            15,
            (0b1111000011110000,),
        )
        test_idpf(
            cls.with_bits(16),
            0b1111000011110000,
            14,
            (0b111100001111000,),
        )
        test_idpf(
            cls.with_bits(16),
            0b1111000011110000,
            13,
            (0b11110000111100,),
        )
        test_idpf(
            cls.with_bits(16),
            0b1111000011110000,
            12,
            (0b1111000011110,),
        )
        test_idpf(cls.with_bits(16), 0b1111000011110000, 11, (0b111100001111,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 10, (0b11110000111,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 5, (0b111100,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 4, (0b11110,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 3, (0b1111,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 2, (0b111,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 1, (0b11,))
        test_idpf(cls.with_bits(16), 0b1111000011110000, 0, (0b1,))
        test_idpf(cls.with_bits(1000), 0, 999, (0,))
        test_idpf_exhaustive(cls.with_bits(1), 0)
        test_idpf_exhaustive(cls.with_bits(1), 1)
        test_idpf_exhaustive(cls.with_bits(8), 91)

    def test_index_encoding(self):
        """
        Ensure that the IDPF index is encoded in big-endian byte order.
        """
        cls = IdpfPoplar.with_value_len(1).with_bits(32)
        binder = b'some nonce'

        def shard(s):
            alpha = from_be_bytes(s)
            beta_inner = [[cls.FieldInner(1)]] * (cls.BITS-1)
            beta_leaf = [cls.FieldLeaf(1)]
            rand = gen_rand(cls.RAND_SIZE)
            return cls.gen(alpha, beta_inner, beta_leaf, binder, rand)

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
            out_share_0 = cls.eval(
                0, public_share, keys[0], level, (alpha,), binder)
            out_share_1 = cls.eval(
                1, public_share, keys[1], level, (alpha,), binder)
            out = vec_add(out_share_0[0], out_share_1[0])[0]
            self.assertEqual(out.as_unsigned(), 1)

    def test_is_prefix(self):
        cls = IdpfPoplar.with_value_len(1).with_bits(8)
        self.assertTrue(cls.is_prefix(0b1, 0b11000001, 0))
        self.assertTrue(cls.is_prefix(0b11, 0b11000001, 1))
        self.assertTrue(cls.is_prefix(0b110, 0b11000001, 2))
        self.assertTrue(cls.is_prefix(0b1100, 0b11000001, 3))
        self.assertFalse(cls.is_prefix(0b111, 0b11000001, 2))
        self.assertFalse(cls.is_prefix(0b1101, 0b11000001, 3))
