import unittest

from common import TEST_VECTOR
from idpf_poplar import IdpfPoplar
from tests.idpf import gen_test_vec, test_idpf, test_idpf_exhaustive


class TestIdpfPoplar(unittest.TestCase):
    def test_idpfpoplar(self):
        cls = IdpfPoplar \
            .with_value_len(2)
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
