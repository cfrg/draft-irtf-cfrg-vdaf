import unittest

from vdaf_poc.common import format_dst, gen_rand
from vdaf_poc.field import Field, Field64, Field128
from vdaf_poc.xof import Xof, XofFixedKeyAes128, XofTurboShake128


def test_xof(cls: type[Xof], field: type[Field], expanded_len: int) -> None:
    dst = format_dst(7, 1337, 2)
    binder = b'a string that binds some protocol artifact to the output'
    seed = gen_rand(cls.SEED_SIZE)

    # Test next
    expanded_data = cls(seed, dst, binder).next(expanded_len)
    assert len(expanded_data) == expanded_len

    want = cls(seed, dst, binder).next(700)
    got = b''
    xof = cls(seed, dst, binder)
    for i in range(0, 700, 7):
        got += xof.next(7)
    assert got == want

    # Test derive
    derived_seed = cls.derive_seed(seed, dst, binder)
    assert len(derived_seed) == cls.SEED_SIZE

    # Test expand_into_vec
    expanded_vec = cls.expand_into_vec(field, seed, dst, binder, expanded_len)
    assert len(expanded_vec) == expanded_len


class TestXof(unittest.TestCase):
    def test_rejection_sampling(self) -> None:
        # This test case was found through brute-force search using this tool:
        # https://github.com/divergentdave/vdaf-rejection-sampling-search
        expanded_vec = XofTurboShake128.expand_into_vec(
            Field64,
            bytes([0x86, 0x1e, 0x9e, 0x8e, 0x49, 0x44, 0xa2, 0x9f, 0xa4, 0x07,
                   0x43, 0x23, 0xaf, 0x39, 0xaa, 0xcf, 0xeb, 0xf5, 0xc8, 0x88,
                   0xa9, 0xe5, 0x5f, 0x0f, 0x9a, 0x9e, 0x4c, 0x70, 0x7d, 0xcd,
                   0x95, 0x55]),
            b'',  # domain separation tag
            b'',  # binder
            18262,
        )
        assert expanded_vec[-1] == Field64(6866317754138817667)

    def test_turboshake128(self) -> None:
        test_xof(XofTurboShake128, Field128, 23)

    def test_fixedkeyaes128(self) -> None:
        test_xof(XofFixedKeyAes128, Field128, 23)
