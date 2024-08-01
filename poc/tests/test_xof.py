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
            bytes([0xd1, 0x95, 0xec, 0x90, 0xc1, 0xbc, 0xf1, 0xf2, 0xcb, 0x2c,
                   0x7e, 0x74, 0xc5, 0xc5, 0xf6, 0xda]),
            b'',  # domain separation tag
            b'',  # binder
            140,
        )
        assert expanded_vec[-1] == Field64(9734340616212735019)

    def test_turboshake128(self) -> None:
        test_xof(XofTurboShake128, Field128, 23)

    def test_fixedkeyaes128(self) -> None:
        test_xof(XofFixedKeyAes128, Field128, 23)
