import json
import os
import unittest

from common import (TEST_VECTOR, TEST_VECTOR_PATH, format_dst, gen_rand,
                    print_wrapped_line)
from field import Field, Field64, Field128
from xof import Xof, XofFixedKeyAes128, XofTurboShake128


def test_xof(cls: type[Xof], f: type[Field], expanded_len: int) -> None:
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
    expanded_vec = cls.expand_into_vec(f, seed, dst, binder, expanded_len)
    assert len(expanded_vec) == expanded_len


def generate_test_vector(cls: type[Xof]) -> None:
    seed = gen_rand(cls.SEED_SIZE)
    dst = b'domain separation tag'
    binder = b'binder string'
    length = 40

    test_vector = {
        'seed': seed.hex(),
        'dst': dst.hex(),
        'binder': binder.hex(),
        'length': length,
        'derived_seed': None,  # set below
        'expanded_vec_field128': None,  # set below
    }

    derived_seed = cls.derive_seed(seed, dst, binder).hex()
    expanded_vec_field128 = Field128.encode_vec(
        cls.expand_into_vec(Field128, seed, dst, binder, length)).hex()
    test_vector['derived_seed'] = derived_seed
    test_vector['expanded_vec_field128'] = expanded_vec_field128

    print('{}:'.format(cls.test_vec_name))
    print('  seed: "{}"'.format(test_vector['seed']))
    print('  dst: "{}"'.format(test_vector['dst']))
    print('  binder: "{}"'.format(test_vector['binder']))
    print('  length: {}'.format(test_vector['length']))
    print('  derived_seed: "{}"'.format(test_vector['derived_seed']))
    print('  expanded_vec_field128: >-')
    print_wrapped_line(expanded_vec_field128, tab=4)

    os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
    with open('{}/{}.json'.format(
            TEST_VECTOR_PATH, cls.__name__), 'w') as f:
        json.dump(test_vector, f, indent=4, sort_keys=True)
        f.write('\n')


class TestXof(unittest.TestCase):
    def test_rejection_sampling(self):
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

    def test_turboshake128(self):
        test_xof(XofTurboShake128, Field128, 23)
        if TEST_VECTOR:
            generate_test_vector(XofTurboShake128)

    def test_fixedkeyaes128(self):
        test_xof(XofFixedKeyAes128, Field128, 23)
        if TEST_VECTOR:
            generate_test_vector(XofFixedKeyAes128)
