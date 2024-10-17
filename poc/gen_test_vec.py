#!/usr/bin/env python3

import json
import os

from vdaf_poc.common import print_wrapped_line
from vdaf_poc.field import Field128
from vdaf_poc.idpf import Idpf
from vdaf_poc.test_utils import gen_test_vec_for_vdaf, test_vec_gen_rand
from vdaf_poc.xof import Xof

# The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH', '../test_vec/')

# IDPF


def gen_test_vec_for_idpf(idpf: Idpf,
                          alpha: tuple[bool, ...],
                          test_vec_instance: int) -> None:
    beta_inner = []
    for level in range(idpf.BITS - 1):
        beta_inner.append([idpf.field_inner(level)] * idpf.VALUE_LEN)
    beta_leaf = [idpf.field_leaf(idpf.BITS - 1)] * idpf.VALUE_LEN
    rand = test_vec_gen_rand(idpf.RAND_SIZE)
    nonce = test_vec_gen_rand(idpf.NONCE_SIZE)
    (public_share, keys) = idpf.gen(
        alpha,
        beta_inner,
        beta_leaf,
        ctx,
        nonce,
        rand,
    )

    printable_beta_inner = [
        [str(elem.int()) for elem in value] for value in beta_inner
    ]
    printable_beta_leaf = [str(elem.int()) for elem in beta_leaf]
    printable_keys = [key.hex() for key in keys]
    test_vec = {
        'bits': int(idpf.BITS),
        'alpha': alpha,
        'beta_inner': printable_beta_inner,
        'beta_leaf': printable_beta_leaf,
        'ctx': ctx.hex(),
        'nonce': nonce.hex(),
        'public_share': idpf.test_vec_encode_public_share(public_share).hex(),
        'keys': printable_keys,
    }

    os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
    filename = '{}/{}_{}.json'.format(TEST_VECTOR_PATH, idpf.test_vec_name,
                                      test_vec_instance)
    with open(filename, 'w') as f:
        json.dump(test_vec, f, indent=4, sort_keys=True)
        f.write('\n')


# XOF

def gen_test_vec_for_xof(cls: type[Xof]) -> None:
    seed = test_vec_gen_rand(cls.SEED_SIZE)
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


if __name__ == '__main__':
    from vdaf_poc import idpf_bbcggi21, vdaf_poplar1, vdaf_prio3, xof

    ctx = b'some application'
    vdaf_test_vec_path = TEST_VECTOR_PATH + "/vdaf/"

    # Prio3Count
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Count(2),
        None,
        ctx,
        [1],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Count(3),
        None,
        ctx,
        [1],
        1,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Count(2),
        None,
        ctx,
        [0, 1, 1, 0, 1],
        2,
    )

    # Prio3Sum
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Sum(2, 255),
        None,
        ctx,
        [100],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Sum(3, 255),
        None,
        ctx,
        [100],
        1,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Sum(2, 1337),
        None,
        ctx,
        [0, 1, 1337, 99, 42, 0, 0, 42],
        2,
    )

    # Prio3SumVec
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3SumVec(2, 10, 8, 9),
        None,
        ctx,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3SumVec(3, 3, 16, 7),
        None,
        ctx,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        1,
    )

    # Prio3Histogram
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Histogram(2, 4, 2),
        None,
        ctx,
        [2],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Histogram(3, 11, 3),
        None,
        ctx,
        [2],
        1,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3Histogram(2, 100, 10),
        None,
        ctx,
        [2, 99, 99, 17, 42, 0, 0, 1, 2, 0],
        2,
    )

    # Prio3MultihotCountVec
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3MultihotCountVec(2, 4, 2, 2),
        None,
        ctx,
        [[False, True, True, False]],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3MultihotCountVec(4, 10, 2, 3),
        None,
        ctx,
        [[False, True, False, False, False, False, False, False, False, True]],
        1,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3MultihotCountVec(2, 4, 4, 1),
        None,
        ctx,
        [
            [False, True, True, False],
            [False, False, True, False],
            [False, False, False, False],
            [True, True, True, False],
            [True, True, True, True],
        ],
        2,
    )

    # Poplar1
    poplar1_test_number = 0
    tests: list[tuple[int, tuple[tuple[bool, ...], ...]]] = [
        (0, ((False,), (True,))),
        (1, ((False, False), (False, True), (True, False), (True, True))),
        (
            2,
            (
                (False, False, False),
                (False, True, False),
                (True, False, False),
                (True, True, False),
            ),
        ),
        (
            3,
            (
                (False, False, False, True),
                (False, False, True, True),
                (False, True, False, True),
                (False, True, True, True),
                (True, False, False, True),
                (True, True, False, True),
                (True, True, True, True),
            ),
        ),
    ]
    measurements: list[tuple[bool, ...]] = [(True, True, False, True)]
    for (test_level, prefixes) in tests:
        gen_test_vec_for_vdaf(
            vdaf_test_vec_path,
            vdaf_poplar1.Poplar1(4),
            (test_level, prefixes),
            ctx,
            measurements,
            poplar1_test_number,
        )
        poplar1_test_number += 1

    tests = [
        (0, ((False,), (True,))),
        (10, (
            (False,) * 11,
            (True, True, False, False, True, False, False, False, False, False,
             False),
            (True, True, False, False, True, False, False, False, False, False,
             True),
            (True,) * 11,
        )),
    ]
    measurements = [
        (True, True, False, False, True, False, False, False, False, False,
         True),
    ]
    for (test_level, prefixes) in tests:
        gen_test_vec_for_vdaf(
            vdaf_test_vec_path,
            vdaf_poplar1.Poplar1(11),
            (test_level, prefixes),
            ctx,
            measurements,
            poplar1_test_number,
        )
        poplar1_test_number += 1

    # IdpfBBCGGI21
    gen_test_vec_for_idpf(
        idpf_bbcggi21.IdpfBBCGGI21(2, 10),
        (False, False, False, False, False, False, False, False, False, False),
        0,
    )

    # XOFs
    gen_test_vec_for_xof(xof.XofTurboShake128)
    gen_test_vec_for_xof(xof.XofFixedKeyAes128)
