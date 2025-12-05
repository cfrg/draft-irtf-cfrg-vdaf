#!/usr/bin/env python3

import json
import os
from typing import Any, cast

from vdaf_poc.common import print_wrapped_line
from vdaf_poc.field import Field64, Field128
from vdaf_poc.idpf import FieldVec, Idpf
from vdaf_poc.test_utils import (VdafTestVectorDict, gen_test_vec_for_vdaf,
                                 pretty_print_vdaf_test_vec, test_vec_gen_rand,
                                 write_test_vec)
from vdaf_poc.vdaf_poplar1 import Poplar1, Poplar1InputShare
from vdaf_poc.vdaf_prio3 import (Prio3, Prio3Count, Prio3Histogram,
                                 Prio3InputShare)
from vdaf_poc.xof import Xof

# The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH', '../test_vec/')

# IDPF


def gen_test_vec_for_idpf(idpf: Idpf,
                          alpha: tuple[bool, ...],
                          ctx: bytes,
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
        'public_share': idpf.encode_public_share(public_share).hex(),
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


def gen_prio3_negative_test_vec(test_vec_path: str, ctx: bytes) -> None:
    """
    Generates various negative test vectors for Prio3.
    """

    prio3count = Prio3Count(2)
    nonce = test_vec_gen_rand(prio3count.NONCE_SIZE)
    rand = test_vec_gen_rand(prio3count.RAND_SIZE)
    public_share, [input_share_0, input_share_1] = prio3count.shard(
        ctx,
        True,
        nonce,
        rand,
    )
    verify_key = test_vec_gen_rand(prio3count.VERIFY_KEY_SIZE)

    # Modify measurement share of leader input share.
    bad_input_share_0_temp: list[Any] = list(
        cast(tuple[Any, ...], input_share_0))
    modified_measurement_share = list(
        cast(list[Field64], bad_input_share_0_temp[0]))
    modified_measurement_share[0] += Field64(1)
    bad_input_share_0_temp[0] = modified_measurement_share
    bad_input_share_0: tuple[list[Field64], list[Field64], None] = tuple(
        bad_input_share_0_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3count,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        bad_input_share_0,
        input_share_1,
        test_vec_path,
        "bad_meas_share",
    )

    # Modify a wire seed in the proof share of the leader input share.
    bad_input_share_0_temp = list(cast(tuple[Any, ...], input_share_0))
    modified_proof_share = list(
        cast(list[Field64], bad_input_share_0_temp[1]))
    modified_proof_share[0] += Field64(1)
    bad_input_share_0_temp[1] = modified_proof_share
    bad_input_share_0 = tuple(bad_input_share_0_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3count,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        bad_input_share_0,
        input_share_1,
        test_vec_path,
        "bad_wire_seed",
    )

    # Modify the gadget polynomial in the proof share of the leader input
    # share.
    bad_input_share_0_temp = list(cast(tuple[Any, ...], input_share_0))
    modified_proof_share = list(
        cast(list[Field64], bad_input_share_0_temp[1]))
    modified_proof_share[-1] += Field64(1)
    bad_input_share_0_temp[1] = modified_proof_share
    bad_input_share_0 = tuple(bad_input_share_0_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3count,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        bad_input_share_0,
        input_share_1,
        test_vec_path,
        "bad_gadget_poly",
    )

    # Modify seed in helper input share.
    bad_input_share_1_temp = list(cast(tuple[Any, ...], input_share_1))
    modified_helper_seed = bytearray(bad_input_share_1_temp[0])
    modified_helper_seed[0] ^= 1
    bad_input_share_1_temp[0] = modified_helper_seed
    bad_input_share_1 = tuple(bad_input_share_1_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3count,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        input_share_0,
        bad_input_share_1,
        test_vec_path,
        "bad_helper_seed",
    )

    prio3histogram = Prio3Histogram(2, 5, 2)
    rand = test_vec_gen_rand(prio3histogram.RAND_SIZE)
    public_share, [input_share_0, input_share_1] = prio3histogram.shard(
        ctx,
        3,
        nonce,
        rand,
    )

    # Modify leader joint randomness blind.
    bad_input_share_0_temp = list(cast(tuple[Any, ...], input_share_0))
    modified_leader_blind = bytearray(bad_input_share_0_temp[2])
    modified_leader_blind[0] ^= 1
    bad_input_share_0_temp[2] = modified_leader_blind
    bad_input_share_0 = tuple(bad_input_share_0_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3histogram,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        bad_input_share_0,
        input_share_1,
        test_vec_path,
        "bad_leader_jr_blind",
    )

    # Modify helper joint randomness blind.
    bad_input_share_1_temp = list(cast(tuple[Any, ...], input_share_1))
    modified_helper_blind = bytearray(bad_input_share_1_temp[1])
    modified_helper_blind[0] ^= 1
    bad_input_share_1_temp[1] = modified_helper_blind
    bad_input_share_1 = tuple(bad_input_share_1_temp)
    _prio3_verifier_shares_to_message_failure(
        prio3histogram,
        verify_key,
        nonce,
        rand,
        ctx,
        public_share,
        input_share_0,
        bad_input_share_1,
        test_vec_path,
        "bad_helper_jr_blind",
    )

    # Modify public share.
    assert public_share is not None
    bad_public_share = list(public_share)
    modified_joint_rand_part = bytearray(bad_public_share[0])
    modified_joint_rand_part[0] ^= 1
    bad_public_share[0] = bytes(modified_joint_rand_part)
    _prio3_verifier_shares_to_message_failure(
        prio3histogram,
        verify_key,
        nonce,
        rand,
        ctx,
        bad_public_share,
        input_share_0,
        input_share_1,
        test_vec_path,
        "bad_public_share",
    )

    # Modify joint randomness seed in the verifier message.
    (verify_state_0, verifier_share_0) = prio3histogram.verify_init(
        verify_key,
        ctx,
        0,
        None,
        nonce,
        public_share,
        input_share_0,
    )
    bad_verifier_message = bytes([0] * prio3histogram.xof.SEED_SIZE)
    try:
        prio3histogram.verify_next(ctx, verify_state_0, bad_verifier_message)
    except ValueError:
        pass
    else:
        raise Exception("pep_next should fail")
    test_vec: VdafTestVectorDict = {
        'operations': [
            {
                'operation': 'verify_init',
                'aggregator_id': 0,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verify_next',
                'aggregator_id': 0,
                'round': 1,
                'report_index': 0,
                'success': False,
            },
        ],
        'shares': 2,
        'verify_key': verify_key.hex(),
        'agg_param': '',
        'ctx': ctx.hex(),
        'reports': [{
            'measurement': None,
            'rand': rand.hex(),
            'nonce': nonce.hex(),
            'public_share': prio3histogram.encode_public_share(
                public_share,
            ).hex(),
            'input_shares': [
                prio3histogram.encode_input_share(
                    input_share_0,
                ).hex(),
                prio3histogram.encode_input_share(
                    input_share_1,
                ).hex(),
            ],
            'verifier_shares': [[
                prio3histogram.encode_verifier_share(verifier_share_0).hex(),
            ]],
            'verifier_messages': [
                bad_verifier_message.hex(),
            ],
            'out_shares': [],
        }],
        'agg_shares': [],
        'agg_result': None,
    }
    type_params = prio3histogram.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )
    pretty_print_vdaf_test_vec(
        prio3histogram,
        test_vec,
        type_params,
    )
    write_test_vec(
        test_vec_path,
        test_vec,
        prio3histogram.test_vec_name,
        "bad_verifier_message",
    )


def _prio3_verifier_shares_to_message_failure(
        vdaf: Prio3,
        verify_key: bytes,
        nonce: bytes,
        rand: bytes,
        ctx: bytes,
        public_share: list[bytes] | None,
        input_share_0: Prio3InputShare,
        input_share_1: Prio3InputShare,
        test_vec_path: str,
        filename_suffix: str) -> None:
    """
    Takes in a corrupt report that will fail verification during
    verifier_shares_to_message, runs the verification algorithms, and outputs a test
    vector.
    """
    (_verify_state_0, verifier_share_0) = vdaf.verify_init(
        verify_key,
        ctx,
        0,
        None,
        nonce,
        public_share,
        input_share_0,
    )
    (_verify_state_1, verifier_share_1) = vdaf.verify_init(
        verify_key,
        ctx,
        1,
        None,
        nonce,
        public_share,
        input_share_1,
    )
    try:
        vdaf.verifier_shares_to_message(
            ctx, None, [verifier_share_0, verifier_share_1])
    except ValueError:
        pass
    else:
        raise Exception("verifier_shares_to_message should fail")
    test_vec: VdafTestVectorDict = {
        'operations': [
            {
                'operation': 'verify_init',
                'aggregator_id': 0,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verify_init',
                'aggregator_id': 1,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verifier_shares_to_message',
                'round': 0,
                'report_index': 0,
                'success': False,
            },
        ],
        'shares': 2,
        'verify_key': verify_key.hex(),
        'agg_param': '',
        'ctx': ctx.hex(),
        'reports': [{
            'measurement': None,
            'rand': rand.hex(),
            'nonce': nonce.hex(),
            'public_share': vdaf.encode_public_share(public_share).hex(),
            'input_shares': [
                vdaf.encode_input_share(input_share_0).hex(),
                vdaf.encode_input_share(input_share_1).hex(),
            ],
            'verifier_shares': [[
                vdaf.encode_verifier_share(verifier_share_0).hex(),
                vdaf.encode_verifier_share(verifier_share_1).hex(),
            ]],
            'verifier_messages': [],
            'out_shares': [],
        }],
        'agg_shares': [],
        'agg_result': None,
    }
    type_params = vdaf.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )
    pretty_print_vdaf_test_vec(
        vdaf,
        test_vec,
        type_params,
    )
    write_test_vec(
        test_vec_path,
        test_vec,
        vdaf.test_vec_name,
        filename_suffix,
    )


def gen_poplar1_negative_test_vec(test_vec_path: str, ctx: bytes) -> None:
    """
    Generates various negative test vectors for Poplar1.
    """

    vdaf = Poplar1(2)
    nonce = test_vec_gen_rand(vdaf.NONCE_SIZE)
    rand = test_vec_gen_rand(vdaf.RAND_SIZE)
    measurement = (False, True)
    public_share, [input_share_0, input_share_1] = vdaf.shard(
        ctx,
        measurement,
        nonce,
        rand,
    )
    verify_key = test_vec_gen_rand(vdaf.VERIFY_KEY_SIZE)
    agg_param = (0, [(False,), (True,)])

    # Modify correlated randomness.
    bad_input_share_0_temp = list(input_share_0)
    modified_correlated_randomness = list(
        cast(list[Field64], bad_input_share_0_temp[2]))
    modified_correlated_randomness[0] += Field64(1)
    bad_input_share_0_temp[2] = modified_correlated_randomness
    bad_input_share_0 = cast(Poplar1InputShare,
                             tuple(bad_input_share_0_temp))
    (verify_state_r0_a0, verifier_share_r0_a0) = vdaf.verify_init(
        verify_key,
        ctx,
        0,
        agg_param,
        nonce,
        public_share,
        bad_input_share_0,
    )
    (verify_state_r0_a1, verifier_share_r0_a1) = vdaf.verify_init(
        verify_key,
        ctx,
        1,
        agg_param,
        nonce,
        public_share,
        input_share_1,
    )
    verifier_message = vdaf.verifier_shares_to_message(
        ctx,
        agg_param,
        [verifier_share_r0_a0, verifier_share_r0_a1],
    )
    (verify_state_r1_a0, verifier_share_r1_a0) = vdaf.verify_next(
        ctx,
        verify_state_r0_a0,
        verifier_message,
    )
    (verify_state_r1_a1, verifier_share_r1_a1) = vdaf.verify_next(
        ctx,
        verify_state_r0_a1,
        verifier_message,
    )
    try:
        vdaf.verifier_shares_to_message(
            ctx,
            agg_param,
            [
                cast(FieldVec, verifier_share_r1_a0),
                cast(FieldVec, verifier_share_r1_a1),
            ],
        )
    except ValueError:
        pass
    else:
        raise Exception("verifier_shares_to_message should fail")
    test_vec: VdafTestVectorDict = {
        'operations': [
            {
                'operation': 'verify_init',
                'aggregator_id': 0,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verify_init',
                'aggregator_id': 1,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verifier_shares_to_message',
                'round': 0,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verify_next',
                'round': 1,
                'aggregator_id': 0,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verify_next',
                'round': 1,
                'aggregator_id': 1,
                'report_index': 0,
                'success': True,
            },
            {
                'operation': 'verifier_shares_to_message',
                'round': 1,
                'report_index': 0,
                'success': False,
            },
        ],
        'shares': 2,
        'verify_key': verify_key.hex(),
        'agg_param': vdaf.encode_agg_param(agg_param).hex(),
        'ctx': ctx.hex(),
        'reports': [{
            'measurement': None,
            'rand': rand.hex(),
            'nonce': nonce.hex(),
            'public_share': vdaf.encode_public_share(public_share).hex(),
            'input_shares': [
                vdaf.encode_input_share(bad_input_share_0).hex(),
                vdaf.encode_input_share(input_share_1).hex(),
            ],
            'verifier_shares': [
                [
                    vdaf.encode_verifier_share(verifier_share_r0_a0).hex(),
                    vdaf.encode_verifier_share(verifier_share_r0_a1).hex(),
                ],
                [
                    vdaf.encode_verifier_share(
                        cast(FieldVec, verifier_share_r1_a0)).hex(),
                    vdaf.encode_verifier_share(
                        cast(FieldVec, verifier_share_r1_a1)).hex(),
                ],
            ],
            'verifier_messages': [
                vdaf.encode_verifier_message(verifier_message).hex(),
            ],
            'out_shares': [],
        }],
        'agg_shares': [],
        'agg_result': None,
    }
    type_params = vdaf.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )
    pretty_print_vdaf_test_vec(
        vdaf,
        test_vec,
        type_params,
    )
    write_test_vec(
        test_vec_path,
        test_vec,
        vdaf.test_vec_name,
        "bad_corr_inner",
    )


def main() -> None:
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
        vdaf_prio3.Prio3SumVec(2, 10, 255, 9),
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
        vdaf_prio3.Prio3SumVec(3, 3, 32000, 7),
        None,
        ctx,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        1,
    )

    # Prio3SumVec with a different field and multiple proofs
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        vdaf_prio3.Prio3SumVecWithMultiproof(2, Field64, 3, 10, 255, 9),
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
        vdaf_prio3.Prio3SumVecWithMultiproof(3, Field64, 3, 3, 65535, 7),
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
        ctx,
        0,
    )

    # XOFs
    gen_test_vec_for_xof(xof.XofTurboShake128)
    gen_test_vec_for_xof(xof.XofFixedKeyAes128)

    gen_prio3_negative_test_vec(vdaf_test_vec_path, ctx)

    gen_poplar1_negative_test_vec(vdaf_test_vec_path, ctx)


if __name__ == '__main__':
    main()
