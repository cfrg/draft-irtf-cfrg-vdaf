import json
import os
from typing import Any, Generic, Optional, TypedDict, TypeVar, cast

from vdaf_poc.common import VERSION, print_wrapped_line, to_le_bytes
from vdaf_poc.field import Field128
from vdaf_poc.idpf import Idpf
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.xof import Xof

Measurement = TypeVar("Measurement")
AggParam = TypeVar("AggParam")
PublicShare = TypeVar("PublicShare")
InputShare = TypeVar("InputShare")
OutShare = TypeVar("OutShare")
AggShare = TypeVar("AggShare")
AggResult = TypeVar("AggResult")
PrepState = TypeVar("PrepState")
PrepShare = TypeVar("PrepShare")
PrepMessage = TypeVar("PrepMessage")

# The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH',
                                  '../test_vec/{:02}'.format(VERSION))


def gen_rand(length: int) -> bytes:
    """
    A dummy source of randomness intended for creating reproducible test vectors.
    """
    out = []
    for i in range(length):
        out.append(i % 256)
    return bytes(out)


# VDAF

class VdafPrepTestVectorDict(Generic[Measurement], TypedDict):
    measurement: Measurement
    nonce: str
    input_shares: list[str]
    prep_shares: list[list[str]]
    prep_messages: list[str]
    out_shares: list[list[str]]
    rand: str
    public_share: str


class VdafTestVectorDict(Generic[Measurement, AggParam, AggResult], TypedDict):
    shares: int
    verify_key: str
    agg_param: AggParam
    prep: list[VdafPrepTestVectorDict[Measurement]]
    agg_shares: list[str]
    agg_result: Optional[AggResult]


def gen_test_vec_for_vdaf(
        vdaf: Vdaf[
            Measurement,
            AggParam,
            PublicShare,
            InputShare,
            list[Any],  # OutShare
            AggShare,
            AggResult,
            PrepState,
            PrepShare,
            PrepMessage,
        ],
        agg_param: AggParam,
        measurements: list[Measurement],
        test_vec_instance: int,
        print_test_vec: bool = True) -> AggResult:
    """
    Generate test vectors for a VDAF.
    """

    nonces = [gen_rand(vdaf.NONCE_SIZE) for _ in range(len(measurements))]
    verify_key = gen_rand(vdaf.VERIFY_KEY_SIZE)

    test_vec: VdafTestVectorDict[Measurement, AggParam, AggResult] = {
        'shares': vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': agg_param,
        'prep': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_params = vdaf.test_vec_set_type_param(
        cast(dict[str, Any], test_vec)
    )

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == vdaf.NONCE_SIZE

        # Each Client shards its measurement into input shares.
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(measurement, nonce, rand)

        prep_test_vec: VdafPrepTestVectorDict[Measurement] = {
            'measurement': measurement,
            'nonce': nonce.hex(),
            'input_shares': [],
            'prep_shares': [[] for _ in range(vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
            'rand': rand.hex(),
            'public_share': vdaf.test_vec_encode_public_share(
                public_share
            ).hex()
        }
        for input_share in input_shares:
            prep_test_vec['input_shares'].append(
                vdaf.test_vec_encode_input_share(input_share).hex())

        # Each Aggregator initializes its preparation state.
        prep_states = []
        outbound_prep_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.prep_init(verify_key, j,
                                            agg_param,
                                            nonce,
                                            public_share,
                                            input_shares[j])
            prep_states.append(state)
            outbound_prep_shares.append(share)

        for prep_share in outbound_prep_shares:
            prep_test_vec['prep_shares'][0].append(
                vdaf.test_vec_encode_prep_share(prep_share).hex())

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS - 1):
            prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                                outbound_prep_shares)
            prep_test_vec['prep_messages'].append(
                vdaf.test_vec_encode_prep_msg(prep_msg).hex())

            outbound_prep_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(prep_states[j], prep_msg)
                assert isinstance(out, tuple)
                (prep_states[j], prep_share) = out
                outbound_prep_shares.append(prep_share)
            # REMOVE ME
            for prep_share in outbound_prep_shares:
                prep_test_vec['prep_shares'][i+1].append(
                    vdaf.test_vec_encode_prep_share(prep_share).hex()
                )

        # The final outputs of the prepare phase are the output
        # shares.
        prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                            outbound_prep_shares)
        prep_test_vec['prep_messages'].append(
            vdaf.test_vec_encode_prep_msg(prep_msg).hex())

        outbound_out_shares = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(prep_states[j], prep_msg)
            assert not isinstance(out_share, tuple)
            outbound_out_shares.append(out_share)

        for out_share in outbound_out_shares:
            prep_test_vec['out_shares'].append([
                to_le_bytes(x.as_unsigned(), x.ENCODED_SIZE).hex()
                for x in out_share
            ])
        test_vec['prep'].append(prep_test_vec)

        out_shares.append(outbound_out_shares)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.aggregate(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)
        # REMOVE ME
        test_vec['agg_shares'].append(
            vdaf.test_vec_encode_agg_share(agg_share_j).hex())

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    test_vec['agg_result'] = agg_result
    if print_test_vec:
        pretty_print_vdaf_test_vec(vdaf, test_vec, type_params)

        os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
        filename = '{}/{}_{}.json'.format(
            TEST_VECTOR_PATH,
            vdaf.test_vec_name,
            test_vec_instance,
        )
        with open(filename, 'w', encoding="UTF-8") as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def pretty_print_vdaf_test_vec(
        vdaf: Vdaf[
            Measurement, AggParam, Any, Any, Any, Any, AggResult, Any, Any, Any
        ],
        typed_test_vec: VdafTestVectorDict[Measurement, AggParam, AggResult],
        type_params: list[str]) -> None:
    test_vec = cast(dict[str, Any], typed_test_vec)
    print('---------- {} ---------------'.format(vdaf.test_vec_name))
    for type_param in type_params:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] is not None:
        print('agg_param: {}'.format(test_vec['agg_param']))

    for (n, prep_test_vec) in enumerate(test_vec['prep']):
        print('upload_{}:'.format(n))
        print('  measurement: {}'.format(prep_test_vec['measurement']))
        print('  nonce: "{}"'.format(prep_test_vec['nonce']))
        print('  public_share: >-')
        print_wrapped_line(prep_test_vec['public_share'], tab=4)

        # Shard
        for (i, input_share) in enumerate(prep_test_vec['input_shares']):
            print('  input_share_{}: >-'.format(i))
            print_wrapped_line(input_share, tab=4)

        # Prepare
        for (i, (prep_shares, prep_msg)) in enumerate(
                zip(prep_test_vec['prep_shares'],
                    prep_test_vec['prep_messages'])):
            print('  round_{}:'.format(i))
            for (j, prep_share) in enumerate(prep_shares):
                print('    prep_share_{}: >-'.format(j))
                print_wrapped_line(prep_share, tab=6)
            print('    prep_message: >-')
            print_wrapped_line(prep_msg, tab=6)

        for (j, out_shares) in enumerate(prep_test_vec['out_shares']):
            print('  out_share_{}:'.format(j))
            for out_share in out_shares:
                print('    - {}'.format(out_share))

    # Aggregate
    for (j, agg_share) in enumerate(test_vec['agg_shares']):
        print('agg_share_{}: >-'.format(j))
        print_wrapped_line(agg_share, tab=2)

    # Unshard
    print('agg_result: {}'.format(test_vec['agg_result']))
    print()


# IDPF

def gen_test_vec_for_idpf(idpf: Idpf,
                          alpha: int,
                          test_vec_instance: int) -> None:
    beta_inner = []
    for level in range(idpf.BITS - 1):
        beta_inner.append([idpf.field_inner(level)] * idpf.VALUE_LEN)
    beta_leaf = [idpf.field_leaf(idpf.BITS - 1)] * idpf.VALUE_LEN
    rand = gen_rand(idpf.RAND_SIZE)
    nonce = gen_rand(idpf.NONCE_SIZE)
    (public_share, keys) = idpf.gen(alpha, beta_inner, beta_leaf, nonce, rand)

    printable_beta_inner = [
        [str(elem.as_unsigned()) for elem in value] for value in beta_inner
    ]
    printable_beta_leaf = [str(elem.as_unsigned()) for elem in beta_leaf]
    printable_keys = [key.hex() for key in keys]
    test_vec = {
        'bits': int(idpf.BITS),
        'alpha': str(alpha),
        'beta_inner': printable_beta_inner,
        'beta_leaf': printable_beta_leaf,
        'nonce': nonce.hex(),
        'public_share': public_share.hex(),
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


if __name__ == '__main__':
    from vdaf_poc import idpf_bbcggi21, vdaf_poplar1, vdaf_prio3, xof

    # Prio3 variants
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Count(2), None, [1], 0)
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Count(3), None, [1], 1)
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Sum(2, 8), None, [100], 0)
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Sum(3, 8), None, [100], 1)
    gen_test_vec_for_vdaf(
        vdaf_prio3.Prio3SumVec(2, 10, 8, 9),
        None,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        0,
    )
    gen_test_vec_for_vdaf(
        vdaf_prio3.Prio3SumVec(3, 3, 16, 7),
        None,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        1,
    )
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Histogram(2, 4, 2),  None, [2], 0)
    gen_test_vec_for_vdaf(vdaf_prio3.Prio3Histogram(3, 11, 3),  None, [2], 1)
    gen_test_vec_for_vdaf(
        vdaf_prio3.Prio3MultihotCountVec(2, 4, 2, 2),
        None,
        [[0, 1, 1, 0]],
        0,
    )

    # Poplar1
    tests = [
        (0, (0, 1)),
        (1, (0, 1, 2, 3)),
        (2, (0, 2, 4, 6)),
        (3, (1, 3, 5, 7, 9, 13, 15)),
    ]
    for (test_level, prefixes) in tests:
        gen_test_vec_for_vdaf(
            vdaf_poplar1.Poplar1(4),
            (test_level, prefixes),
            [0b1101],
            test_level,
        )

    # IdpfBBCGGI21
    gen_test_vec_for_idpf(idpf_bbcggi21.IdpfBBCGGI21(2, 10), 0, 0)

    # XOFs
    gen_test_vec_for_xof(xof.XofTurboShake128)
    gen_test_vec_for_xof(xof.XofFixedKeyAes128)
