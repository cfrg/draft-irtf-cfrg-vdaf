import json
import os
from functools import reduce

from common import TEST_VECTOR_PATH, gen_rand, vec_add


def test_idpf(Idpf, alpha, level, prefixes):
    """
    Generate a set of IDPF keys and evaluate them on the given set of prefix.
    """
    beta_inner = [[Idpf.FieldInner(1)] * Idpf.VALUE_LEN] * (Idpf.BITS-1)
    beta_leaf = [Idpf.FieldLeaf(1)] * Idpf.VALUE_LEN

    # Generate the IDPF keys.
    rand = gen_rand(Idpf.RAND_SIZE)
    binder = b'some nonce'
    (public_share, keys) = Idpf.gen(alpha, beta_inner, beta_leaf, binder, rand)

    out = [Idpf.current_field(level).zeros(Idpf.VALUE_LEN)] * len(prefixes)
    for agg_id in range(Idpf.SHARES):
        out_share = Idpf.eval(
            agg_id, public_share, keys[agg_id], level, prefixes, binder)
        for i in range(len(prefixes)):
            out[i] = vec_add(out[i], out_share[i])

    for (got, prefix) in zip(out, prefixes):
        if Idpf.is_prefix(prefix, alpha, level):
            if level < Idpf.BITS-1:
                want = beta_inner[level]
            else:
                want = beta_leaf
        else:
            want = Idpf.current_field(level).zeros(Idpf.VALUE_LEN)

        if got != want:
            print('error: {0:b} {1:b} {2}: got {3}; want {4}'.format(
                alpha, prefix, level, got, want))


def test_idpf_exhaustive(Idpf, alpha):
    """Generate a set of IDPF keys and test every possible output."""

    # Generate random outputs with which to program the IDPF.
    beta_inner = []
    for _ in range(Idpf.BITS - 1):
        beta_inner.append(Idpf.FieldInner.rand_vec(Idpf.VALUE_LEN))
    beta_leaf = Idpf.FieldLeaf.rand_vec(Idpf.VALUE_LEN)

    # Generate the IDPF keys.
    rand = gen_rand(Idpf.RAND_SIZE)
    binder = b"some nonce"
    (public_share, keys) = Idpf.gen(alpha, beta_inner, beta_leaf, binder, rand)

    # Evaluate the IDPF at every node of the tree.
    for level in range(Idpf.BITS):
        prefixes = tuple(range(2 ** level))

        out_shares = []
        for agg_id in range(Idpf.SHARES):
            out_shares.append(
                Idpf.eval(agg_id, public_share,
                          keys[agg_id], level, prefixes, binder))

        # Check that each set of output shares for each prefix sums up to the
        # correct value.
        for prefix in prefixes:
            got = reduce(lambda x, y: vec_add(x, y),
                         map(lambda x: x[prefix], out_shares))

            if Idpf.is_prefix(prefix, alpha, level):
                if level < Idpf.BITS-1:
                    want = beta_inner[level]
                else:
                    want = beta_leaf
            else:
                want = Idpf.current_field(level).zeros(Idpf.VALUE_LEN)

            if got != want:
                print('error: {0:b} {1:b} {2}: got {3}; want {4}'.format(
                    alpha, prefix, level, got, want))


def gen_test_vec(Idpf, alpha, test_vec_instance):
    beta_inner = []
    for level in range(Idpf.BITS-1):
        beta_inner.append([Idpf.FieldInner(level)] * Idpf.VALUE_LEN)
    beta_leaf = [Idpf.FieldLeaf(Idpf.BITS-1)] * Idpf.VALUE_LEN
    rand = gen_rand(Idpf.RAND_SIZE)
    binder = b'some nonce'
    (public_share, keys) = Idpf.gen(alpha, beta_inner, beta_leaf, binder, rand)

    printable_beta_inner = [
        [str(elem.as_unsigned()) for elem in value] for value in beta_inner
    ]
    printable_beta_leaf = [str(elem.as_unsigned()) for elem in beta_leaf]
    printable_keys = [key.hex() for key in keys]
    test_vec = {
        'bits': int(Idpf.BITS),
        'alpha': str(alpha),
        'beta_inner': printable_beta_inner,
        'beta_leaf': printable_beta_leaf,
        'binder': binder.hex(),
        'public_share': public_share.hex(),
        'keys': printable_keys,
    }

    os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
    filename = '{}/{}_{}.json'.format(TEST_VECTOR_PATH, Idpf.test_vec_name,
                                      test_vec_instance)
    with open(filename, 'w') as f:
        json.dump(test_vec, f, indent=4, sort_keys=True)
        f.write('\n')
