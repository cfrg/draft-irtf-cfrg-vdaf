from functools import reduce
from typing import Sequence

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.idpf import Idpf


def test_idpf(idpf: Idpf, alpha: int, level: int, prefixes: Sequence[int]) -> None:
    """
    Generate a set of IDPF keys and evaluate them on the given set of prefix.
    """
    beta_inner = [[idpf.field_inner(1)] * idpf.VALUE_LEN] * (idpf.BITS - 1)
    beta_leaf = [idpf.field_leaf(1)] * idpf.VALUE_LEN

    # Generate the IDPF keys.
    rand = gen_rand(idpf.RAND_SIZE)
    nonce = gen_rand(idpf.NONCE_SIZE)
    (public_share, keys) = idpf.gen(alpha, beta_inner, beta_leaf, nonce, rand)

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

        if got != want:
            print('error: {0:b} {1:b} {2}: got {3}; want {4}'.format(
                alpha, prefix, level, got, want))


def test_idpf_exhaustive(idpf: Idpf, alpha: int) -> None:
    """Generate a set of IDPF keys and test every possible output."""

    # Generate random outputs with which to program the IDPF.
    beta_inner = []
    for _ in range(idpf.BITS - 1):
        beta_inner.append(idpf.field_inner.rand_vec(idpf.VALUE_LEN))
    beta_leaf = idpf.field_leaf.rand_vec(idpf.VALUE_LEN)

    # Generate the IDPF keys.
    rand = gen_rand(idpf.RAND_SIZE)
    nonce = gen_rand(idpf.NONCE_SIZE)
    (public_share, keys) = idpf.gen(alpha, beta_inner, beta_leaf, nonce, rand)

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

            if got != want:
                print('error: {0:b} {1:b} {2}: got {3}; want {4}'.format(
                    alpha, prefix, level, got, want))
