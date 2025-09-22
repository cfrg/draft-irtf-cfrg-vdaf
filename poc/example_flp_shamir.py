'''
Demonstration of the composition of FLP with Shamir's secret sharing. This
could be the basis of a Prio3 variant that tolerates drop out of an Aggregator.

Imagine a DAP setup [1] where a Leader wants to be able to run the protocol with
one of two Helpers so that if the first Helper goes offline, it can continue
the computation with the other.

For this to work, the Client still needs to know the identities of the two
Helpers prior to generating its report.

[1] https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/22
'''

from typing import TypeVar
from unittest import TestCase

from vdaf_poc.common import vec_add
from vdaf_poc.field import Field, Field64, Field128, poly_interp
from vdaf_poc.flp_bbcggi19 import Count, FlpBBCGGI19, Sum, SumVec

F = TypeVar("F", bound=Field)


def shamir_shard(field: type[F],
                 meas: list[F],
                 unshard_threshold: int,
                 num_shares: int) -> list[list[F]]:
    '''
    Compute Shamir's threshold secret sharing of `meas`. `num_shares` specifies
    the total of number of shares; `unshard_threshold` specifies the number of
    shares needed to unshard.
    '''
    # NOTE It would be more efficient to do "packed" Shamir by letting f(x) =
    # meas + rand_1 * x + rand_2 * x**2 + ..., and so on and letting the shares
    # be f(0), f(1), ..., and so on. That is:
    #
    # coeffs = [meas]
    # for _ in range(unshard_threshold):
    #    coeffs.append(field.rand_vec(len(meas)))
    #
    # meas_shares = []
    # for x in range(num_shares):
    #     f = field.zeros(len(meas))
    #     for (i, c) in enumerate(coeffs):
    #         for j in range(len(meas)):
    #             f[j] += c[j] * field(x)**i
    #     meas_shares.append(f)
    #
    # However we would need a version of `poly_interp()` that operates on
    # vectors over the field.
    meas_shares = [field.zeros(len(meas)) for _ in range(num_shares)]
    for i in range(len(meas)):
        coeffs = [meas[i]] + field.rand_vec(unshard_threshold-1)
        for j in range(num_shares):
            f = field(0)
            for (k, c) in enumerate(coeffs):
                x = field(j+1)
                f += c * x ** k
            meas_shares[j][i] = f
    return meas_shares


def shamir_unshard(field: type[F],
                   index: list[int],
                   meas_shares: list[list[F]]) -> list[F]:
    '''
    Combine Shamir secret shares `meas_share` into the underlying secret.
    `index` is indicates the index of each secret share. That is, `index[I]` is
    equal to the index of `meas_share[I]` in the output of `shamir_shard()`.
    '''
    meas_len = len(meas_shares[0])
    meas = []
    for i in range(meas_len):
        xs = []
        fs = []
        for (j, share) in zip(index, meas_shares):
            x = field(j+1)
            f = share[i]
            xs.append(x)
            fs.append(f)
        coeffs = poly_interp(field, xs, fs)
        meas.append(coeffs[0])
    return meas


class TestShamir(TestCase):
    def test_shard_unshard(self) -> None:
        '''Test the basic functionality.'''
        meas = [Field64(13), Field64(37)]
        meas_shares = shamir_shard(Field64, meas, 2, 3)

        got = shamir_unshard(Field64, [0, 1], [meas_shares[0], meas_shares[1]])
        self.assertEqual(got, meas)
        got = shamir_unshard(Field64, [0, 2], [meas_shares[0], meas_shares[2]])
        self.assertEqual(got, meas)
        got = shamir_unshard(Field64, [1, 2], [meas_shares[1], meas_shares[2]])
        self.assertEqual(got, meas)

    def test_aggregate(self) -> None:
        '''Show that Shamir secret sharing works with aggregation as well.'''
        unshard_threshold = 2
        num_shares = 3
        max_measurement = 100
        v = Sum(Field64, max_measurement)

        agg_shares = [v.field.zeros(v.OUTPUT_LEN)] * num_shares
        for x in range(max_measurement):
            meas = v.encode(x)
            meas_shares = shamir_shard(v.field,
                                       meas,
                                       unshard_threshold,
                                       num_shares)
            for j in range(num_shares):
                agg_shares[j] = vec_add(
                    agg_shares[j], v.truncate(meas_shares[j]))

        agg = shamir_unshard(v.field, [0, 1], [agg_shares[0], agg_shares[1]])
        agg_result = v.decode(agg, max_measurement)
        self.assertEqual(agg_result, max_measurement * (max_measurement-1) / 2)

    def test_flp_count(self) -> None:
        flp = FlpBBCGGI19(Count(Field64))
        prove_rand = flp.field.rand_vec(flp.PROVE_RAND_LEN)
        query_rand = flp.field.rand_vec(flp.QUERY_RAND_LEN)

        meas = flp.encode(False)
        meas_shares = shamir_shard(flp.field, meas, 2, 3)

        proof = flp.prove(meas, prove_rand, [])
        proof_shares = shamir_shard(flp.field, proof, 2, 3)

        verifier = shamir_unshard(
            flp.field,
            [0, 2],
            [
                flp.query(meas_shares[0], proof_shares[0], query_rand, [], 1),
                flp.query(meas_shares[2], proof_shares[2], query_rand, [], 1),
            ],
        )
        self.assertTrue(flp.decide(verifier))

    def test_flp_sum(self) -> None:
        flp = FlpBBCGGI19(Sum(Field64, 23))
        prove_rand = flp.field.rand_vec(flp.PROVE_RAND_LEN)
        query_rand = flp.field.rand_vec(flp.QUERY_RAND_LEN)

        meas = flp.encode(22)
        meas_shares = shamir_shard(flp.field, meas, 2, 3)

        proof = flp.prove(meas, prove_rand, [])
        proof_shares = shamir_shard(flp.field, proof, 2, 3)

        verifier = shamir_unshard(
            flp.field,
            [0, 2],
            [
                flp.query(meas_shares[0], proof_shares[0], query_rand, [], 1),
                flp.query(meas_shares[2], proof_shares[2], query_rand, [], 1),
            ],
        )
        self.assertTrue(flp.decide(verifier))

    def test_flp_sum_vec(self) -> None:
        flp = FlpBBCGGI19(SumVec(Field128, 100, 2, 10))
        prove_rand = flp.field.rand_vec(flp.PROVE_RAND_LEN)
        query_rand = flp.field.rand_vec(flp.QUERY_RAND_LEN)
        joint_rand = flp.field.rand_vec(flp.JOINT_RAND_LEN)

        meas = flp.encode([1] * 100)
        meas_shares = shamir_shard(flp.field, meas, 2, 3)

        proof = flp.prove(meas, prove_rand, joint_rand)
        proof_shares = shamir_shard(flp.field, proof, 2, 3)

        verifier = shamir_unshard(
            flp.field,
            [0, 2],
            [
                flp.query(meas_shares[0], proof_shares[0],
                          query_rand, joint_rand, 1),
                flp.query(meas_shares[2], proof_shares[2],
                          query_rand, joint_rand, 1),
            ],
        )
        self.assertTrue(flp.decide(verifier))
