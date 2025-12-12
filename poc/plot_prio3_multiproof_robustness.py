#!/usr/bin/env python3
# Plot robustness bounds for various parameters.
#
# python plot_prio3_multiproof_robustness.py
import math
from typing import TypeVar

import matplotlib.pyplot as plt

from vdaf_poc.field import Field64, Field128, NttField
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19, SumVec

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)


def base_soundness(flp: FlpBBCGGI19[Measurement, AggResult, F]) -> float:
    '''
    ia.cr/2019/188, Theorem 4.3
    '''
    return sum((g_calls * g.DEGREE) / (flp.field.MODULUS - g_calls)
               for (g, g_calls) in zip(flp.valid.GADGETS, flp.valid.GADGET_CALLS))


def robustness(
        soundness: float,
        ro_queries: int,
        verify_queries: int,
        num_proofs: int) -> float:
    '''
    ia.cr/2023/130, Theorem 1, assuming the bound can be modified by raising
    `epsilon` to the power of the number of FLPs. We're also assuming the first
    term dominates, i.e., we're ignoring the seed size.

    soundness - soundness of the FLP

    ro_queries - random oracle queries, a proxy for the amount of
                 precomputation done by the adversary

    verify_queries - number of online attempts, a proxy for the batch size

    num_proofs - number of FLPs
    '''
    return (ro_queries + verify_queries) * soundness**num_proofs


def sum_vec(field: type[NttField], num_proofs: int, length: int) -> float:
    '''
    Maximum probability of at least 1 in 1 billion attacks on Prio3SumVec
    robustness succeeding after doing 2**80 random oracle queries.
    '''
    max_measurement = 1
    chunk_length = max(1, length**(1/2))
    flp = FlpBBCGGI19(SumVec(field, length, max_measurement, chunk_length))

    # Assuming we adopt the improvement from
    # https://github.com/cfrg/draft-irtf-cfrg-vdaf/issues/427
    soundness = chunk_length / field.MODULUS + base_soundness(flp)

    return robustness(
        soundness,
        2**80,          # ro queries
        1_000_000_000,  # verify queries
        num_proofs,
    )


if __name__ == '__main__':
    print(-math.log2(sum_vec(Field128, 1, 100_000)))
    print(-math.log2(sum_vec(Field64, 3, 100_000)))
    print(-math.log2(sum_vec(Field64, 2, 100_000)))
    print(-math.log2(sum_vec(Field64, 1, 100_000)))

    lengths = range(100, 10**6, 100)
    plt.plot(
        lengths,
        [sum_vec(Field128, 1, length) for length in lengths],
        label='Field128/1',
    )
    plt.plot(
        lengths,
        [sum_vec(Field64, 3, length) for length in lengths],
        label='Field64/3',
    )
    plt.plot(
        lengths,
        [sum_vec(Field64, 2, length) for length in lengths],
        label='Field64/2',
    )
    # plt.plot(
    #     lengths,
    #     [sum_vec(Field64, 1, length) for length in lengths],
    #     label='Field64/1',
    # )

    plt.xscale('log', base=10)
    plt.yscale('log', base=2)
    plt.xlabel('Length')
    plt.ylabel('Prob')
    plt.title('Prio3SumvVec (field/number of proofs)')
    plt.legend()
    plt.grid()
    plt.show()
