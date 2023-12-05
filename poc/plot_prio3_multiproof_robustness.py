# prio3_multiproof_robustness.py - Plot robustness bounds for various parameters.
# Use `sage -python prio3_multiproof_robustness.py`
import math

import matplotlib.pyplot as plt

from field import Field64, Field128
from vdaf_prio3 import Prio3SumVec

NUM_REPORTS = 1000000000


def soundness(gadget_calls, gadget_degree, field_size):
    '''
    ia.cr/2019/188, Theorem 4.3

    gadget_calls - number of times the gadget is called

    gadget_degree - arithmetic degree of the gadget

    field_size - size of the field
    '''
    return gadget_calls * gadget_degree / (field_size - gadget_calls)


def robustness(epsilon, ro_queries, prep_queries, num_proofs, seed_bits):
    '''
    ia.cr/2023/130, Theorem 1, assuming the bound can be modified by raising
    `epsilon` to the power of the number of FLPs.

    epsilon - soundness of the base FLP

    ro_queries - random oracle queries, a proxy for the amount of precomputation
                 done by the adversary

    prep_queries - number of online attempts, a proxy for the batch size

    num_proofs - number of FLPs

    seed_bits - the size of the XOF seed in bits
    '''
    return (ro_queries + prep_queries) * epsilon**num_proofs + \
           (ro_queries + prep_queries**2) / 2**(seed_bits - 1)


def sum_vec(field_size, num_proofs, length):
    '''
    Prio3SumVec (draft-irtf-cfrg-vdaf-08, Section 7.4.3): Probability of
    accepting one report in a batch of NUM_REPORTS. Assuming the asymptotically
    optimal chunk length.
    '''
    bits = 1
    chunk_length = max(1, length**(1/2))
    vdaf = Prio3SumVec.with_params(length, bits, chunk_length)
    gadget_calls = vdaf.Flp.Valid.GADGET_CALLS[0]
    gadget_degree = vdaf.Flp.Valid.GADGETS[0].DEGREE

    base_flp_soundness = soundness(gadget_calls, gadget_degree, field_size)

    # SumVec interprets the inner Mul-gadget outputs as coefficients of a
    # polynomial and evaluates the polynomial at a random point. If a gadget
    # output is non-zero, then the output is non-zero except with this
    # probability. This is bounded by the number of roots of the polynomial.
    circuit_soundness = length * bits / field_size

    return robustness(
        base_flp_soundness + circuit_soundness,  # ia.cr/2019/188, Theorem 5.3
        2**80,
        NUM_REPORTS,
        num_proofs,
        vdaf.Xof.SEED_SIZE * 8,
    )


print(math.log2(sum_vec(Field128.MODULUS, 1, 100000)))

lengths = range(100, 10**6, 100)
plt.plot(
    lengths,
    [sum_vec(Field128.MODULUS, 1, length) for length in lengths],
    label='Field128/1',
)
plt.plot(
    lengths,
    [sum_vec(Field64.MODULUS, 2, length) for length in lengths],
    label='Field64/2',
)
plt.plot(
    lengths,
    [sum_vec(Field64.MODULUS, 3, length) for length in lengths],
    label='Field64/3',
)

plt.xscale('log', base=10)
plt.yscale('log', base=2)
plt.xlabel('Length')
plt.ylabel('Prob(1 in {} accepted reports being invalid)'.format(NUM_REPORTS))
plt.title('Prio3SumvVec (field/number of proofs)')
plt.legend()
plt.grid()
plt.show()
