import unittest
from typing import TypeVar

from tests.test_flp import FlpTest
from tests.test_flp_bbcggi19 import TestAverage
from vdaf_poc.common import TEST_VECTOR
from vdaf_poc.field import FftField, Field64, Field128
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19
from vdaf_poc.vdaf import test_vdaf
from vdaf_poc.vdaf_prio3 import (Prio3, Prio3Count, Prio3Histogram,
                                 Prio3MultihotCountVec, Prio3Sum, Prio3SumVec,
                                 Prio3SumVecWithMultiproof)
from vdaf_poc.xof import XofTurboShake128

F = TypeVar("F", bound=FftField)


class TestPrio3Average(Prio3):
    """
    A Prio3 instantiation to test use of num_measurements in the Valid
    class's decode() method.
    """

    xof = XofTurboShake128
    # NOTE 0xFFFFFFFF is reserved for testing. If we decide to standardize this
    # Prio3 variant, then we'll need to pick a real codepoint for it.
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    def __init__(self, shares: int, bits: int):
        flp = FlpBBCGGI19(TestAverage(Field128, bits))
        super().__init__(shares, flp, 1)


def test_prio3sumvec(num_proofs: int, field: type[F]) -> None:
    multiproof = Prio3SumVecWithMultiproof[F](2, field, num_proofs, 10, 8, 9)

    assert multiproof.ID == 0xFFFFFFFF
    assert multiproof.PROOFS == num_proofs

    test_vdaf(
        multiproof,
        None,
        [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
        [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
    )
    test_vdaf(
        multiproof,
        None,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        list(range(256, 266)),
        print_test_vec=False,
    )

    prio3 = Prio3SumVec(3, 3, 16, 7)
    test_vdaf(
        prio3,
        None,
        [
            [10000, 32000, 9],
            [19342, 19615, 3061],
            [15986, 24671, 23910]
        ],
        [45328, 76286, 26980],
        print_test_vec=False,
        test_vec_instance=1,
    )


class Prio3FlpTest(Prio3):
    ID = 0xFFFFFFFF
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    def __init__(self, joint_rand_len: int):
        flp = FlpTest(Field128, joint_rand_len)
        super().__init__(2, flp, 1)


class TestPrio3(unittest.TestCase):
    def test_flp_test(self) -> None:
        prio3 = Prio3FlpTest(1)
        test_vdaf(prio3, None, [1, 2, 3, 4, 4], 14)

        # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
        # generating the joint randomness.
        prio3 = Prio3FlpTest(0)
        test_vdaf(prio3, None, [1, 2, 3, 4, 4], 14)

    def test_count(self) -> None:
        prio3 = Prio3Count(2)
        assert prio3.ID == 0x00000000
        test_vdaf(prio3, None, [0, 1, 1, 0, 1], 3)
        test_vdaf(prio3, None, [1], 1, print_test_vec=TEST_VECTOR)

    def test_count_3_shares(self) -> None:
        prio3 = Prio3Count(3)
        test_vdaf(prio3, None, [1], 1, print_test_vec=TEST_VECTOR,
                  test_vec_instance=1)

    def test_sum(self) -> None:
        prio3 = Prio3Sum(2, 8)
        assert prio3.ID == 0x00000001
        test_vdaf(prio3, None, [0, 147, 1, 0, 11, 0], 159)
        test_vdaf(prio3, None, [100], 100, print_test_vec=TEST_VECTOR)

    def test_sum_3_shares(self) -> None:
        prio3 = Prio3Sum(3, 8)
        test_vdaf(prio3, None, [100], 100, print_test_vec=TEST_VECTOR,
                  test_vec_instance=1)

    def test_sum_vec(self) -> None:
        prio3 = Prio3SumVec(2, 10, 8, 9)
        assert prio3.ID == 0x00000002
        test_vdaf(
            prio3,
            None,
            [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
            [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
        )
        test_vdaf(
            prio3,
            None,
            [
                list(range(10)),
                [1] * 10,
                [255] * 10
            ],
            list(range(256, 266)),
            print_test_vec=TEST_VECTOR,
        )

    def test_sum_vec_3_shares(self) -> None:
        prio3 = Prio3SumVec(3, 3, 16, 7)
        test_vdaf(
            prio3,
            None,
            [
                [10000, 32000, 9],
                [19342, 19615, 3061],
                [15986, 24671, 23910]
            ],
            [45328, 76286, 26980],
            print_test_vec=TEST_VECTOR,
            test_vec_instance=1,
        )

    def test_histogram(self) -> None:
        prio3 = Prio3Histogram(2, 4, 2)
        assert prio3.ID == 0x00000003
        test_vdaf(prio3, None, [0], [1, 0, 0, 0])
        test_vdaf(prio3, None, [1], [0, 1, 0, 0])
        test_vdaf(prio3, None, [2], [0, 0, 1, 0])
        test_vdaf(prio3, None, [3], [0, 0, 0, 1])
        test_vdaf(prio3, None, [0, 0, 1, 1, 2, 2, 3, 3], [2, 2, 2, 2])
        test_vdaf(prio3, None, [2], [0, 0, 1, 0], print_test_vec=TEST_VECTOR)
        prio3 = Prio3Histogram(3, 11, 3)
        test_vdaf(
            prio3,
            None,
            [2],
            [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            print_test_vec=TEST_VECTOR,
            test_vec_instance=1,
        )

    def test_multihot_count_vec(self) -> None:
        # Prio3MultihotCountVec with length = 4, max_weight = 2,
        # chunk_length = 2.
        prio3 = Prio3MultihotCountVec(2, 4, 2, 2)
        assert prio3.ID == 0x00000004
        test_vdaf(prio3, None, [[0, 0, 0, 0]], [0, 0, 0, 0])
        test_vdaf(prio3, None, [[0, 1, 0, 0]], [0, 1, 0, 0])
        test_vdaf(prio3, None, [[0, 1, 1, 0]], [0, 1, 1, 0])
        test_vdaf(prio3, None, [[0, 1, 1, 0], [0, 1, 0, 1]], [0, 2, 1, 1])
        test_vdaf(
            prio3, None, [[0, 1, 1, 0]], [0, 1, 1, 0], print_test_vec=TEST_VECTOR
        )

    def test_multi_hot_histogram_3_shares(self) -> None:
        # Prio3MultihotCountVec with length = 11, max_weight = 5,
        # chunk_length = 3.
        prio3 = Prio3MultihotCountVec(3, 11, 5, 3)
        test_vdaf(
            prio3,
            None,
            [[1] * 5 + [0] * 6],
            [1] * 5 + [0] * 6,
            print_test_vec=False,
            test_vec_instance=1,
        )

    def test_average(self) -> None:
        prio3 = TestPrio3Average(2, 3)
        test_vdaf(prio3, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    def test_is_valid(self) -> None:
        prio3 = TestPrio3Average(2, 3)
        # Test `is_valid` returns True on empty previous_agg_params, and False
        # otherwise.
        assert prio3.is_valid(None, list([]))
        assert not prio3.is_valid(None, list([None]))

    def test_multiproof(self) -> None:
        for n in range(2, 5):
            test_prio3sumvec(num_proofs=n, field=Field64)
