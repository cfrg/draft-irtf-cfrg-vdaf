from typing import TypeVar

from tests.test_flp import FlpTest
from tests.test_flp_bbcggi19 import HigherDegree, TestAverage
from vdaf_poc.field import Field64, Field128, NttField
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19
from vdaf_poc.test_utils import TestVdaf
from vdaf_poc.vdaf_prio3 import (Prio3, Prio3Count, Prio3Histogram,
                                 Prio3MultihotCountVec, Prio3Sum, Prio3SumVec,
                                 Prio3SumVecWithMultiproof)
from vdaf_poc.xof import XofTurboShake128

F = TypeVar("F", bound=NttField)


class Prio3Average(Prio3):
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


class Prio3HigherDegree(Prio3):
    """
    A Prio3 instantiation for use in tests that incorporates a degree three
    gadget.
    """
    xof = XofTurboShake128
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    test_vec_name = 'Prio3HigherDegree'

    def __init__(self, shares: int):
        flp = FlpBBCGGI19(HigherDegree())
        super().__init__(shares, flp, 1)


class Prio3FlpTest(Prio3):
    ID = 0xFFFFFFFF
    xof = XofTurboShake128
    VERIFY_KEY_SIZE = xof.SEED_SIZE

    def __init__(self, joint_rand_len: int):
        flp = FlpTest(Field128, joint_rand_len)
        super().__init__(2, flp, 1)


class TestPrio3FlpTest(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3FlpTest(1)
        self.run_vdaf_test(prio3, None, [1, 2, 3, 4, 4], 14)

        # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
        # generating the joint randomness.
        prio3 = Prio3FlpTest(0)
        self.run_vdaf_test(prio3, None, [1, 2, 3, 4, 4], 14)


class TestPrio3Count(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3Count(2)
        self.assertEqual(prio3.ID, 0x00000001)
        self.run_vdaf_test(prio3, None, [0, 1, 1, 0, 1], 3)
        self.run_vdaf_test(prio3, None, [1], 1)

    def test_3_shares(self) -> None:
        prio3 = Prio3Count(3)
        self.run_vdaf_test(prio3, None, [1], 1)


class TestPrio3Sum(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3Sum(2, 147)
        self.assertEqual(prio3.ID, 0x00000002)
        self.run_vdaf_test(prio3, None, [0, 147, 1, 0, 11, 0], 159)
        self.run_vdaf_test(prio3, None, [100], 100)

    def test_3_shares(self) -> None:
        prio3 = Prio3Sum(3, 100)
        self.run_vdaf_test(prio3, None, [100], 100)


class TestPrio3SumVec(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3SumVec(2, 10, 255, 9)
        self.assertEqual(prio3.ID, 0x00000003)
        self.run_vdaf_test(
            prio3,
            None,
            [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
            [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
        )
        self.run_vdaf_test(
            prio3,
            None,
            [
                list(range(10)),
                [1] * 10,
                [255] * 10
            ],
            list(range(256, 266)),
        )

    def test_3_shares(self) -> None:
        prio3 = Prio3SumVec(3, 3, 32000, 7)
        self.run_vdaf_test(
            prio3,
            None,
            [
                [10000, 32000, 9],
                [19342, 19615, 3061],
                [15986, 24671, 23910]
            ],
            [45328, 76286, 26980],
        )


class TestHistogram(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3Histogram(2, 4, 2)
        self.assertEqual(prio3.ID, 0x00000004)
        self.run_vdaf_test(prio3, None, [0], [1, 0, 0, 0])
        self.run_vdaf_test(prio3, None, [1], [0, 1, 0, 0])
        self.run_vdaf_test(prio3, None, [2], [0, 0, 1, 0])
        self.run_vdaf_test(prio3, None, [3], [0, 0, 0, 1])
        self.run_vdaf_test(prio3, None, [0, 0, 1, 1, 2, 2, 3, 3], [2, 2, 2, 2])
        self.run_vdaf_test(prio3, None, [2], [0, 0, 1, 0])
        prio3 = Prio3Histogram(3, 11, 3)
        self.run_vdaf_test(
            prio3,
            None,
            [2],
            [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        )


class TestPrio3MultihotCountVec(TestVdaf):
    def test(self) -> None:
        # Prio3MultihotCountVec with length = 4, max_weight = 2,
        # chunk_length = 2.
        prio3 = Prio3MultihotCountVec(2, 4, 2, 2)
        self.assertEqual(prio3.ID, 0x00000005)
        self.run_vdaf_test(
            prio3,
            None,
            [[False, False, False, False]],
            [0, 0, 0, 0],
        )
        self.run_vdaf_test(
            prio3,
            None,
            [[False, True, False, False]],
            [0, 1, 0, 0],
        )
        self.run_vdaf_test(
            prio3,
            None,
            [[False, True, True, False]],
            [0, 1, 1, 0],
        )
        self.run_vdaf_test(
            prio3,
            None,
            [[False, True, True, False], [False, True, False, True]],
            [0, 2, 1, 1],
        )

    def test_3_shares(self) -> None:
        # Prio3MultihotCountVec with length = 11, max_weight = 5,
        # chunk_length = 3.
        prio3 = Prio3MultihotCountVec(3, 11, 5, 3)
        self.run_vdaf_test(
            prio3,
            None,
            [[True] * 5 + [False] * 6],
            [1] * 5 + [0] * 6,
        )


class TestPrio3Average(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3Average(2, 5)
        self.run_vdaf_test(prio3, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    def test_is_valid(self) -> None:
        prio3 = Prio3Average(2, 3)
        # Test `is_valid` returns True on empty previous_agg_params, and False
        # otherwise.
        self.assertTrue(prio3.is_valid(None, list([])))
        self.assertFalse(prio3.is_valid(None, list([None])))


class TestPrio3HigherDegree(TestVdaf):
    def test(self) -> None:
        prio3 = Prio3HigherDegree(2)
        self.run_vdaf_test(prio3, None, [0, 1, 2], 3)


class TestPrio3SumVecWithMultiproof(TestVdaf):
    def test(self) -> None:
        for num_proofs in range(2, 5):
            multiproof = Prio3SumVecWithMultiproof(
                2, Field64, num_proofs, 10, 255, 9)

            self.assertEqual(multiproof.ID, 0xFFFFFFFF)
            self.assertEqual(multiproof.PROOFS, num_proofs)

            self.run_vdaf_test(
                multiproof,
                None,
                [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
                [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
            )
            self.run_vdaf_test(
                multiproof,
                None,
                [
                    list(range(10)),
                    [1] * 10,
                    [255] * 10
                ],
                list(range(256, 266)),
            )

            prio3 = Prio3SumVec(3, 3, 65535, 7)
            self.run_vdaf_test(
                prio3,
                None,
                [
                    [10000, 32000, 9],
                    [19342, 19615, 3061],
                    [15986, 24671, 23910]
                ],
                [45328, 76286, 26980],
            )
