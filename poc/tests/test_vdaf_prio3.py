import unittest

from common import TEST_VECTOR
from field import Field64
from flp_generic import FlpGeneric
from tests.test_flp import FlpTestField128
from tests.test_flp_generic import TestAverage
from tests.vdaf import test_vdaf
from vdaf_prio3 import (Prio3, Prio3Count, Prio3Histogram,
                        Prio3MultihotCountVec, Prio3Sum, Prio3SumVec,
                        Prio3SumVecWithMultiproof)
from xof import XofTurboShake128


class TestPrio3Average(Prio3):
    """
    A Prio3 instantiation to test use of num_measurements in the Valid
    class's decode() method.
    """

    Xof = XofTurboShake128
    # NOTE 0xFFFFFFFF is reserved for testing. If we decide to standardize this
    # Prio3 variant, then we'll need to pick a real codepoint for it.
    ID = 0xFFFFFFFF
    VERIFY_KEY_SIZE = XofTurboShake128.SEED_SIZE

    @classmethod
    def with_bits(cls, bits: int):
        class TestPrio3AverageWithBits(TestPrio3Average):
            Flp = FlpGeneric(TestAverage(bits))
        return TestPrio3AverageWithBits


def test_prio3sumvec(num_proofs: int, field: type):
    cls = Prio3SumVecWithMultiproof \
        .with_params(10, 8, 9, num_proofs, field) \
        .with_shares(2)

    assert cls.ID == 0xFFFFFFFF
    assert cls.PROOFS == num_proofs

    test_vdaf(
        cls,
        None,
        [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
        [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
    )
    test_vdaf(
        cls,
        None,
        [
            list(range(10)),
            [1] * 10,
            [255] * 10
        ],
        list(range(256, 266)),
        print_test_vec=False,
    )
    cls = Prio3SumVec.with_params(3, 16, 7).with_shares(3)
    test_vdaf(
        cls,
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


class TestPrio3(unittest.TestCase):
    def test_flp_test(self):
        cls = Prio3 \
            .with_xof(XofTurboShake128) \
            .with_flp(FlpTestField128()) \
            .with_shares(2)
        cls.ID = 0xFFFFFFFF
        test_vdaf(cls, None, [1, 2, 3, 4, 4], 14)

        # If JOINT_RAND_LEN == 0, then Fiat-Shamir isn't needed and we can skip
        # generating the joint randomness.
        cls = Prio3 \
            .with_xof(XofTurboShake128) \
            .with_flp(FlpTestField128.with_joint_rand_len(0)) \
            .with_shares(2)
        cls.ID = 0xFFFFFFFF
        test_vdaf(cls, None, [1, 2, 3, 4, 4], 14)

    def test_count(self):
        cls = Prio3Count.with_shares(2)
        assert cls.ID == 0x00000000
        test_vdaf(cls, None, [0, 1, 1, 0, 1], 3)
        test_vdaf(cls, None, [1], 1, print_test_vec=TEST_VECTOR)

    def test_count_3_shares(self):
        cls = Prio3Count.with_shares(3)
        test_vdaf(cls, None, [1], 1, print_test_vec=TEST_VECTOR,
                  test_vec_instance=1)

    def test_sum(self):
        cls = Prio3Sum.with_bits(8).with_shares(2)
        assert cls.ID == 0x00000001
        test_vdaf(cls, None, [0, 147, 1, 0, 11, 0], 159)
        test_vdaf(cls, None, [100], 100, print_test_vec=TEST_VECTOR)

    def test_sum_3_shares(self):
        cls = Prio3Sum.with_bits(8).with_shares(3)
        test_vdaf(cls, None, [100], 100, print_test_vec=TEST_VECTOR,
                  test_vec_instance=1)

    def test_sum_vec(self):
        cls = Prio3SumVec.with_params(10, 8, 9).with_shares(2)
        assert cls.ID == 0x00000002
        test_vdaf(
            cls,
            None,
            [[1, 61, 86, 61, 23, 0, 255, 3, 2, 1]],
            [1, 61, 86, 61, 23, 0, 255, 3, 2, 1]
        )
        test_vdaf(
            cls,
            None,
            [
                list(range(10)),
                [1] * 10,
                [255] * 10
            ],
            list(range(256, 266)),
            print_test_vec=TEST_VECTOR,
        )

    def test_sum_vec_3_shares(self):
        cls = Prio3SumVec.with_params(3, 16, 7).with_shares(3)
        test_vdaf(
            cls,
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

    def test_histogram(self):
        cls = Prio3Histogram \
            .with_params(4, 2) \
            .with_shares(2)
        assert cls.ID == 0x00000003
        test_vdaf(cls, None, [0], [1, 0, 0, 0])
        test_vdaf(cls, None, [1], [0, 1, 0, 0])
        test_vdaf(cls, None, [2], [0, 0, 1, 0])
        test_vdaf(cls, None, [3], [0, 0, 0, 1])
        test_vdaf(cls, None, [0, 0, 1, 1, 2, 2, 3, 3], [2, 2, 2, 2])
        test_vdaf(cls, None, [2], [0, 0, 1, 0], print_test_vec=TEST_VECTOR)
        cls = Prio3Histogram.with_params(11, 3).with_shares(3)
        test_vdaf(
            cls,
            None,
            [2],
            [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            print_test_vec=TEST_VECTOR,
            test_vec_instance=1,
        )

    def test_multihot_count_vec(self):
        # Prio3MultihotCountVec with length = 4, max_weight = 2,
        # chunk_length = 2.
        cls = Prio3MultihotCountVec \
            .with_params(4, 2, 2) \
            .with_shares(2)
        assert cls.ID == 0x00000004
        test_vdaf(cls, None, [[0, 0, 0, 0]], [0, 0, 0, 0])
        test_vdaf(cls, None, [[0, 1, 0, 0]], [0, 1, 0, 0])
        test_vdaf(cls, None, [[0, 1, 1, 0]], [0, 1, 1, 0])
        test_vdaf(cls, None, [[0, 1, 1, 0], [0, 1, 0, 1]], [0, 2, 1, 1])
        test_vdaf(
            cls, None, [[0, 1, 1, 0]], [0, 1, 1, 0], print_test_vec=TEST_VECTOR
        )

    def test_multi_hot_histogram_3_shares(self):
        # Prio3MultihotCountVec with length = 11, max_weight = 5,
        # chunk_length = 3.
        cls = Prio3MultihotCountVec.with_params(11, 5, 3).with_shares(3)
        test_vdaf(
            cls,
            None,
            [[1] * 5 + [0] * 6],
            [1] * 5 + [0] * 6,
            print_test_vec=False,
            test_vec_instance=1,
        )

    def test_average(self):
        cls = TestPrio3Average.with_bits(3).with_shares(2)
        test_vdaf(cls, None, [1, 5, 1, 1, 4, 1, 3, 2], 2)

    def test_is_valid(self):
        cls = TestPrio3Average.with_bits(3).with_shares(2)
        # Test `is_valid` returns True on empty previous_agg_params, and False
        # otherwise.
        assert cls.is_valid(None, set([]))
        assert not cls.is_valid(None, set([None]))

    def test_multiproof(self):
        for n in range(2, 5):
            test_prio3sumvec(num_proofs=n, field=Field64)
