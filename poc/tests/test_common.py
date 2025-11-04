import unittest

from vdaf_poc.common import bitrev


class TestCommon(unittest.TestCase):
    def test_bitrev(self) -> None:
        want = [0, 4, 2, 6, 1, 5, 3, 7]  # bitrev(3,i)
        got = [bitrev(3, i) for i in range(8)]
        self.assertEqual(got, want)
