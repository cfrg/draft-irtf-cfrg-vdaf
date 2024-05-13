import unittest

from common import TEST_VECTOR, from_be_bytes
from tests.vdaf import test_vdaf
from vdaf_poplar1 import Poplar1, get_ancestor


class TestPoplar1(unittest.TestCase):
    def test_poplar1(self):
        test_vdaf(Poplar1.with_bits(15), (15, ()), [], [])
        test_vdaf(Poplar1.with_bits(2), (1, (0b11,)), [], [0])
        test_vdaf(
            Poplar1.with_bits(2),
            (0, (0b0, 0b1)),
            [0b10, 0b00, 0b11, 0b01, 0b11],
            [2, 3],
        )
        test_vdaf(
            Poplar1.with_bits(2),
            (1, (0b00, 0b01)),
            [0b10, 0b00, 0b11, 0b01, 0b01],
            [1, 2],
        )
        test_vdaf(
            Poplar1.with_bits(16),
            (15, (0b1111000011110000,)),
            [0b1111000011110000],
            [1],
        )
        test_vdaf(
            Poplar1.with_bits(16),
            (14, (0b111100001111000,)),
            [
                0b1111000011110000,
                0b1111000011110001,
                0b0111000011110000,
                0b1111000011110010,
                0b1111000000000000,
            ],
            [2],
        )
        test_vdaf(
            Poplar1.with_bits(128),
            (
                127,
                (from_be_bytes(b'0123456789abcdef'),),
            ),
            [
                from_be_bytes(b'0123456789abcdef'),
            ],
            [1],
        )
        test_vdaf(
            Poplar1.with_bits(256),
            (
                63,
                (
                    from_be_bytes(b'00000000'),
                    from_be_bytes(b'01234567'),
                ),
            ),
            [
                from_be_bytes(b'0123456789abcdef0123456789abcdef'),
                from_be_bytes(b'01234567890000000000000000000000'),
            ],
            [0, 2],
        )

    def test_get_ancestor(self):
        # No change.
        assert get_ancestor(0b0, 0, 0) == 0b0
        assert get_ancestor(0b100, 0, 0) == 0b100
        assert get_ancestor(0b0, 1, 1) == 0b0
        assert get_ancestor(0b100, 1, 1) == 0b100

        # Shift once.
        assert get_ancestor(0b0, 1, 0) == 0b0
        assert get_ancestor(0b1, 1, 0) == 0b0
        assert get_ancestor(0b100, 1, 0) == 0b10
        assert get_ancestor(0b100, 2, 1) == 0b10

        # Shift twice.
        assert get_ancestor(0b0, 2, 0) == 0b0
        assert get_ancestor(0b100, 2, 0) == 0b1
        assert get_ancestor(0b100, 4, 2) == 0b1

    def test_is_valid(self):
        # Test `is_valid` returns False on repeated levels, and True otherwise.
        cls = Poplar1.with_bits(256)
        agg_params = [(0, (0b0, 0b1)), (1, (0b00,)), (1, (0b00, 0b10))]
        assert cls.is_valid(agg_params[0], list([]))
        assert cls.is_valid(agg_params[1], list(agg_params[:1]))
        assert not cls.is_valid(agg_params[2], list(agg_params[:2]))

        # Test `is_valid` accepts level jumps.
        agg_params = [(0, (0b0, 0b1)), (2, (0b010, 0b011, 0b101, 0b111))]
        assert cls.is_valid(agg_params[1], list(agg_params[:1]))

        # Test `is_valid` rejects unconnected prefixes.
        agg_params = [(0, (0b0,)), (2, (0b010, 0b011, 0b101, 0b111))]
        assert not cls.is_valid(agg_params[1], list(agg_params[:1]))

    def test_aggregation_parameter_encoding(self):
        # Test aggregation parameter encoding.
        cls = Poplar1.with_bits(256)
        want = (0, ())
        assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
        want = (0, (0, 1))
        assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
        want = (2, (0, 1, 2, 3))
        assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
        want = (17, (0, 1, 1233, 2 ** 18 - 1))
        assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
        want = (255, (0, 1, 1233, 2 ** 256 - 1))
        assert want == cls.decode_agg_param(cls.encode_agg_param(*want))

    def test_generate_test_vectors(self):
        # Generate test vectors.
        cls = Poplar1.with_bits(4)
        assert cls.ID == 0x00001000
        measurements = [0b1101]
        tests = [
            # (level, prefixes, expected result)
            (0, [0, 1], [0, 1]),
            (1, [0, 1, 2, 3], [0, 0, 0, 1]),
            (2, [0, 2, 4, 6], [0, 0, 0, 1]),
            (3, [1, 3, 5, 7, 9, 13, 15], [0, 0, 0, 0, 0, 1, 0]),
        ]
        for (level, prefixes, expected_result) in tests:
            agg_param = (int(level), tuple(map(int, prefixes)))
            test_vdaf(cls, agg_param, measurements, expected_result,
                      print_test_vec=TEST_VECTOR, test_vec_instance=level)
