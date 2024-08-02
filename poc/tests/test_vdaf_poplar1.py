from vdaf_poc.common import from_be_bytes
from vdaf_poc.test_utils import TestVdaf
from vdaf_poc.vdaf_poplar1 import Poplar1, get_ancestor


class TestPoplar1(TestVdaf):
    def test_poplar1(self) -> None:
        self.run_vdaf_test(Poplar1(15), (15, ()), [], [])
        self.run_vdaf_test(Poplar1(2), (1, (0b11,)), [], [0])
        self.run_vdaf_test(Poplar1(2), (1, (0b11,)), [0], [0])
        self.run_vdaf_test(
            Poplar1(2),
            (0, (0b0, 0b1)),
            [0b10, 0b00, 0b11, 0b01, 0b11],
            [2, 3],
        )
        self.run_vdaf_test(
            Poplar1(2),
            (1, (0b00, 0b01)),
            [0b10, 0b00, 0b11, 0b01, 0b01],
            [1, 2],
        )
        self.run_vdaf_test(
            Poplar1(16),
            (15, (0b1111000011110000,)),
            [0b1111000011110000],
            [1],
        )
        self.run_vdaf_test(
            Poplar1(16),
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
        self.run_vdaf_test(
            Poplar1(128),
            (
                127,
                (from_be_bytes(b'0123456789abcdef'),),
            ),
            [
                from_be_bytes(b'0123456789abcdef'),
            ],
            [1],
        )
        self.run_vdaf_test(
            Poplar1(256),
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

    def test_get_ancestor(self) -> None:
        # No change.
        self.assertEqual(get_ancestor(0b0, 0, 0), 0b0)
        self.assertEqual(get_ancestor(0b100, 0, 0), 0b100)
        self.assertEqual(get_ancestor(0b0, 1, 1), 0b0)
        self.assertEqual(get_ancestor(0b100, 1, 1), 0b100)

        # Shift once.
        self.assertEqual(get_ancestor(0b0, 1, 0), 0b0)
        self.assertEqual(get_ancestor(0b1, 1, 0), 0b0)
        self.assertEqual(get_ancestor(0b100, 1, 0), 0b10)
        self.assertEqual(get_ancestor(0b100, 2, 1), 0b10)

        # Shift twice.
        self.assertEqual(get_ancestor(0b0, 2, 0), 0b0)
        self.assertEqual(get_ancestor(0b10, 2, 0), 0b0)
        self.assertEqual(get_ancestor(0b100, 2, 0), 0b1)
        self.assertEqual(get_ancestor(0b100, 4, 2), 0b1)

    def test_is_valid(self) -> None:
        # Test `is_valid` returns False on repeated levels, and True otherwise.
        cls = Poplar1(256)
        agg_params = [(0, (0b0, 0b1)), (1, (0b00,)), (1, (0b00, 0b10))]
        self.assertTrue(cls.is_valid(agg_params[0], list([])))
        self.assertTrue(cls.is_valid(agg_params[1], list(agg_params[:1])))
        self.assertFalse(cls.is_valid(agg_params[2], list(agg_params[:2])))

        # Test `is_valid` accepts level jumps.
        agg_params = [(0, (0b0, 0b1)), (2, (0b010, 0b011, 0b101, 0b111))]
        self.assertTrue(cls.is_valid(agg_params[1], list(agg_params[:1])))

        # Test `is_valid` rejects unconnected prefixes.
        agg_params = [(0, (0b0,)), (2, (0b010, 0b011, 0b101, 0b111))]
        self.assertFalse(cls.is_valid(agg_params[1], list(agg_params[:1])))

    def test_aggregation_parameter_encoding(self) -> None:
        # Test aggregation parameter encoding.
        cls = Poplar1(256)
        want: tuple[int, tuple[int, ...]]
        want = (0, ())
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (0, (0, 1))
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (2, (0, 1, 2, 3))
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (17, (0, 1, 1233, 2 ** 18 - 1))
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (255, (0, 1, 1233, 2 ** 256 - 1))
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))

    def test_generate_test_vectors(self) -> None:
        # Generate test vectors.
        cls = Poplar1(4)
        self.assertEqual(cls.ID, 0x00001000)
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
            self.run_vdaf_test(cls, agg_param, measurements, expected_result)
