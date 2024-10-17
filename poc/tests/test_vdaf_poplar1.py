from typing import Sequence

from tests.test_idpf_bbcggi21 import bytes_to_bit_string, int_to_bit_string
from vdaf_poc.test_utils import TestVdaf
from vdaf_poc.vdaf_poplar1 import Poplar1, get_ancestor


class TestPoplar1(TestVdaf):
    def run_poplar1_test(
            self,
            vdaf: Poplar1,
            agg_param: tuple[int, Sequence[tuple[bool, ...]]],
            measurements: list[tuple[bool, ...]],
            expected_agg_result: list[int]) -> None:
        """This wrapper method just helps with type inference."""
        return self.run_vdaf_test(
            vdaf,
            agg_param,
            measurements,
            expected_agg_result,
        )

    def test_poplar1(self) -> None:
        self.run_poplar1_test(
            Poplar1(15),
            (15, ()),
            [],
            [],
        )
        self.run_poplar1_test(
            Poplar1(2),
            (1, (int_to_bit_string(0b11, 2),)),
            [],
            [0],
        )
        self.run_poplar1_test(
            Poplar1(2),
            (1, (int_to_bit_string(0b11, 2),)),
            [int_to_bit_string(0b00, 2)],
            [0],
        )
        self.run_poplar1_test(
            Poplar1(2),
            (0, (int_to_bit_string(0b0, 1), int_to_bit_string(0b1, 1))),
            [
                int_to_bit_string(0b10, 2),
                int_to_bit_string(0b00, 2),
                int_to_bit_string(0b11, 2),
                int_to_bit_string(0b01, 2),
                int_to_bit_string(0b11, 2),
            ],
            [2, 3],
        )
        self.run_poplar1_test(
            Poplar1(2),
            (1, (int_to_bit_string(0b00, 2), int_to_bit_string(0b01, 2))),
            [
                int_to_bit_string(0b10, 2),
                int_to_bit_string(0b00, 2),
                int_to_bit_string(0b11, 2),
                int_to_bit_string(0b01, 2),
                int_to_bit_string(0b01, 2),
            ],
            [1, 2],
        )
        self.run_poplar1_test(
            Poplar1(16),
            (
                15,
                (int_to_bit_string(0b1111000011110000, 16),),
            ),
            [int_to_bit_string(0b1111000011110000, 16)],
            [1],
        )
        self.run_poplar1_test(
            Poplar1(16),
            (
                14,
                (int_to_bit_string(0b111100001111000, 15),),
            ),
            [
                int_to_bit_string(0b1111000011110000, 16),
                int_to_bit_string(0b1111000011110001, 16),
                int_to_bit_string(0b0111000011110000, 16),
                int_to_bit_string(0b1111000011110010, 16),
                int_to_bit_string(0b1111000000000000, 16),
            ],
            [2],
        )
        self.run_poplar1_test(
            Poplar1(128),
            (
                127,
                (bytes_to_bit_string(b'0123456789abcdef'),),
            ),
            [
                bytes_to_bit_string(b'0123456789abcdef'),
            ],
            [1],
        )
        self.run_poplar1_test(
            Poplar1(256),
            (
                63,
                (
                    bytes_to_bit_string(b'00000000'),
                    bytes_to_bit_string(b'01234567'),
                ),
            ),
            [
                bytes_to_bit_string(b'0123456789abcdef0123456789abcdef'),
                bytes_to_bit_string(b'01234567890000000000000000000000'),
            ],
            [0, 2],
        )

    def test_get_ancestor(self) -> None:
        # No change.
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b000, 3),
                2,
            ),
            int_to_bit_string(0b000, 3),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b100, 3),
                2,
            ),
            int_to_bit_string(0b100, 3),
        )

        # Shift once.
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b00, 2),
                0,
            ),
            int_to_bit_string(0b0, 1),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b01, 2),
                0,
            ),
            int_to_bit_string(0b0, 1),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b100, 3),
                1,
            ),
            int_to_bit_string(0b10, 2),
        )

        # Shift twice.
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b000, 3),
                0,
            ),
            int_to_bit_string(0b0, 1),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b010, 3),
                0,
            ),
            int_to_bit_string(0b0, 1),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b100, 3),
                0,
            ),
            int_to_bit_string(0b1, 1),
        )
        self.assertEqual(
            get_ancestor(
                int_to_bit_string(0b00100, 5),
                2,
            ),
            int_to_bit_string(0b001, 3),
        )

    def test_is_valid(self) -> None:
        # Test `is_valid` returns False on repeated levels, and True otherwise.
        cls = Poplar1(256)
        agg_params = [
            (0, (int_to_bit_string(0b0, 1), int_to_bit_string(0b1, 1))),
            (1, (int_to_bit_string(0b00, 2),)),
            (1, (int_to_bit_string(0b00, 2), int_to_bit_string(0b10, 2))),
        ]
        self.assertTrue(cls.is_valid(agg_params[0], list([])))
        self.assertTrue(cls.is_valid(agg_params[1], list(agg_params[:1])))
        self.assertFalse(cls.is_valid(agg_params[2], list(agg_params[:2])))

        # Test `is_valid` accepts level jumps.
        agg_params = [
            (0, (int_to_bit_string(0b0, 1), int_to_bit_string(0b1, 1))),
            (2, (
                int_to_bit_string(0b010, 3),
                int_to_bit_string(0b011, 3),
                int_to_bit_string(0b101, 3),
                int_to_bit_string(0b111, 3),
            ))
        ]
        self.assertTrue(cls.is_valid(agg_params[1], list(agg_params[:1])))

        # Test `is_valid` rejects unconnected prefixes.
        agg_params = [
            (0, (int_to_bit_string(0b0, 1),)),
            (2, (
                int_to_bit_string(0b010, 3),
                int_to_bit_string(0b011, 3),
                int_to_bit_string(0b101, 3),
                int_to_bit_string(0b111, 3),
            )),
        ]
        self.assertFalse(cls.is_valid(agg_params[1], list(agg_params[:1])))

        # Test `is_valid` rejects unsorted prefixes.
        agg_params = [
            (0, (int_to_bit_string(0b1, 1), int_to_bit_string(0b0, 1))),
        ]
        self.assertFalse(cls.is_valid(agg_params[0], list(agg_params)))

    def test_aggregation_parameter_encoding(self) -> None:
        # Test aggregation parameter encoding.
        cls = Poplar1(256)
        want: tuple[int, tuple[tuple[bool, ...], ...]]
        want = (0, ())
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (0, (int_to_bit_string(0b0, 1), int_to_bit_string(0b1, 1)))
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (
            2,
            (
                int_to_bit_string(0b000, 3),
                int_to_bit_string(0b001, 3),
                int_to_bit_string(0b010, 3),
                int_to_bit_string(0b011, 3),
            ),
        )
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (
            17,
            (
                int_to_bit_string(0, 18),
                int_to_bit_string(1, 18),
                int_to_bit_string(1233, 18),
                int_to_bit_string(2 ** 18 - 1, 18),
            ),
        )
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))
        want = (
            255,
            (
                int_to_bit_string(0, 256),
                int_to_bit_string(1, 256),
                int_to_bit_string(1233, 256),
                int_to_bit_string(2 ** 256 - 1, 256),
            ),
        )
        self.assertEqual(want, cls.decode_agg_param(
            cls.encode_agg_param(want)))

    def test_generate_test_vectors(self) -> None:
        # Generate test vectors.
        cls = Poplar1(4)
        self.assertEqual(cls.ID, 0x00000006)
        measurements: list[tuple[bool, ...]] = [int_to_bit_string(0b1101, 4)]
        tests: list[tuple[int, list[tuple[bool, ...]], list[int]]] = [
            # (level, prefixes, expected result)
            (
                0,
                [int_to_bit_string(0, 1), int_to_bit_string(1, 1)],
                [0, 1],
            ),
            (
                1,
                [
                    int_to_bit_string(0, 2),
                    int_to_bit_string(1, 2),
                    int_to_bit_string(2, 2),
                    int_to_bit_string(3, 2),
                ],
                [0, 0, 0, 1],
            ),
            (
                2,
                [
                    int_to_bit_string(0, 3),
                    int_to_bit_string(2, 3),
                    int_to_bit_string(4, 3),
                    int_to_bit_string(6, 3),
                ],
                [0, 0, 0, 1],
            ),
            (
                3,
                [
                    int_to_bit_string(1, 4),
                    int_to_bit_string(3, 4),
                    int_to_bit_string(5, 4),
                    int_to_bit_string(7, 4),
                    int_to_bit_string(9, 4),
                    int_to_bit_string(13, 4),
                    int_to_bit_string(15, 4),
                ],
                [0, 0, 0, 0, 0, 1, 0],
            ),
        ]
        for (level, prefixes, expected_result) in tests:
            agg_param: tuple[int, list[tuple[bool, ...]]] = (
                level,
                prefixes,
            )
            self.run_poplar1_test(
                cls,
                agg_param,
                measurements,
                expected_result,
            )
