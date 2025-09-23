import json
import os.path
import unittest
from typing import Generic, Optional, TypeVar, cast

from vdaf_poc.field import Field64, NttField
from vdaf_poc.test_utils import VdafTestVectorDict
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.vdaf_poplar1 import Poplar1
from vdaf_poc.vdaf_prio3 import (Prio3Count, Prio3Histogram,
                                 Prio3MultihotCountVec, Prio3Sum, Prio3SumVec,
                                 Prio3SumVecWithMultiproof)

Measurement = TypeVar("Measurement")
AggParam = TypeVar("AggParam")
PublicShare = TypeVar("PublicShare")
InputShare = TypeVar("InputShare")
OutShare = TypeVar("OutShare")
AggShare = TypeVar("AggShare")
AggResult = TypeVar("AggResult")
VerifyState = TypeVar("VerifyState")
VerifierShare = TypeVar("VerifierShare")
VerifierMessage = TypeVar("VerifierMessage")
F = TypeVar("F", bound=NttField)


class TestVdafTestVector(unittest.TestCase, Generic[Measurement, AggResult]):
    def check_test_vector(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            test_vector: VdafTestVectorDict[Measurement, AggResult]) -> None:
        # Verifyare states are indexed by the report index, aggregator ID, and
        # round.
        ver_states: list[list[dict[int, VerifyState]]] = [
            [{} for _ in range(vdaf.SHARES)]
            for _ in test_vector["verify"]
        ]

        for operation in test_vector["operations"]:
            if operation["operation"] == "shard":
                report_index = operation["report_index"]
                verify = test_vector["verify"][report_index]
                if operation["success"]:
                    self.check_shard_success(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        verify["measurement"],
                        bytes.fromhex(verify["nonce"]),
                        bytes.fromhex(verify["rand"]),
                        bytes.fromhex(verify["public_share"]),
                        [
                            bytes.fromhex(input_share)
                            for input_share in verify["input_shares"]
                        ],
                    )
                else:
                    self.check_shard_failure(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        verify["measurement"],
                        bytes.fromhex(verify["nonce"]),
                        bytes.fromhex(verify["rand"]),
                    )
            elif operation["operation"] == "verify_init":
                report_index = operation["report_index"]
                verify = test_vector["verify"][report_index]
                aggregator_id = operation["aggregator_id"]
                if operation["success"]:
                    new_ver_state = self.check_verify_init_success(
                        vdaf,
                        bytes.fromhex(test_vector["verify_key"]),
                        bytes.fromhex(test_vector["ctx"]),
                        aggregator_id,
                        bytes.fromhex(test_vector["agg_param"]),
                        bytes.fromhex(verify["nonce"]),
                        bytes.fromhex(verify["public_share"]),
                        bytes.fromhex(verify["input_shares"][aggregator_id]),
                        bytes.fromhex(verify["ver_shares"][0][aggregator_id]),
                    )
                    ver_states[report_index][aggregator_id][0] = cast(
                        VerifyState,
                        new_ver_state,
                    )
                else:
                    self.check_verify_init_failure(
                        vdaf,
                        bytes.fromhex(test_vector["verify_key"]),
                        bytes.fromhex(test_vector["ctx"]),
                        aggregator_id,
                        bytes.fromhex(test_vector["agg_param"]),
                        bytes.fromhex(verify["nonce"]),
                        bytes.fromhex(verify["public_share"]),
                        bytes.fromhex(verify["input_shares"][aggregator_id]),
                    )
            elif operation["operation"] == "ver_shares_to_msg":
                report_index = operation["report_index"]
                verify = test_vector["verify"][report_index]
                round = operation["round"]
                if operation["success"]:
                    self.check_ver_shares_to_msg_success(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            ver_states[report_index][i][round]
                            for i in range(vdaf.SHARES)
                        ],
                        [
                            bytes.fromhex(ver_share)
                            for ver_share in verify["ver_shares"][round]
                        ],
                        bytes.fromhex(verify["ver_msgs"][round]),
                    )
                else:
                    self.check_ver_shares_to_msg_failure(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            ver_states[report_index][i][round]
                            for i in range(vdaf.SHARES)
                        ],
                        [
                            bytes.fromhex(ver_share)
                            for ver_share in verify["ver_shares"][round]
                        ],
                    )
            elif operation["operation"] == "verify_next":
                report_index = operation["report_index"]
                verify = test_vector["verify"][report_index]
                aggregator_id = operation["aggregator_id"]
                round = operation["round"]
                ctx = bytes.fromhex(test_vector["ctx"])
                ver_state = ver_states[report_index][aggregator_id][round - 1]
                ver_msg = bytes.fromhex(verify["ver_msgs"][round - 1])
                if operation["success"]:
                    if round < vdaf.ROUNDS:
                        result = self.check_verify_next_success(
                            vdaf,
                            ctx,
                            round,
                            ver_state,
                            ver_msg,
                            bytes.fromhex(
                                verify["ver_shares"][round][aggregator_id],
                            ),
                            b"",
                        )
                        ver_states[report_index][aggregator_id][round] = cast(
                            VerifyState,
                            result,
                        )
                    else:
                        self.check_verify_next_success(
                            vdaf,
                            ctx,
                            round,
                            ver_state,
                            ver_msg,
                            b"",
                            bytes.fromhex(verify["out_shares"][aggregator_id]),
                        )
                else:
                    self.check_verify_next_failure(
                        vdaf,
                        ctx,
                        round,
                        ver_state,
                        ver_msg,
                    )
            elif operation["operation"] == "aggregate":
                aggregator_id = operation["aggregator_id"]
                if operation["success"]:
                    self.check_aggregate_success(
                        vdaf,
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            bytes.fromhex(
                                verify["out_shares"][aggregator_id],
                            )
                            for verify in test_vector["verify"]
                        ],
                        bytes.fromhex(
                            test_vector["agg_shares"][aggregator_id],
                        ),
                    )
                else:
                    self.check_aggregate_failure(
                        vdaf,
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            bytes.fromhex(
                                verify["out_shares"][aggregator_id],
                            )
                            for verify in test_vector["verify"]
                        ],
                    )
            elif operation["operation"] == "unshard":
                if operation["success"]:
                    self.check_unshard_success(
                        vdaf,
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            bytes.fromhex(agg_share)
                            for agg_share in test_vector["agg_shares"]
                        ],
                        len(test_vector["verify"]),
                        cast(AggResult, test_vector["agg_result"]),
                    )
                else:
                    self.check_unshard_failure(
                        vdaf,
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            bytes.fromhex(agg_share)
                            for agg_share in test_vector["agg_shares"]
                        ],
                        len(test_vector["verify"]),
                    )
            else:
                raise Exception(
                    f"unexpected operation: {operation["operation"]}",
                )

    def check_shard_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            measurement: Measurement,
            nonce: bytes,
            rand: bytes,
            expected_public_share: bytes,
            expected_input_shares: list[bytes]) -> None:
        public_share, input_shares = vdaf.shard(
            ctx,
            measurement,
            nonce,
            rand,
        )
        encoded_public_share = vdaf.encode_public_share(
            public_share,
        )
        self.assertEqual(encoded_public_share, expected_public_share)
        self.assertEqual(len(input_shares), len(expected_input_shares))
        for input_share, expected_input_share in zip(
                input_shares, expected_input_shares):
            encoded_input_share = vdaf.encode_input_share(
                input_share,
            )
            self.assertEqual(encoded_input_share, expected_input_share)

    def check_shard_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            measurement: Measurement,
            nonce: bytes,
            rand: bytes) -> None:
        self.assertRaises(
            Exception,
            lambda: vdaf.shard(ctx, measurement, nonce, rand),
        )

    def check_verify_init_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            verify_key: bytes,
            ctx: bytes,
            aggregator_id: int,
            agg_param_bytes: bytes,
            nonce: bytes,
            public_share_bytes: bytes,
            input_share_bytes: bytes,
            expected_ver_share: bytes) -> VerifyState:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        public_share = vdaf.decode_public_share(public_share_bytes)
        input_share = vdaf.decode_input_share(
            aggregator_id,
            input_share_bytes,
        )
        ver_state, ver_share = vdaf.verify_init(
            verify_key,
            ctx,
            aggregator_id,
            agg_param,
            nonce,
            public_share,
            input_share,
        )
        encoded_ver_share = vdaf.encode_ver_share(ver_share)
        self.assertEqual(encoded_ver_share, expected_ver_share)
        return ver_state

    def check_verify_init_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            verify_key: bytes,
            ctx: bytes,
            aggregator_id: int,
            agg_param_bytes: bytes,
            nonce: bytes,
            public_share_bytes: bytes,
            input_share_bytes: bytes) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        public_share = vdaf.decode_public_share(public_share_bytes)
        input_share = vdaf.decode_input_share(
            aggregator_id,
            input_share_bytes,
        )
        self.assertRaises(
            Exception,
            lambda: vdaf.verify_init(
                verify_key,
                ctx,
                aggregator_id,
                agg_param,
                nonce,
                public_share,
                input_share,
            ),
        )

    def check_ver_shares_to_msg_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            agg_param_bytes: bytes,
            ver_states: list[VerifyState],
            ver_shares_bytes: list[bytes],
            expected_ver_msg: bytes) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        ver_shares = [
            vdaf.decode_ver_share(ver_state, ver_share_bytes)
            for ver_state, ver_share_bytes in zip(
                ver_states,
                ver_shares_bytes,
            )
        ]
        ver_msg = vdaf.ver_shares_to_msg(
            ctx,
            agg_param,
            ver_shares,
        )
        encoded_ver_msg = vdaf.encode_ver_msg(ver_msg)
        self.assertEqual(encoded_ver_msg, expected_ver_msg)

    def check_ver_shares_to_msg_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            agg_param_bytes: bytes,
            ver_states: list[VerifyState],
            ver_shares_bytes: list[bytes]) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        ver_shares = [
            vdaf.decode_ver_share(ver_state, ver_share_bytes)
            for ver_state, ver_share_bytes in zip(
                ver_states,
                ver_shares_bytes,
            )
        ]
        self.assertRaises(
            Exception,
            lambda: vdaf.ver_shares_to_msg(
                ctx,
                agg_param,
                ver_shares,
            ),
        )

    def check_verify_next_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            round: int,
            ver_state: VerifyState,
            ver_msg_bytes: bytes,
            expected_ver_share: bytes,
            expected_out_share: bytes) -> Optional[VerifyState]:
        ver_msg = vdaf.decode_ver_msg(ver_state, ver_msg_bytes)
        result = vdaf.verify_next(
            ctx,
            ver_state,
            ver_msg,
        )
        if round < vdaf.ROUNDS:
            assert isinstance(result, tuple)
            next_ver_state, ver_share = result
            encoded_ver_share = vdaf.encode_ver_share(
                ver_share,
            )
            self.assertEqual(encoded_ver_share, expected_ver_share)
            return next_ver_state
        else:
            out_share = cast(OutShare, result)
            encoded_out_share = vdaf.encode_out_share(out_share)
            self.assertEqual(encoded_out_share, expected_out_share)
            return None

    def check_verify_next_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            ctx: bytes,
            round: int,
            ver_state: VerifyState,
            ver_msg_bytes: bytes) -> None:
        ver_msg = vdaf.decode_ver_msg(ver_state, ver_msg_bytes)
        self.assertRaises(
            Exception,
            lambda: vdaf.verify_next(
                ctx,
                ver_state,
                ver_msg,
            )
        )

    def check_aggregate_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            agg_param_bytes: bytes,
            out_shares_bytes: list[bytes],
            expected_agg_share: bytes) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        out_shares = [
            vdaf.decode_out_share(agg_param, out_share_bytes)
            for out_share_bytes in out_shares_bytes
        ]
        agg_share = vdaf.agg_init(agg_param)
        for out_share in out_shares:
            agg_share = vdaf.agg_update(agg_param, agg_share, out_share)
        encoded_agg_share = vdaf.encode_agg_share(agg_share)
        self.assertEqual(encoded_agg_share, expected_agg_share)

    def check_aggregate_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            agg_param_bytes: bytes,
            out_shares_bytes: list[bytes]) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        out_shares = [
            vdaf.decode_out_share(agg_param, out_share_bytes)
            for out_share_bytes in out_shares_bytes
        ]

        def aggregate() -> AggShare:
            agg_share = vdaf.agg_init(agg_param)
            for out_share in out_shares:
                agg_share = vdaf.agg_update(agg_param, agg_share, out_share)
            return agg_share

        self.assertRaises(Exception, aggregate)

    def check_unshard_success(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            agg_param_bytes: bytes,
            agg_shares_bytes: list[bytes],
            num_measurements: int,
            expected_agg_result: AggResult) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        agg_shares = [
            vdaf.decode_agg_share(agg_param, agg_share_bytes)
            for agg_share_bytes in agg_shares_bytes
        ]
        agg_result = vdaf.unshard(agg_param, agg_shares, num_measurements)
        self.assertEqual(agg_result, expected_agg_result)

    def check_unshard_failure(
            self,
            vdaf: Vdaf[
                Measurement,
                AggParam,
                PublicShare,
                InputShare,
                OutShare,
                AggShare,
                AggResult,
                VerifyState,
                VerifierShare,
                VerifierMessage,
            ],
            agg_param_bytes: bytes,
            agg_shares_bytes: list[bytes],
            num_measurements: int) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        agg_shares = [
            vdaf.decode_agg_share(agg_param, agg_share_bytes)
            for agg_share_bytes in agg_shares_bytes
        ]
        self.assertRaises(
            Exception,
            lambda: vdaf.unshard(agg_param, agg_shares, num_measurements),
        )

    def load_test_vector(self, filename: str) -> VdafTestVectorDict[Measurement, AggResult]:
        path = os.path.join("..", "test_vec", "vdaf", filename)
        with open(path, "rb") as f:
            doc = json.load(f)
        assert "operations" in doc
        assert "shares" in doc
        assert "verify_key" in doc
        assert "agg_param" in doc
        assert "ctx" in doc
        assert "verify" in doc
        assert "agg_shares" in doc
        assert "agg_result" in doc
        return doc


class TestPrio3CountTestVector(TestVdafTestVector[int, int]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3Count(test_vector["shares"])
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3Count_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3Count_1.json")

    def test_2(self) -> None:
        self.run_test("Prio3Count_2.json")

    def test_bad_meas_share(self) -> None:
        self.run_test("Prio3Count_bad_meas_share.json")

    def test_bad_wire_seed(self) -> None:
        self.run_test("Prio3Count_bad_wire_seed.json")

    def test_bad_gadget_poly(self) -> None:
        self.run_test("Prio3Count_bad_gadget_poly.json")

    def test_bad_helper_seed(self) -> None:
        self.run_test("Prio3Count_bad_helper_seed.json")


class TestPrio3SumTestVector(TestVdafTestVector[int, int]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3Sum(
            test_vector["shares"],
            cast(dict, test_vector)["max_measurement"],
        )
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3Sum_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3Sum_1.json")

    def test_2(self) -> None:
        self.run_test("Prio3Sum_2.json")


class TestPrio3SumVecTestVector(TestVdafTestVector[list[int], list[int]]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3SumVec(
            test_vector["shares"],
            cast(dict, test_vector)["length"],
            cast(dict, test_vector)["bits"],
            cast(dict, test_vector)["chunk_length"],
        )
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3SumVec_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3SumVec_1.json")


class TestPrio3SumVecWithMultiproofTestVector(TestVdafTestVector[list[int], list[int]]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3SumVecWithMultiproof(
            test_vector["shares"],
            Field64,
            3,
            cast(dict, test_vector)["length"],
            cast(dict, test_vector)["bits"],
            cast(dict, test_vector)["chunk_length"],
        )
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3SumVecWithMultiproof_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3SumVecWithMultiproof_1.json")


class TestPrio3HistogramTestVector(TestVdafTestVector[int, list[int]]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3Histogram(
            test_vector["shares"],
            cast(dict, test_vector)["length"],
            cast(dict, test_vector)["chunk_length"],
        )
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3Histogram_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3Histogram_1.json")

    def test_2(self) -> None:
        self.run_test("Prio3Histogram_2.json")

    def test_bad_public_share(self) -> None:
        self.run_test("Prio3Histogram_bad_public_share.json")

    def test_bad_leader_jr_blind(self) -> None:
        self.run_test("Prio3Histogram_bad_leader_jr_blind.json")

    def test_bad_helper_jr_blind(self) -> None:
        self.run_test("Prio3Histogram_bad_helper_jr_blind.json")

    def test_bad_ver_msg(self) -> None:
        self.run_test("Prio3Histogram_bad_ver_msg.json")


class TestPrio3MultihotCountVecTestVector(TestVdafTestVector[list[bool], list[int]]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Prio3MultihotCountVec(
            test_vector["shares"],
            cast(dict, test_vector)["length"],
            cast(dict, test_vector)["max_weight"],
            cast(dict, test_vector)["chunk_length"],
        )
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Prio3MultihotCountVec_0.json")

    def test_1(self) -> None:
        self.run_test("Prio3MultihotCountVec_1.json")

    def test_2(self) -> None:
        self.run_test("Prio3MultihotCountVec_2.json")


class TestPoplar1TestVector(TestVdafTestVector[tuple[bool, ...], list[int]]):
    def run_test(self, filename: str) -> None:
        test_vector = self.load_test_vector(filename)
        vdaf = Poplar1(cast(dict, test_vector)["bits"])
        self.check_test_vector(vdaf, test_vector)

    def test_0(self) -> None:
        self.run_test("Poplar1_0.json")

    def test_1(self) -> None:
        self.run_test("Poplar1_1.json")

    def test_2(self) -> None:
        self.run_test("Poplar1_2.json")

    def test_3(self) -> None:
        self.run_test("Poplar1_3.json")

    def test_4(self) -> None:
        self.run_test("Poplar1_4.json")

    def test_5(self) -> None:
        self.run_test("Poplar1_5.json")

    def test_bad_corr_inner(self) -> None:
        self.run_test("Poplar1_bad_corr_inner.json")
