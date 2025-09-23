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
        # Verification states are indexed by the report index, aggregator ID,
        # and round.
        verify_states: list[list[dict[int, VerifyState]]] = [
            [{} for _ in range(vdaf.SHARES)]
            for _ in test_vector["reports"]
        ]

        for operation in test_vector["operations"]:
            if operation["operation"] == "shard":
                report_index = operation["report_index"]
                report_test_vec = test_vector["reports"][report_index]
                if operation["success"]:
                    self.check_shard_success(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        report_test_vec["measurement"],
                        bytes.fromhex(report_test_vec["nonce"]),
                        bytes.fromhex(report_test_vec["rand"]),
                        bytes.fromhex(report_test_vec["public_share"]),
                        [
                            bytes.fromhex(input_share)
                            for input_share in report_test_vec["input_shares"]
                        ],
                    )
                else:
                    self.check_shard_failure(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        report_test_vec["measurement"],
                        bytes.fromhex(report_test_vec["nonce"]),
                        bytes.fromhex(report_test_vec["rand"]),
                    )
            elif operation["operation"] == "verify_init":
                report_index = operation["report_index"]
                report_test_vec = test_vector["reports"][report_index]
                aggregator_id = operation["aggregator_id"]
                if operation["success"]:
                    new_verify_state = self.check_verify_init_success(
                        vdaf,
                        bytes.fromhex(test_vector["verify_key"]),
                        bytes.fromhex(test_vector["ctx"]),
                        aggregator_id,
                        bytes.fromhex(test_vector["agg_param"]),
                        bytes.fromhex(report_test_vec["nonce"]),
                        bytes.fromhex(report_test_vec["public_share"]),
                        bytes.fromhex(
                            report_test_vec["input_shares"][aggregator_id]),
                        bytes.fromhex(
                            report_test_vec["verifier_shares"][0][aggregator_id]),
                    )
                    verify_states[report_index][aggregator_id][0] = cast(
                        VerifyState,
                        new_verify_state,
                    )
                else:
                    self.check_verify_init_failure(
                        vdaf,
                        bytes.fromhex(test_vector["verify_key"]),
                        bytes.fromhex(test_vector["ctx"]),
                        aggregator_id,
                        bytes.fromhex(test_vector["agg_param"]),
                        bytes.fromhex(report_test_vec["nonce"]),
                        bytes.fromhex(report_test_vec["public_share"]),
                        bytes.fromhex(
                            report_test_vec["input_shares"][aggregator_id]),
                    )
            elif operation["operation"] == "verifier_shares_to_message":
                report_index = operation["report_index"]
                report_test_vec = test_vector["reports"][report_index]
                round = operation["round"]
                if operation["success"]:
                    self.check_verifier_shares_to_message_success(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            verify_states[report_index][i][round]
                            for i in range(vdaf.SHARES)
                        ],
                        [
                            bytes.fromhex(verifier_share)
                            for verifier_share in report_test_vec["verifier_shares"][round]
                        ],
                        bytes.fromhex(
                            report_test_vec["verifier_messages"][round]),
                    )
                else:
                    self.check_verifier_shares_to_message_failure(
                        vdaf,
                        bytes.fromhex(test_vector["ctx"]),
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            verify_states[report_index][i][round]
                            for i in range(vdaf.SHARES)
                        ],
                        [
                            bytes.fromhex(verifier_share)
                            for verifier_share in report_test_vec["verifier_shares"][round]
                        ],
                    )
            elif operation["operation"] == "verify_next":
                report_index = operation["report_index"]
                report_test_vec = test_vector["reports"][report_index]
                aggregator_id = operation["aggregator_id"]
                round = operation["round"]
                ctx = bytes.fromhex(test_vector["ctx"])
                verify_state = verify_states[report_index][aggregator_id][round - 1]
                verifier_message = bytes.fromhex(
                    report_test_vec["verifier_messages"][round - 1])
                if operation["success"]:
                    if round < vdaf.ROUNDS:
                        result = self.check_verify_next_success(
                            vdaf,
                            ctx,
                            round,
                            verify_state,
                            verifier_message,
                            bytes.fromhex(
                                report_test_vec["verifier_shares"][round][aggregator_id],
                            ),
                            b"",
                        )
                        verify_states[report_index][aggregator_id][round] = cast(
                            VerifyState,
                            result,
                        )
                    else:
                        self.check_verify_next_success(
                            vdaf,
                            ctx,
                            round,
                            verify_state,
                            verifier_message,
                            b"",
                            bytes.fromhex(
                                report_test_vec["out_shares"][aggregator_id]),
                        )
                else:
                    self.check_verify_next_failure(
                        vdaf,
                        ctx,
                        round,
                        verify_state,
                        verifier_message,
                    )
            elif operation["operation"] == "aggregate":
                aggregator_id = operation["aggregator_id"]
                if operation["success"]:
                    self.check_aggregate_success(
                        vdaf,
                        bytes.fromhex(test_vector["agg_param"]),
                        [
                            bytes.fromhex(
                                report_test_vec["out_shares"][aggregator_id],
                            )
                            for report_test_vec in test_vector["reports"]
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
                                report_test_vec["out_shares"][aggregator_id],
                            )
                            for report_test_vec in test_vector["reports"]
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
                        len(test_vector["reports"]),
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
                        len(test_vector["reports"]),
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
            expected_verifier_share: bytes) -> VerifyState:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        public_share = vdaf.decode_public_share(public_share_bytes)
        input_share = vdaf.decode_input_share(
            aggregator_id,
            input_share_bytes,
        )
        verify_state, verifier_share = vdaf.verify_init(
            verify_key,
            ctx,
            aggregator_id,
            agg_param,
            nonce,
            public_share,
            input_share,
        )
        encoded_verifier_share = vdaf.encode_verifier_share(verifier_share)
        self.assertEqual(encoded_verifier_share, expected_verifier_share)
        return verify_state

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

    def check_verifier_shares_to_message_success(
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
            verify_states: list[VerifyState],
            verifier_shares_bytes: list[bytes],
            expected_verifier_message: bytes) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        verifier_shares = [
            vdaf.decode_verifier_share(verify_state, verifier_share_bytes)
            for verify_state, verifier_share_bytes in zip(
                verify_states,
                verifier_shares_bytes,
            )
        ]
        verifier_message = vdaf.verifier_shares_to_message(
            ctx,
            agg_param,
            verifier_shares,
        )
        encoded_verifier_message = vdaf.encode_verifier_message(
            verifier_message)
        self.assertEqual(encoded_verifier_message, expected_verifier_message)

    def check_verifier_shares_to_message_failure(
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
            verify_states: list[VerifyState],
            verifier_shares_bytes: list[bytes]) -> None:
        agg_param = vdaf.decode_agg_param(agg_param_bytes)
        verifier_shares = [
            vdaf.decode_verifier_share(verify_state, verifier_share_bytes)
            for verify_state, verifier_share_bytes in zip(
                verify_states,
                verifier_shares_bytes,
            )
        ]
        self.assertRaises(
            Exception,
            lambda: vdaf.verifier_shares_to_message(
                ctx,
                agg_param,
                verifier_shares,
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
            verify_state: VerifyState,
            verifier_message_bytes: bytes,
            expected_verifier_share: bytes,
            expected_out_share: bytes) -> Optional[VerifyState]:
        verifier_message = vdaf.decode_verifier_message(
            verify_state, verifier_message_bytes)
        result = vdaf.verify_next(
            ctx,
            verify_state,
            verifier_message,
        )
        if round < vdaf.ROUNDS:
            assert isinstance(result, tuple)
            next_verify_state, verifier_share = result
            encoded_verifier_share = vdaf.encode_verifier_share(
                verifier_share,
            )
            self.assertEqual(encoded_verifier_share, expected_verifier_share)
            return next_verify_state
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
            verify_state: VerifyState,
            verifier_message_bytes: bytes) -> None:
        verifier_message = vdaf.decode_verifier_message(
            verify_state, verifier_message_bytes)
        self.assertRaises(
            Exception,
            lambda: vdaf.verify_next(
                ctx,
                verify_state,
                verifier_message,
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
        assert "reports" in doc
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

    def test_bad_verifier_message(self) -> None:
        self.run_test("Prio3Histogram_bad_verifier_message.json")


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
