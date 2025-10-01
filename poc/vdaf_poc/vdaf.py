"""Definition of VDAFs."""

from abc import abstractmethod
from typing import Any, Generic, TypeVar, override

from vdaf_poc.common import format_dst, gen_rand
from vdaf_poc.daf import DistributedAggregation
from vdaf_poc.field import Field

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
F = TypeVar("F", bound=Field)


class Vdaf(
        Generic[
            Measurement, AggParam, PublicShare, InputShare, OutShare, AggShare,
            AggResult, VerifyState, VerifierShare, VerifierMessage
        ],
        DistributedAggregation[
            Measurement, AggParam, PublicShare, InputShare, OutShare, AggShare,
            AggResult
        ]):
    """
    A Verifiable Distributed Aggregation Function (VDAF).

    Generic type parameters:
    Measurement -- the measurement type
    AggParam -- the aggregation parameter type
    PublicShare -- the public share type
    InputShare -- the input share type
    OutShare -- the output share type
    AggShare -- the aggregate share type
    AggResult -- the aggregate result type

    Attributes:
    ID -- algorithm identifier, a 32-bit integer
    SHARES -- the number of Aggregators
    NONCE_SIZE -- length of the nonce
    RAND_SIZE -- number of random bytes consumed by `shard()`
    """

    # Algorithm identifier for this VDAF, a 32-bit integer.
    ID: int  # `[0, 2**32)`

    # Length of the verification key shared by the Aggregators.
    VERIFY_KEY_SIZE: int

    # Length of the nonce.
    NONCE_SIZE: int

    # Number of random bytes consumed by `shard()`.
    RAND_SIZE: int

    # The number of Aggregators.
    SHARES: int

    # The number of rounds of communication during verification.
    ROUNDS: int

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name: str

    @override
    @abstractmethod
    def shard(self,
              ctx: bytes,
              measurement: Measurement,
              nonce: bytes,
              rand: bytes,
              ) -> tuple[PublicShare, list[InputShare]]:
        """
        Shard a measurement into a "public share" and a sequence of input
        shares, one for each Aggregator. This method is run by the Client.

        Pre-conditions:

            - `len(nonce) == Vdaf.NONCE_SIZE`
            - `len(rand) == Vdaf.RAND_SIZE`
        """
        pass

    @override
    @abstractmethod
    def is_valid(self, agg_param: AggParam,
                 previous_agg_params: list[AggParam]) -> bool:
        """
        Check if `agg_param` is valid for use with an input share that has
        previously been used with all `previous_agg_params`.
        """
        pass

    @abstractmethod
    def verify_init(self,
                    verify_key: bytes,
                    ctx: bytes,
                    agg_id: int,
                    agg_param: AggParam,
                    nonce: bytes,
                    public_share: PublicShare,
                    input_share: InputShare,
                    ) -> tuple[VerifyState, VerifierShare]:
        """
        Initialize the verification state for the given input share and return
        the first verifier share. This method is run by an Aggregator. Along
        with the public share and its input share, the inputs include the
        verification key shared by all of the Aggregators, the Aggregator's ID,
        and the aggregation parameter, application context, and nonce agreed
        upon by all of the Aggregators.

        Pre-conditions:

            - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
            - `agg_id` in the range `[0, vdaf.SHARES)`
            - `len(nonce) == vdaf.NONCE_SIZE`
        """
        pass

    @abstractmethod
    def verify_next(self,
                    ctx: bytes,
                    verify_state: VerifyState,
                    verifier_message: VerifierMessage,
                    ) -> tuple[VerifyState, VerifierShare] | OutShare:
        """
        Consume the inbound message from the previous round and return the
        Aggregator's share of the next round (or the aggregator's output share
        if this is the last round).
        """
        pass

    @abstractmethod
    def verifier_shares_to_message(self,
                                   ctx: bytes,
                                   agg_param: AggParam,
                                   verifier_shares: list[VerifierShare]) -> VerifierMessage:
        """
        Unshard the verifier shares from the previous round of verification.
        This is called by an Aggregator after receiving all of the message
        shares from the previous round.
        """
        pass

    @override
    @abstractmethod
    def agg_init(self,
                 agg_param: AggParam) -> AggShare:
        """
        Return an empty aggregate share.
        """
        pass

    @override
    @abstractmethod
    def agg_update(self,
                   agg_param: AggParam,
                   agg_share: AggShare,
                   out_share: OutShare) -> AggShare:
        """
        Accumulate an output share into an aggregate share and return the
        updated aggregate share.
        """
        pass

    @override
    @abstractmethod
    def merge(self,
              agg_param: AggParam,
              agg_shares: list[AggShare]) -> AggShare:
        """
        Merge a sequence of aggregate shares into a single aggregate share.
        """
        pass

    @override
    @abstractmethod
    def unshard(self,
                agg_param: AggParam,
                agg_shares: list[AggShare],
                num_measurements: int) -> AggResult:
        """
        Unshard the aggregate shares (encoded as byte strings) and compute the
        aggregate result. This is called by the Collector.

        Pre-condition:

            - `num_measurements >= 1`
        """
        pass

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def domain_separation_tag(self, usage: int, ctx: bytes) -> bytes:
        """
        Format domain separation tag for this VDAF with the given
        application context and usage.

        Pre-conditions:

            - `usage` in the range `[0, 2**16)`
        """
        return format_dst(0, self.ID, usage) + ctx

    @abstractmethod
    def encode_agg_param(self, agg_param: AggParam) -> bytes:
        pass

    @abstractmethod
    def decode_agg_param(self, encoded: bytes) -> AggParam:
        pass

    @abstractmethod
    def encode_input_share(self, input_share: InputShare) -> bytes:
        pass

    @abstractmethod
    def decode_input_share(self, agg_id: int, encoded: bytes) -> InputShare:
        pass

    @abstractmethod
    def encode_public_share(self, public_share: PublicShare) -> bytes:
        pass

    @abstractmethod
    def decode_public_share(self, encoded: bytes) -> PublicShare:
        pass

    @abstractmethod
    def encode_agg_share(self, agg_share: AggShare) -> bytes:
        pass

    @abstractmethod
    def decode_agg_share(self, agg_param: AggParam, encoded: bytes) -> AggShare:
        pass

    @abstractmethod
    def encode_verifier_share(self, verifier_share: VerifierShare) -> bytes:
        pass

    @abstractmethod
    def decode_verifier_share(self, verify_state: VerifyState, encoded: bytes) -> VerifierShare:
        pass

    @abstractmethod
    def encode_verifier_message(self, verifier_message: VerifierMessage) -> bytes:
        pass

    @abstractmethod
    def decode_verifier_message(self, verify_state: VerifyState, encoded: bytes) -> VerifierMessage:
        pass

    @abstractmethod
    def encode_out_share(self, out_share: OutShare) -> bytes:
        pass

    @abstractmethod
    def decode_out_share(self, agg_param: AggParam, encoded: bytes) -> OutShare:
        pass

    # Methods for generating test vectors

    def test_vec_set_type_param(self, _test_vec: dict[str, Any]) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []


# NOTE: This function is excerpted in the document, as the figure
# {{run-vdaf}}. Its width should be limited to 69 columns to avoid
# warnings from xml2rfc.
# ===================================================================
def run_vdaf(
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
        agg_param: AggParam,
        ctx: bytes,
        measurements: list[Measurement]) -> AggResult:
    """
    Execute the VDAF for the given measurements, aggregation
    parameter (`agg_param`), application context (`ctx`), and
    verification key (`verify_key`).
    """
    # REMOVE ME
    if len(verify_key) != vdaf.VERIFY_KEY_SIZE:
        raise ValueError("incorrect verify_key size")

    agg_shares = [vdaf.agg_init(agg_param)
                  for _ in range(vdaf.SHARES)]
    for measurement in measurements:
        # Sharding: The Client shards its measurement into a report
        # consisting of a public share and a sequence of input
        # shares.
        nonce = gen_rand(vdaf.NONCE_SIZE)
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(ctx, measurement, nonce, rand)

        # Initialize verification: Each Aggregator receives its
        # report share (the public share and its input share) from
        # the Client and initializes verification.
        verify_states = []
        outbound_verifier_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.verify_init(verify_key, ctx, j,
                                              agg_param,
                                              nonce,
                                              public_share,
                                              input_shares[j])
            verify_states.append(state)
            outbound_verifier_shares.append(share)

        # Complete verification: The Aggregators execute each round
        # of verification until each computes an output share. A
        # round begins by gathering the verifier shares and combining
        # them into the verifier message. The round ends when each
        # uses the verifier message to transition to the next state.
        for i in range(vdaf.ROUNDS - 1):
            verifier_message = vdaf.verifier_shares_to_message(
                ctx, agg_param, outbound_verifier_shares)

            outbound_verifier_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.verify_next(ctx,
                                       verify_states[j],
                                       verifier_message)
                assert isinstance(out, tuple)
                (verify_states[j], verifier_share) = out
                outbound_verifier_shares.append(verifier_share)

        verifier_message = vdaf.verifier_shares_to_message(
            ctx, agg_param, outbound_verifier_shares)

        # Aggregation: Each Aggregator updates its aggregate share
        # with its output share.
        for j in range(vdaf.SHARES):
            out_share = vdaf.verify_next(
                ctx, verify_states[j], verifier_message)
            assert not isinstance(out_share, tuple)
            agg_shares[j] = vdaf.agg_update(agg_param,
                                            agg_shares[j],
                                            out_share)

    # Unsharding: The Collector receives the aggregate shares from
    # the Aggregators and combines them into the aggregate result.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    return agg_result
