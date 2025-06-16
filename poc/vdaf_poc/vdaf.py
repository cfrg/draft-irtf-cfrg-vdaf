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
PrepState = TypeVar("PrepState")
PrepShare = TypeVar("PrepShare")
PrepMessage = TypeVar("PrepMessage")
F = TypeVar("F", bound=Field)


class Vdaf(
        Generic[
            Measurement, AggParam, PublicShare, InputShare, OutShare, AggShare,
            AggResult, PrepState, PrepShare, PrepMessage
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
    ID: int  # `[0, 2^32)`

    # Length of the verification key shared by the Aggregators.
    VERIFY_KEY_SIZE: int

    # Length of the nonce.
    NONCE_SIZE: int

    # Number of random bytes consumed by `shard()`.
    RAND_SIZE: int

    # The number of Aggregators.
    SHARES: int

    # The number of rounds of communication during the Prepare phase.
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
    def prep_init(self,
                  verify_key: bytes,
                  ctx: bytes,
                  agg_id: int,
                  agg_param: AggParam,
                  nonce: bytes,
                  public_share: PublicShare,
                  input_share: InputShare) -> tuple[PrepState, PrepShare]:
        """
        Initialize the prep state for the given input share and return the
        initial prep share. This method is run by an Aggregator. Along with the
        public share and its input share, the inputs include the verification
        key shared by all of the Aggregators, the Aggregator's ID, and the
        aggregation parameter, application context, and nonce agreed upon by
        all of the Aggregators.

        Pre-conditions:

            - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
            - `agg_id` in the range `[0, vdaf.SHARES)`
            - `len(nonce) == vdaf.NONCE_SIZE`
        """
        pass

    @abstractmethod
    def prep_next(self,
                  ctx: bytes,
                  prep_state: PrepState,
                  prep_msg: PrepMessage,
                  ) -> tuple[PrepState, PrepShare] | OutShare:
        """
        Consume the inbound message from the previous round and return the
        Aggregator's share of the next round (or the aggregator's output share
        if this is the last round).
        """
        pass

    @abstractmethod
    def prep_shares_to_prep(self,
                            ctx: bytes,
                            agg_param: AggParam,
                            prep_shares: list[PrepShare]) -> PrepMessage:
        """
        Unshard the prep shares from the previous round of preparation. This is
        called by an Aggregator after receiving all of the message shares from
        the previous round.
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

            - `usage` in the range `[0, 2^16)`
        """
        return format_dst(0, self.ID, usage) + ctx

    @abstractmethod
    def encode_agg_param(self, agg_param: AggParam) -> bytes:
        pass

    # Methods for generating test vectors

    def test_vec_set_type_param(self, _test_vec: dict[str, Any]) -> list[str]:
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Returns the keys that were set.
        """
        return []

    @abstractmethod
    def test_vec_encode_input_share(self, input_share: InputShare) -> bytes:
        pass

    @abstractmethod
    def test_vec_encode_public_share(self, public_share: PublicShare) -> bytes:
        pass

    @abstractmethod
    def test_vec_encode_agg_share(self, agg_share: AggShare) -> bytes:
        pass

    @abstractmethod
    def test_vec_encode_prep_share(self, prep_share: PrepShare) -> bytes:
        pass

    @abstractmethod
    def test_vec_encode_prep_msg(self, prep_message: PrepMessage) -> bytes:
        pass

    @abstractmethod
    def test_vec_encode_out_share(self, out_share: OutShare) -> bytes:
        pass


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
            PrepState,
            PrepShare,
            PrepMessage,
        ],
        verify_key: bytes,
        agg_param: AggParam,
        ctx: bytes,
        measurements: list[Measurement]) -> AggResult:
    """
    Pre-conditions:

        - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
    """
    # REMOVE ME
    if len(verify_key) != vdaf.VERIFY_KEY_SIZE:
        raise ValueError("incorrect verify_key size")

    agg_shares = [vdaf.agg_init(agg_param)
                  for _ in range(vdaf.SHARES)]
    for measurement in measurements:
        # Sharding
        nonce = gen_rand(vdaf.NONCE_SIZE)
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(ctx, measurement, nonce, rand)

        # Initialize preparation
        prep_states = []
        outbound_prep_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.prep_init(verify_key, ctx, j,
                                            agg_param,
                                            nonce,
                                            public_share,
                                            input_shares[j])
            prep_states.append(state)
            outbound_prep_shares.append(share)

        # Complete preparation
        for i in range(vdaf.ROUNDS - 1):
            prep_msg = vdaf.prep_shares_to_prep(ctx,
                                                agg_param,
                                                outbound_prep_shares)

            outbound_prep_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(ctx, prep_states[j], prep_msg)
                assert isinstance(out, tuple)
                (prep_states[j], prep_share) = out
                outbound_prep_shares.append(prep_share)

        prep_msg = vdaf.prep_shares_to_prep(ctx,
                                            agg_param,
                                            outbound_prep_shares)

        # Aggregation
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(ctx, prep_states[j], prep_msg)
            assert not isinstance(out_share, tuple)
            agg_shares[j] = vdaf.agg_update(agg_param,
                                            agg_shares[j],
                                            out_share)

    # Unsharding
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    return agg_result
