"""Definition of VDAFs."""

from abc import ABCMeta, abstractmethod
from typing import Any, Generic, TypeVar

from vdaf_poc.common import format_dst, gen_rand
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
        metaclass=ABCMeta):
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
    ID: int  # `range(2**32)`

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

    @abstractmethod
    def shard(self,
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
        aggregation parameter and nonce agreed upon by all of the Aggregators.

        Pre-conditions:

            - `len(verify_key) == Vdaf.VERIFY_KEY_SIZE`
            - `agg_id` in `range(0, Vdaf.SHARES)`
            - `len(nonce) == Vdaf.NONCE_SIZE`
        """
        pass

    @abstractmethod
    def prep_next(self,
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
                            agg_param: AggParam,
                            prep_shares: list[PrepShare]) -> PrepMessage:
        """
        Unshard the prep shares from the previous round of preparation. This is
        called by an Aggregator after receiving all of the message shares from
        the previous round.
        """
        pass

    @abstractmethod
    def aggregate(self,
                  agg_param: AggParam,
                  out_shares: list[OutShare]) -> AggShare:
        """
        Merge a list of output shares into an aggregate share, encoded as a byte
        string. This is called by an aggregator after recovering a batch of
        output shares.
        """
        pass

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
    def domain_separation_tag(self, usage: int) -> bytes:
        """
        Format domain separation tag for this VDAF with the given usage.

        Pre-conditions:

            - `usage` in `range(2**16)`
        """
        return format_dst(0, self.ID, usage)

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
            list[F],  # OutShare
            AggShare,
            AggResult,
            PrepState,
            PrepShare,
            PrepMessage,
        ],
        verify_key: bytes,
        agg_param: AggParam,
        nonces: list[bytes],
        measurements: list[Measurement]) -> AggResult:
    """
    Run the VDAF on a list of measurements.

    Pre-conditions:

        - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
        - `len(nonces) == len(measurements)`
        - `all(len(nonce) == vdaf.NONCE_SIZE for nonce in nonces)`
    """

    if len(verify_key) != vdaf.VERIFY_KEY_SIZE:
        raise ValueError("incorrect verify_key size")
    if any(len(nonce) != vdaf.NONCE_SIZE for nonce in nonces):
        raise ValueError("incorrect nonce size")
    if len(nonces) != len(measurements):
        raise ValueError(
            "measurements and nonces lists have different lengths"
        )

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == vdaf.NONCE_SIZE

        # Each Client shards its measurement into input shares.
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(measurement, nonce, rand)

        # Each Aggregator initializes its preparation state.
        prep_states = []
        outbound_prep_shares = []
        for j in range(vdaf.SHARES):
            (state, share) = vdaf.prep_init(verify_key, j,
                                            agg_param,
                                            nonce,
                                            public_share,
                                            input_shares[j])
            prep_states.append(state)
            outbound_prep_shares.append(share)

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS - 1):
            prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                                outbound_prep_shares)

            outbound_prep_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(prep_states[j], prep_msg)
                assert isinstance(out, tuple)
                (prep_states[j], prep_share) = out
                outbound_prep_shares.append(prep_share)

        # The final outputs of the prepare phase are the output
        # shares.
        prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                            outbound_prep_shares)

        outbound_out_shares = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(prep_states[j], prep_msg)
            assert not isinstance(out_share, tuple)
            outbound_out_shares.append(out_share)

        out_shares.append(outbound_out_shares)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.aggregate(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    return agg_result
