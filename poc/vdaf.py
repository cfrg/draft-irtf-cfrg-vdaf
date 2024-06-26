"""Definition of VDAFs."""

import json
import os
from abc import ABCMeta, abstractmethod
from typing import Any, Generic, Optional, TypedDict, TypeVar, Union, cast

from common import (TEST_VECTOR_PATH, format_dst, gen_rand, print_wrapped_line,
                    to_le_bytes)
from field import Field

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
                  ) -> Union[tuple[PrepState, PrepShare], OutShare]:
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


class PrepTestVectorDict(Generic[Measurement], TypedDict):
    measurement: Measurement
    nonce: str
    input_shares: list[str]
    prep_shares: list[list[str]]
    prep_messages: list[str]
    out_shares: list[list[str]]
    rand: str
    public_share: str


class TestVectorDict(Generic[Measurement, AggParam, AggResult], TypedDict):
    shares: int
    verify_key: str
    agg_param: AggParam
    prep: list[PrepTestVectorDict[Measurement]]
    agg_shares: list[str]
    agg_result: Optional[AggResult]


F = TypeVar("F", bound=Field)


# NOTE: This function is excerpted in the document, as the figure
# {{run-vdaf}}. Its width should be limited to 69 columns to avoid
# warnings from xml2rfc.
# ===================================================================
def run_vdaf(
        vdaf: Vdaf[
            Measurement, AggParam, PublicShare, InputShare, list[F], AggShare,
            AggResult, PrepState, PrepShare, PrepMessage
        ],
        verify_key: bytes,
        agg_param: AggParam,
        nonces: list[bytes],
        measurements: list[Measurement],
        print_test_vec: bool = False,
        test_vec_instance: int = 0) -> AggResult:
    """Run the VDAF on a list of measurements.

    Pre-conditions:

        - `len(verify_key) == vdaf.VERIFY_KEY_SIZE`
        - `len(nonces) == len(measurements)`
        - `len(nonce) == vdaf.NONCE_SIZE` for each `nonce` in `nonces`
    """

    if len(verify_key) != vdaf.VERIFY_KEY_SIZE:
        raise ValueError("incorrect verify_key size")
    if any(len(nonce) != vdaf.NONCE_SIZE for nonce in nonces):
        raise ValueError("incorrect nonce size")
    if len(nonces) != len(measurements):
        raise ValueError(
            "measurements and nonces lists have different lengths"
        )

    # REMOVE ME
    test_vec: TestVectorDict[Measurement, AggParam, AggResult] = {
        'shares': vdaf.SHARES,
        'verify_key': verify_key.hex(),
        'agg_param': agg_param,
        'prep': [],
        'agg_shares': [],
        'agg_result': None,  # set below
    }
    type_params = vdaf.test_vec_set_type_param(cast(dict[str, Any], test_vec))

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        assert len(nonce) == vdaf.NONCE_SIZE

        # Each Client shards its measurement into input shares.
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            vdaf.shard(measurement, nonce, rand)

        # REMOVE ME
        prep_test_vec: PrepTestVectorDict[Measurement] = {
            'measurement': measurement,
            'nonce': nonce.hex(),
            'input_shares': [],
            'prep_shares': [[] for _ in range(vdaf.ROUNDS)],
            'prep_messages': [],
            'out_shares': [],
            'rand': rand.hex(),
            'public_share': vdaf.test_vec_encode_public_share(public_share).hex()
        }
        for input_share in input_shares:
            prep_test_vec['input_shares'].append(
                vdaf.test_vec_encode_input_share(input_share).hex())

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

        # REMOVE ME
        for prep_share in outbound_prep_shares:
            prep_test_vec['prep_shares'][0].append(
                vdaf.test_vec_encode_prep_share(prep_share).hex())

        # Aggregators recover their output shares.
        for i in range(vdaf.ROUNDS - 1):
            prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                                outbound_prep_shares)
            # REMOVE ME
            prep_test_vec['prep_messages'].append(
                vdaf.test_vec_encode_prep_msg(prep_msg).hex())

            outbound_prep_shares = []
            for j in range(vdaf.SHARES):
                out = vdaf.prep_next(prep_states[j], prep_msg)
                assert isinstance(out, tuple)
                (prep_states[j], prep_share) = out
                outbound_prep_shares.append(prep_share)
            # REMOVE ME
            for prep_share in outbound_prep_shares:
                prep_test_vec['prep_shares'][i+1].append(
                    vdaf.test_vec_encode_prep_share(prep_share).hex())

        # The final outputs of the prepare phase are the output shares.
        prep_msg = vdaf.prep_shares_to_prep(agg_param,
                                            outbound_prep_shares)
        # REMOVE ME
        prep_test_vec['prep_messages'].append(
            vdaf.test_vec_encode_prep_msg(prep_msg).hex())

        outbound_output_shares = []
        for j in range(vdaf.SHARES):
            out_share = vdaf.prep_next(prep_states[j], prep_msg)
            assert not isinstance(out_share, tuple)
            outbound_output_shares.append(out_share)

        # REMOVE ME
        for out_share in outbound_output_shares:
            prep_test_vec['out_shares'].append([
                to_le_bytes(x.as_unsigned(), x.ENCODED_SIZE).hex()
                for x in out_share
            ])
        test_vec['prep'].append(prep_test_vec)

        out_shares.append(outbound_output_shares)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = vdaf.aggregate(agg_param, out_shares_j)
        agg_shares.append(agg_share_j)
        # REMOVE ME
        test_vec['agg_shares'].append(
            vdaf.test_vec_encode_agg_share(agg_share_j).hex())

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = vdaf.unshard(agg_param, agg_shares,
                              num_measurements)
    # REMOVE ME
    test_vec['agg_result'] = agg_result
    if print_test_vec:
        pretty_print_vdaf_test_vec(vdaf, test_vec, type_params)

        os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
        filename = '{}/{}_{}.json'.format(
            TEST_VECTOR_PATH,
            vdaf.test_vec_name,
            test_vec_instance,
        )
        with open(filename, 'w', encoding="UTF-8") as f:
            json.dump(test_vec, f, indent=4, sort_keys=True)
            f.write('\n')

    return agg_result


def pretty_print_vdaf_test_vec(
        vdaf: Vdaf[
            Measurement, AggParam, Any, Any, Any, Any, AggResult, Any, Any, Any
        ],
        typed_test_vec: TestVectorDict[Measurement, AggParam, AggResult],
        type_params: list[str]) -> None:
    test_vec = cast(dict[str, Any], typed_test_vec)
    print('---------- {} ---------------'.format(vdaf.test_vec_name))
    for type_param in type_params:
        print('{}: {}'.format(type_param, test_vec[type_param]))
    print('verify_key: "{}"'.format(test_vec['verify_key']))
    if test_vec['agg_param'] is not None:
        print('agg_param: {}'.format(test_vec['agg_param']))

    for (n, prep_test_vec) in enumerate(test_vec['prep']):
        print('upload_{}:'.format(n))
        print('  measurement: {}'.format(prep_test_vec['measurement']))
        print('  nonce: "{}"'.format(prep_test_vec['nonce']))
        print('  public_share: >-')
        print_wrapped_line(prep_test_vec['public_share'], tab=4)

        # Shard
        for (i, input_share) in enumerate(prep_test_vec['input_shares']):
            print('  input_share_{}: >-'.format(i))
            print_wrapped_line(input_share, tab=4)

        # Prepare
        for (i, (prep_shares, prep_msg)) in enumerate(zip(prep_test_vec['prep_shares'], prep_test_vec['prep_messages'])):
            print('  round_{}:'.format(i))
            for (j, prep_share) in enumerate(prep_shares):
                print('    prep_share_{}: >-'.format(j))
                print_wrapped_line(prep_share, tab=6)
            print('    prep_message: >-')
            print_wrapped_line(prep_msg, tab=6)

        for (j, out_shares) in enumerate(prep_test_vec['out_shares']):
            print('  out_share_{}:'.format(j))
            for out_share in out_shares:
                print('    - {}'.format(out_share))

    # Aggregate
    for (j, agg_share) in enumerate(test_vec['agg_shares']):
        print('agg_share_{}: >-'.format(j))
        print_wrapped_line(agg_share, tab=2)

    # Unshard
    print('agg_result: {}'.format(test_vec['agg_result']))
    print()
