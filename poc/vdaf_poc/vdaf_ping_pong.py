"""Ping-pong topology for VDAFs."""

from abc import ABCMeta
from typing import Generic, TypeVar, cast

from vdaf_poc.common import byte, from_be_bytes, front, to_be_bytes
from vdaf_poc.vdaf import Vdaf

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

# NOTE: Classes State, Start, Continued, Finished, and Rejected are excerpted in
# the document. Their width should be limited to 69 columns to avoid warnings
# from xml2rfc.
# ===================================================================


class State:
    pass


class Start(State):
    pass


class Continued(State, Generic[VerifyState]):
    def __init__(self,
                 ver_state: VerifyState,
                 ver_round: int,
                 outbound: bytes):
        self.ver_state = ver_state
        self.ver_round = ver_round
        self.outbound = outbound

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Continued) and \
            self.ver_state == other.ver_state and \
            self.ver_round == other.ver_round and \
            self.outbound == other.outbound


class Finished(State, Generic[OutShare]):
    def __init__(self, out_share: OutShare):
        self.out_share = out_share

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Finished) and \
            self.out_share == other.out_share


class FinishedWithOutbound(State, Generic[OutShare]):
    def __init__(self, out_share: OutShare, outbound: bytes):
        self.out_share = out_share
        self.outbound = outbound

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FinishedWithOutbound) and \
            self.out_share == other.out_share and \
            self.outbound == other.outbound


class Rejected(State):
    pass


class PingPong(
        Vdaf[
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
        metaclass=ABCMeta):
    # NOTE: Methods ping_pong_leader_init(), ping_pong_helper_init(),
    # ping_pong_transition(), ping_pong_leader_continued(),
    # ping_pong_continued(), and ping_pong_helper_continued() are excerpted in
    # the document, de-indented. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid warnings
    # from xml2rfc.
    # ===================================================================
    def ping_pong_leader_init(
            self,
            vdaf_verify_key: bytes,
            ctx: bytes,
            agg_param: bytes,
            nonce: bytes,
            public_share: bytes,
            input_share: bytes) -> Continued | Rejected:
        """Called by the Leader to initialize ping-ponging."""
        try:
            (ver_state, ver_share) = self.verify_init(
                vdaf_verify_key,
                ctx,
                0,
                self.decode_agg_param(agg_param),
                nonce,
                self.decode_public_share(public_share),
                self.decode_input_share(0, input_share),
            )

            encoded_ver_share = self.encode_ver_share(ver_share)
            return Continued(
                ver_state, 0,
                encode(0, encoded_ver_share),  # initialize
            )
        except Exception:
            return Rejected()

    def ping_pong_helper_init(
        self,
        vdaf_verify_key: bytes,
        ctx: bytes,
        agg_param: bytes,
        nonce: bytes,
        public_share: bytes,
        input_share: bytes,
        inbound: bytes,  # encoded ping pong Message
    ) -> Continued | FinishedWithOutbound | Rejected:
        """
        Called by the Helper in response to the Leader's initial
        message.
        """

        try:
            (ver_state, ver_share) = self.verify_init(
                vdaf_verify_key,
                ctx,
                1,
                self.decode_agg_param(agg_param),
                nonce,
                self.decode_public_share(public_share),
                self.decode_input_share(1, input_share),
            )

            (inbound_type, inbound_items) = decode(inbound)
            if inbound_type != 0:  # initialize
                return Rejected()

            encoded_ver_share = inbound_items[0]
            ver_shares = [
                self.decode_ver_share(ver_state, encoded_ver_share),
                ver_share,
            ]
            return self.ping_pong_transition(
                ctx,
                self.decode_agg_param(agg_param),
                ver_shares,
                ver_state,
                0,
            )
        except Exception:
            return Rejected()

    def ping_pong_transition(
            self,
            ctx: bytes,
            agg_param: AggParam,
            ver_shares: list[VerifierShare],
            ver_state: VerifyState,
            ver_round: int) -> Continued | FinishedWithOutbound:
        ver_msg = self.ver_shares_to_msg(ctx,
                                         agg_param,
                                         ver_shares)
        encoded_ver_msg = self.encode_ver_msg(ver_msg)
        out = self.verify_next(ctx, ver_state, ver_msg)
        if ver_round+1 == self.ROUNDS:
            return FinishedWithOutbound(
                out,
                encode(2, encoded_ver_msg),  # finalize
            )
        (ver_state, ver_share) = cast(
            tuple[VerifyState, VerifierShare], out)
        encoded_ver_share = self.encode_ver_share(ver_share)
        return Continued(
            ver_state, ver_round+1,
            encode(1, encoded_ver_msg, encoded_ver_share)  # continue
        )

    def ping_pong_leader_continued(
        self,
        ctx: bytes,
        agg_param: bytes,
        state: Continued,
        inbound: bytes,  # encoded ping pong Message
    ) -> State:
        """
        Called by the Leader to start the next step of ping-ponging.
        """
        return self.ping_pong_continued(
            True, ctx, agg_param, state, inbound)

    def ping_pong_continued(
        self,
        is_leader: bool,
        ctx: bytes,
        agg_param: bytes,
        state: Continued,
        inbound: bytes,  # encoded ping pong Message
    ) -> State:
        try:
            ver_round = state.ver_round

            (inbound_type, inbound_items) = decode(inbound)
            if inbound_type == 0:  # initialize
                return Rejected()

            encoded_ver_msg = inbound_items[0]
            ver_msg = self.decode_ver_msg(
                state.ver_state,
                encoded_ver_msg,
            )
            out = self.verify_next(ctx, state.ver_state, ver_msg)
            if ver_round+1 < self.ROUNDS and \
                    inbound_type == 1:  # continue
                (ver_state, ver_share) = cast(
                    tuple[VerifyState, VerifierShare], out)
                encoded_ver_share = inbound_items[1]
                ver_shares = [
                    self.decode_ver_share(
                        ver_state,
                        encoded_ver_share,
                    ),
                    ver_share,
                ]
                if is_leader:
                    ver_shares.reverse()
                return self.ping_pong_transition(
                    ctx,
                    self.decode_agg_param(agg_param),
                    ver_shares,
                    ver_state,
                    ver_round+1,
                )
            elif ver_round+1 == self.ROUNDS and \
                    inbound_type == 2:  # finish
                return Finished(out)
            else:
                return Rejected()
        except Exception:
            return Rejected()

    def ping_pong_helper_continued(
        self,
        ctx: bytes,
        agg_param: bytes,
        state: Continued,
        inbound: bytes,  # encoded ping pong Message
    ) -> State:
        """Called by the Helper to continue ping-ponging."""
        return self.ping_pong_continued(
            False, ctx, agg_param, state, inbound)


def encode(msg_type: int, *items: bytes) -> bytes:
    encoded = bytes()
    encoded += byte(msg_type)
    for item in items:
        encoded += to_be_bytes(len(item), 4)
        encoded += item
    return encoded


def decode(encoded: bytes) -> tuple[int, list[bytes]]:
    ([msg_type], encoded) = front(1, encoded)
    if msg_type == 0:    # initialize
        num_counts = 1   # ver_share
    elif msg_type == 1:  # continue
        num_counts = 2   # ver_msg, ver_share
    elif msg_type == 2:  # finish
        num_counts = 1   # ver_msg
    else:
        raise ValueError('unexpected message type: {}'.format(msg_type))
    items = []
    for _ in range(num_counts):
        (encoded_item_len, encoded) = front(4, encoded)
        item_len = from_be_bytes(encoded_item_len)
        (item, encoded) = front(item_len, encoded)
        items.append(item)
    if len(encoded) > 0:
        raise ValueError('unexpected message length')
    return (int(msg_type), items)
