"""The Poplar1 VDAF."""

from typing import Any, Optional, Sequence, TypeAlias, Union, cast

from common import byte, from_be_bytes, front, to_be_bytes, vec_add, vec_sub
from field import Field, Field64, Field255
from idpf import Idpf
from idpf_poplar import IdpfPoplar
from vdaf import Vdaf
from xof import Xof, XofTurboShake128

USAGE_SHARD_RAND = 1
USAGE_CORR_INNER = 2
USAGE_CORR_LEAF = 3
USAGE_VERIFY_RAND = 4

FieldVec: TypeAlias = Union[list[Field64], list[Field255]]
Poplar1AggParam: TypeAlias = tuple[
    int,  # level
    Sequence[int],  # prefixes
]
Poplar1InputShare: TypeAlias = tuple[
    bytes,  # IDPF key
    bytes,  # correlated randomness seed
    list[Field64],  # inner node correlated randomness
    list[Field255],  # leaf node correlated randomness
]
Poplar1PrepState: TypeAlias = tuple[
    bytes,  # sketch step (evaluate or reveal)
    int,  # level
    FieldVec,  # output (and sketch) share
]


class Poplar1(
        Vdaf[
            int,  # Measurement, `range(0, 2 ** BITS)`
            Poplar1AggParam,  # AggParam
            bytes,  # PublicShare, encoded IDPF public share
            Poplar1InputShare,  # InputShare
            FieldVec,  # OutShare
            FieldVec,  # AggShare
            list[int],  # AggResult
            Poplar1PrepState,  # PrepState
            FieldVec,  # PrepShare
            Optional[FieldVec],  # PrepMessage
        ]):

    idpf: Idpf[Field64, Field255]
    xof: type[Xof]

    ID = 0x00001000
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 2

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Poplar1'

    def __init__(self, bits: int):
        self.idpf = IdpfPoplar(2, bits)
        self.xof = XofTurboShake128
        self.VERIFY_KEY_SIZE = self.xof.SEED_SIZE
        self.RAND_SIZE = 3 * self.xof.SEED_SIZE + self.idpf.RAND_SIZE

    # NOTE: This method is excerpted in the document, de-indented, as the
    # figure {{poplar1-mes2inp}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def shard(self, measurement: int, nonce: bytes, rand: bytes) -> tuple[bytes, list[Poplar1InputShare]]:
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("incorrect size of random bytes argument")

        l = self.xof.SEED_SIZE

        # Split the random input into the random input for IDPF key
        # generation, correlated randomness, and sharding.
        if len(rand) != self.RAND_SIZE:
            raise ValueError('incorrect rand size')
        idpf_rand, rand = front(self.idpf.RAND_SIZE, rand)
        seeds = [rand[i:i + l] for i in range(0, 3 * l, l)]
        corr_seed, seeds = front(2, seeds)
        (k_shard,), seeds = front(1, seeds)

        xof = self.xof(
            k_shard,
            self.domain_separation_tag(USAGE_SHARD_RAND),
            nonce,
        )

        # Construct the IDPF values for each level of the IDPF tree.
        # Each "data" value is 1; in addition, the Client generates
        # a random "authenticator" value used by the Aggregators to
        # evaluate the sketch during preparation. This sketch is used
        # to verify the one-hotness of their output shares.
        beta_inner = [
            [self.idpf.field_inner(1), k]
            for k in xof.next_vec(self.idpf.field_inner,
                                  self.idpf.BITS - 1)
        ]
        beta_leaf = [self.idpf.field_leaf(1)] + \
            xof.next_vec(self.idpf.field_leaf, 1)

        # Generate the IDPF keys.
        (public_share, keys) = self.idpf.gen(
            measurement,
            beta_inner,
            beta_leaf,
            nonce,
            idpf_rand,
        )

        # Generate correlated randomness used by the Aggregators to
        # evaluate the sketch over their output shares. Seeds are used
        # to encode shares of the `(a, b, c)` triples. (See [BBCGGI21,
        # Appendix C.4].)
        corr_offsets: list[Field] = vec_add(
            self.xof.expand_into_vec(
                self.idpf.field_inner,
                corr_seed[0],
                self.domain_separation_tag(USAGE_CORR_INNER),
                byte(0) + nonce,
                3 * (self.idpf.BITS - 1),
            ),
            self.xof.expand_into_vec(
                self.idpf.field_inner,
                corr_seed[1],
                self.domain_separation_tag(USAGE_CORR_INNER),
                byte(1) + nonce,
                3 * (self.idpf.BITS - 1),
            ),
        )
        corr_offsets += vec_add(
            self.xof.expand_into_vec(
                self.idpf.field_leaf,
                corr_seed[0],
                self.domain_separation_tag(USAGE_CORR_LEAF),
                byte(0) + nonce,
                3,
            ),
            self.xof.expand_into_vec(
                self.idpf.field_leaf,
                corr_seed[1],
                self.domain_separation_tag(USAGE_CORR_LEAF),
                byte(1) + nonce,
                3,
            ),
        )

        # For each level of the IDPF tree, shares of the `(A, B)`
        # pairs are computed from the corresponding `(a, b, c)`
        # triple and authenticator value `k`.
        corr_inner: list[list[Field64]] = [[], []]
        for level in range(self.idpf.BITS):
            field = cast(type[Field], self.idpf.current_field(level))
            k = beta_inner[level][1] if level < self.idpf.BITS - 1 \
                else beta_leaf[1]
            (a, b, c), corr_offsets = corr_offsets[:3], corr_offsets[3:]
            A = -field(2) * a + k
            B = a ** 2 + b - a * k + c
            corr1 = xof.next_vec(field, 2)
            corr0 = vec_sub([A, B], corr1)
            if level < self.idpf.BITS - 1:
                corr_inner[0] += cast(list[Field64], corr0)
                corr_inner[1] += cast(list[Field64], corr1)
            else:
                corr_leaf = [
                    cast(list[Field255], corr0),
                    cast(list[Field255], corr1),
                ]

        # Each input share consists of the Aggregator's IDPF key
        # and a share of the correlated randomness.
        input_shares = list(zip(keys, corr_seed, corr_inner, corr_leaf))
        return (public_share, input_shares)

    # NOTE: This method is excerpted in the document, de-indented, as
    # part of the figure {{poplar1-validity-scope}}. Its width should be
    # limited to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def is_valid(self, agg_param: Poplar1AggParam, previous_agg_params: list[Poplar1AggParam]) -> bool:
        """
        Checks that levels are increasing between calls, and also enforces that
        the prefixes at each level are suffixes of the previous level's
        prefixes.
        """
        if len(previous_agg_params) < 1:
            return True

        (level, prefixes) = agg_param
        (last_level, last_prefixes) = previous_agg_params[-1]
        last_prefixes_set = set(last_prefixes)

        # Check that level increased.
        if level <= last_level:
            return False

        # Check that prefixes are suffixes of the last level's prefixes.
        for prefix in prefixes:
            last_prefix = get_ancestor(prefix, level, last_level)
            if last_prefix not in last_prefixes_set:
                # Current prefix not a suffix of last level's prefixes.
                return False
        return True

    # NOTE: The prep_init(), prep_next(), and prep_shares_to_prep()
    # methods are excerpted in the document, de-indented, as the figure
    # {{poplar1-prep-state}}. Their width should be limited to 69 columns
    # after de-indenting, or 73 columns before de-indenting, to avoid
    # warnings from xml2rfc.
    # ===================================================================
    def prep_init(self, verify_key: bytes, agg_id: int, agg_param: Poplar1AggParam,
                  nonce: bytes, public_share: bytes, input_share: Poplar1InputShare) -> tuple[Poplar1PrepState, FieldVec]:
        (level, prefixes) = agg_param
        (key, corr_seed, corr_inner, corr_leaf) = input_share
        field = self.idpf.current_field(level)

        # Ensure that candidate prefixes are all unique and appear in
        # lexicographic order.
        for i in range(1, len(prefixes)):
            if prefixes[i - 1] >= prefixes[i]:
                raise ValueError('out of order prefix')

        # Evaluate the IDPF key at the given set of prefixes.
        value = self.idpf.eval(
            agg_id, public_share, key, level, prefixes, nonce)

        # Get shares of the correlated randomness for evaluating the
        # Aggregator's share of the sketch.
        if level < self.idpf.BITS - 1:
            corr_xof = self.xof(
                corr_seed,
                self.domain_separation_tag(USAGE_CORR_INNER),
                byte(agg_id) + nonce,
            )
            # Fast-forward the XOF state to the current level.
            corr_xof.next_vec(field, 3 * level)
        else:
            corr_xof = self.xof(
                corr_seed,
                self.domain_separation_tag(USAGE_CORR_LEAF),
                byte(agg_id) + nonce,
            )
        (a_share, b_share, c_share) = corr_xof.next_vec(field, 3)
        if level < self.idpf.BITS - 1:
            (A_share, B_share) = cast(
                list[Field],
                corr_inner[2 * level:2 * (level + 1)],
            )
        else:
            (A_share, B_share) = cast(list[Field], corr_leaf)

        # Evaluate the Aggregator's share of the sketch. These are
        # called the "masked input values" [BBCGGI21, Appendix C.4].
        verify_rand_xof = self.xof(
            verify_key,
            self.domain_separation_tag(USAGE_VERIFY_RAND),
            nonce + to_be_bytes(level, 2),
        )
        verify_rand = cast(
            list[Field],
            verify_rand_xof.next_vec(field, len(prefixes)),
        )
        sketch_share = [a_share, b_share, c_share]
        out_share = []
        for (i, r) in enumerate(verify_rand):
            data_share = cast(Field, value[i][0])
            auth_share = cast(Field, value[i][1])
            sketch_share[0] += data_share * r
            sketch_share[1] += data_share * r ** 2
            sketch_share[2] += auth_share * r
            out_share.append(data_share)

        prep_mem = [A_share, B_share, field(agg_id)] + out_share
        return (
            (
                b'evaluate sketch',
                level,
                cast(FieldVec, prep_mem),
            ),
            cast(FieldVec, sketch_share),
        )

    def prep_next(self, prep_state: Poplar1PrepState, prep_msg: Optional[FieldVec]) -> Union[tuple[Poplar1PrepState, FieldVec], FieldVec]:
        prev_sketch = cast(list[Field], prep_msg)
        (step, level, prep_mem) = prep_state

        if step == b'evaluate sketch':
            if prev_sketch is None:
                raise ValueError("inconsistent state")
            elif len(prev_sketch) != 3:
                raise ValueError('incorrect sketch length')
            A_share = cast(Field, prep_mem[0])
            B_share = cast(Field, prep_mem[1])
            agg_id = cast(Field, prep_mem[2])
            prep_mem = prep_mem[3:]
            sketch_share = [
                agg_id * (prev_sketch[0] ** 2
                          - prev_sketch[1]
                          - prev_sketch[2])
                + A_share * prev_sketch[0]
                + B_share
            ]
            return cast(
                tuple[Poplar1PrepState, FieldVec],
                (
                    (
                        b'reveal sketch',
                        level,
                        prep_mem,
                    ),
                    sketch_share,
                )
            )

        elif step == b'reveal sketch':
            if prev_sketch is None:
                return prep_mem  # Output shares
            else:
                raise ValueError('invalid prep message')

        raise ValueError('invalid prep state')

    def prep_shares_to_prep(self, agg_param: Poplar1AggParam, prep_shares: list[FieldVec]) -> Optional[FieldVec]:
        if len(prep_shares) != 2:
            raise ValueError('incorrect number of prep shares')
        (level, _) = agg_param
        field = self.idpf.current_field(level)
        sketch = vec_add(
            cast(list[Field], prep_shares[0]),
            cast(list[Field], prep_shares[1]),
        )
        if len(sketch) == 3:
            return cast(FieldVec, sketch)
        elif len(sketch) == 1:
            if sketch == field.zeros(1):
                # In order to reduce communication overhead, let `None`
                # denote a successful sketch verification.
                return None
            else:
                raise ValueError('sketch verification failed')
        else:
            raise ValueError('incorrect sketch length')

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{poplar1-out2agg}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def aggregate(self, agg_param: Poplar1AggParam, out_shares: list[FieldVec]) -> FieldVec:
        (level, prefixes) = agg_param
        field = self.idpf.current_field(level)
        agg_share = cast(list[Field], field.zeros(len(prefixes)))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, cast(list[Field], out_share))
        return cast(FieldVec, agg_share)

    # NOTE: This method is excerpted in the document, de-indented, as
    # figure {{poplar1-agg-output}}. Its width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    def unshard(self, agg_param: Poplar1AggParam,
                agg_shares: list[FieldVec], _num_measurements: int) -> list[int]:
        (level, prefixes) = agg_param
        field = self.idpf.current_field(level)
        agg = cast(list[Field], field.zeros(len(prefixes)))
        for agg_share in agg_shares:
            agg = vec_add(agg, cast(list[Field], agg_share))
        return [x.as_unsigned() for x in agg]

    # NOTE: The encode_agg_param() and decode_agg_param() methods are
    # excerpted in the document, de-indented. Their width should be
    # limited to 69 columns after de-indenting, or 73 columns before
    # de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def encode_agg_param(self, level: int, prefixes: Sequence[int]) -> bytes:
        if level not in range(2 ** 16):
            raise ValueError('level out of range')
        if len(prefixes) not in range(2 ** 32):
            raise ValueError('number of prefixes out of range')
        encoded = bytes()
        encoded += to_be_bytes(level, 2)
        encoded += to_be_bytes(len(prefixes), 4)
        packed = 0
        for (i, prefix) in enumerate(prefixes):
            packed |= prefix << ((level + 1) * i)
        l = ((level + 1) * len(prefixes) + 7) // 8
        encoded += to_be_bytes(packed, l)
        return encoded

    def decode_agg_param(self, encoded: bytes) -> Poplar1AggParam:
        encoded_level, encoded = encoded[:2], encoded[2:]
        level = from_be_bytes(encoded_level)
        encoded_prefix_count, encoded = encoded[:4], encoded[4:]
        prefix_count = from_be_bytes(encoded_prefix_count)
        l = ((level + 1) * prefix_count + 7) // 8
        encoded_packed, encoded = encoded[:l], encoded[l:]
        packed = from_be_bytes(encoded_packed)
        prefixes = []
        m = 2 ** (level + 1) - 1
        for i in range(prefix_count):
            prefixes.append(packed >> ((level + 1) * i) & m)
        if len(encoded) != 0:
            raise ValueError('trailing bytes')
        return (level, tuple(prefixes))

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['bits'] = int(self.idpf.BITS)
        return ['bits']

    def test_vec_encode_input_share(self, input_share: Poplar1InputShare) -> bytes:
        (key, seed, inner, leaf) = input_share
        encoded = bytes()
        encoded += key
        encoded += seed
        encoded += self.idpf.field_inner.encode_vec(inner)
        encoded += self.idpf.field_leaf.encode_vec(leaf)
        return encoded

    def test_vec_encode_public_share(self, public_share: bytes) -> bytes:
        return public_share

    def test_vec_encode_agg_share(self, agg_share: FieldVec) -> bytes:
        return encode_idpf_field_vec(agg_share)

    def test_vec_encode_prep_share(self, prep_share: FieldVec) -> bytes:
        return encode_idpf_field_vec(prep_share)

    def test_vec_encode_prep_msg(self, prep_message: Optional[FieldVec]) -> bytes:
        if prep_message is not None:
            return encode_idpf_field_vec(prep_message)
        return b''


def encode_idpf_field_vec(vec: FieldVec) -> bytes:
    encoded = bytes()
    if len(vec) > 0:
        field = vec[0].__class__
        encoded += cast(type[Field], field).encode_vec(cast(list[Field], vec))
    return encoded


# NOTE: This function is excerpted in the document, as part of the
# figure {{poplar1-validity-scope}}. Its width should be limited to
# 69 columns, to avoid warnings from xml2rfc.
# ===================================================================
def get_ancestor(index: int, this_level: int, last_level: int) -> int:
    """
    Helper function to determine the prefix of `index` at `last_level`.
    """
    return index >> (this_level - last_level)
