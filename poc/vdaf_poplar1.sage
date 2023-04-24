"""The Poplar1 VDAF."""

from __future__ import annotations
from collections import namedtuple
from typing import Tuple, Union
from common import \
    ERR_INPUT, \
    ERR_VERIFY, \
    TEST_VECTOR, \
    Bytes, \
    Error, \
    Unsigned, \
    Vec, \
    byte, \
    from_be_bytes, \
    front, \
    to_be_bytes, \
    vec_add, \
    vec_sub
from vdaf import Vdaf, test_vdaf
import sagelib.idpf as idpf
import sagelib.idpf_poplar as idpf_poplar
import sagelib.prg as prg

DST_SHARD_RAND = 1
DST_CORR_INNER = 2
DST_CORR_LEAF = 3
DST_VERIFY_RAND = 4

class Poplar1(Vdaf):
    # Types provided by a concrete instadce of `Poplar1`.
    Idpf = idpf.Idpf
    Prg = prg.Prg

    # Parameters required by `Vdaf`.
    ID = 0x00001000
    VERIFY_KEY_SIZE = None # Set by Idpf.Prg
    RAND_SIZE = None # Set by Idpf.Prg
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 2

    # Types required by `Vdaf`.
    Measurement = Unsigned
    AggParam = Tuple[Unsigned, Vec[Unsigned]]
    Prep = Tuple[Bytes,
                 Unsigned,
                 Union[Vec[Vec[Idpf.FieldInner]],
                       Vec[Vec[Idpf.FieldLeaf]]]]
    OutShare = Union[Vec[Vec[Idpf.FieldInner]],
                     Vec[Vec[Idpf.FieldLeaf]]]
    AggResult = Vec[Unsigned]

    # Operational parameters.
    test_vec_name = 'Poplar1'

    @classmethod
    def measurement_to_input_shares(Poplar1, measurement, nonce, rand):
        l = Poplar1.Prg.SEED_SIZE

        # Split the random input into the random input for IDPF key
        # generation, correlated randomness, and sharding.
        if len(rand) != Poplar1.RAND_SIZE:
            raise ERR_INPUT # unexpected length for random input
        idpf_rand, rand = front(Poplar1.Idpf.RAND_SIZE, rand)
        seeds = [rand[i:i+l] for i in range(0,3*l,l)]
        corr_seed, seeds = front(2, seeds)
        (k_shard,), seeds = front(1, seeds)

        prg = Poplar1.Prg(k_shard,
                               Poplar1.custom(DST_SHARD_RAND), b'')

        # Construct the IDPF values for each level of the IDPF tree.
        # Each "data" value is 1; in addition, the Client generates
        # a random "authenticator" value used by the Aggregators to
        # compute the sketch during preparation. This sketch is used
        # to verify the one-hotness of their output shares.
        beta_inner = [
            [Poplar1.Idpf.FieldInner(1), k] \
                for k in prg.next_vec(Poplar1.Idpf.FieldInner,
                                      Poplar1.Idpf.BITS - 1) ]
        beta_leaf = [Poplar1.Idpf.FieldLeaf(1)] + \
            prg.next_vec(Poplar1.Idpf.FieldLeaf, 1)

        # Generate the IDPF keys.
        (public_share, keys) = Poplar1.Idpf.gen(measurement,
                                                beta_inner,
                                                beta_leaf,
                                                nonce,
                                                idpf_rand)

        # Generate correlated randomness used by the Aggregators to
        # compute a sketch over their output shares. PRG seeds are
        # used to encode shares of the `(a, b, c)` triples.
        # (See [BBCGGI21, Appendix C.4].)
        corr_offsets = vec_add(
            Poplar1.Prg.expand_into_vec(
                Poplar1.Idpf.FieldInner,
                corr_seed[0],
                Poplar1.custom(DST_CORR_INNER),
                byte(0) + nonce,
                3 * (Poplar1.Idpf.BITS-1),
            ),
            Poplar1.Prg.expand_into_vec(
                Poplar1.Idpf.FieldInner,
                corr_seed[1],
                Poplar1.custom(DST_CORR_INNER),
                byte(1) + nonce,
                3 * (Poplar1.Idpf.BITS-1),
            ),
        )
        corr_offsets += vec_add(
            Poplar1.Prg.expand_into_vec(
                Poplar1.Idpf.FieldLeaf,
                corr_seed[0],
                Poplar1.custom(DST_CORR_LEAF),
                byte(0) + nonce,
                3,
            ),
            Poplar1.Prg.expand_into_vec(
                Poplar1.Idpf.FieldLeaf,
                corr_seed[1],
                Poplar1.custom(DST_CORR_LEAF),
                byte(1) + nonce,
                3,
            ),
        )

        # For each level of the IDPF tree, shares of the `(A, B)`
        # pairs are computed from the corresponding `(a, b, c)`
        # triple and authenticator value `k`.
        corr_inner = [[], []]
        for level in range(Poplar1.Idpf.BITS):
            Field = Poplar1.Idpf.current_field(level)
            k = beta_inner[level][1] if level < Poplar1.Idpf.BITS - 1 \
                else beta_leaf[1]
            (a, b, c), corr_offsets = corr_offsets[:3], corr_offsets[3:]
            A = -Field(2) * a + k
            B = a^2 + b - a * k + c
            corr1 = prg.next_vec(Field, 2)
            corr0 = vec_sub([A, B], corr1)
            if level < Poplar1.Idpf.BITS - 1:
                corr_inner[0] += corr0
                corr_inner[1] += corr1
            else:
                corr_leaf = [corr0, corr1]

        # Each input share consists of the Aggregator's IDPF key
        # and a share of the correlated randomness.
        return (public_share,
                Poplar1.encode_input_shares(
                    keys, corr_seed, corr_inner, corr_leaf))

    def is_valid(agg_param, previous_agg_params):
        """
        Checks if the level of `agg_param` appears anywhere in
        `previous_agg_params`. Returns `False` if it does, and `True` otherwise.
        """
        (level, _) = agg_param
        return all(
            level != other_level
            for (other_level, _) in previous_agg_params
        )

    @classmethod
    def prep_init(Poplar1, verify_key, agg_id, agg_param,
                  nonce, public_share, input_share):
        (level, prefixes) = agg_param
        (key, corr_seed, corr_inner, corr_leaf) = \
            Poplar1.decode_input_share(input_share)
        Field = Poplar1.Idpf.current_field(level)

        # Ensure that candidate prefixes are all unique and appear in
        # lexicographic order.
        for i in range(1,len(prefixes)):
            if prefixes[i-1] >= prefixes[i]:
                raise ERR_INPUT # out-of-order prefix

        # Evaluate the IDPF key at the given set of prefixes.
        value = Poplar1.Idpf.eval(
            agg_id, public_share, key, level, prefixes, nonce)

        # Get shares of the correlated randomness for computing the
        # Aggregator's share of the sketch for the given level of the IDPF
        # tree.
        if level < Poplar1.Idpf.BITS - 1:
            corr_prg = Poplar1.Prg(corr_seed,
                                        Poplar1.custom(DST_CORR_INNER),
                                        byte(agg_id) + nonce)
            # Fast-forward the PRG state to the current level.
            corr_prg.next_vec(Field, 3 * level)
        else:
            corr_prg = Poplar1.Prg(corr_seed,
                                        Poplar1.custom(DST_CORR_LEAF),
                                        byte(agg_id) + nonce)
        (a_share, b_share, c_share) = corr_prg.next_vec(Field, 3)
        (A_share, B_share) = corr_inner[2*level:2*(level+1)] \
            if level < Poplar1.Idpf.BITS - 1 else corr_leaf

        # Compute the Aggregator's first round of the sketch. These are
        # called the "masked input values" [BBCGGI21, Appendix C.4].
        verify_rand_prg = Poplar1.Prg(verify_key,
            Poplar1.custom(DST_VERIFY_RAND),
            nonce + to_be_bytes(level, 2))
        verify_rand = verify_rand_prg.next_vec(Field, len(prefixes))
        sketch_share = [a_share, b_share, c_share]
        out_share = []
        for (i, r) in enumerate(verify_rand):
            (data_share, auth_share) = value[i]
            sketch_share[0] += data_share * r
            sketch_share[1] += data_share * r^2
            sketch_share[2] += auth_share * r
            out_share.append(data_share)

        prep_mem = sketch_share \
                    + [A_share, B_share, Field(agg_id)] \
                    + out_share
        return (b'ready', level, prep_mem)

    @classmethod
    def prep_next(Poplar1, prep_state, opt_sketch):
        (step, level, prep_mem) = prep_state
        Field = Poplar1.Idpf.current_field(level)

        # Aggregators exchange masked input values (step (3.)
        # of [BBCGGI21, Appendix C.4]).
        if step == b'ready' and opt_sketch == None:
            sketch_share, prep_mem = prep_mem[:3], prep_mem[3:]
            return ((b'sketch round 1', level, prep_mem),
                    Field.encode_vec(sketch_share))

        # Aggregators exchange evaluated shares (step (4.)).
        elif step == b'sketch round 1' and opt_sketch != None:
            prev_sketch = Field.decode_vec(opt_sketch)
            if len(prev_sketch) == 0:
                prev_sketch = Field.zeros(3)
            elif len(prev_sketch) != 3:
                raise ERR_INPUT # prep message malformed
            (A_share, B_share, agg_id), prep_mem = \
                prep_mem[:3], prep_mem[3:]
            sketch_share = [
                agg_id * (prev_sketch[0]^2 \
                            - prev_sketch[1]
                            - prev_sketch[2]) \
                    + A_share * prev_sketch[0] \
                    + B_share
            ]
            return ((b'sketch round 2', level, prep_mem),
                    Field.encode_vec(sketch_share))

        elif step == b'sketch round 2' and opt_sketch != None:
            if len(opt_sketch) == 0:
                return prep_mem # Output shares
            else:
                raise ERR_INPUT # prep message malformed

        raise ERR_INPUT # unexpected input

    @classmethod
    def prep_shares_to_prep(Poplar1, agg_param, prep_shares):
        if len(prep_shares) != 2:
            raise ERR_INPUT # unexpected number of prep shares
        (level, _) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        sketch = vec_add(Field.decode_vec(prep_shares[0]),
                         Field.decode_vec(prep_shares[1]))
        if len(sketch) == 3:
            return Field.encode_vec(sketch)
        elif len(sketch) == 1:
            if sketch == Field.zeros(1):
                # In order to reduce communication overhead, let the
                # empty string denote a successful sketch verification.
                return b''
            else:
                raise ERR_VERIFY # sketch verification failed
        else:
            raise ERR_INPUT # unexpected input length

    @classmethod
    def out_shares_to_agg_share(Poplar1, agg_param, out_shares):
        (level, prefixes) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        agg_share = Field.zeros(len(prefixes))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return Field.encode_vec(agg_share)

    @classmethod
    def agg_shares_to_result(Poplar1, agg_param,
                             agg_shares, _num_measurements):
        (level, prefixes) = agg_param
        Field = Poplar1.Idpf.current_field(level)
        agg = Field.zeros(len(prefixes))
        for agg_share in agg_shares:
            agg = vec_add(agg, Field.decode_vec(agg_share))
        return list(map(lambda x: x.as_unsigned(), agg))

    @classmethod
    def encode_input_shares(Poplar1, keys,
                            corr_seed, corr_inner, corr_leaf):
        input_shares = []
        for (key, seed, inner, leaf) in zip(keys,
                                            corr_seed,
                                            corr_inner,
                                            corr_leaf):
            encoded = Bytes()
            encoded += key
            encoded += seed
            encoded += Poplar1.Idpf.FieldInner.encode_vec(inner)
            encoded += Poplar1.Idpf.FieldLeaf.encode_vec(leaf)
            input_shares.append(encoded)
        return input_shares

    @classmethod
    def decode_input_share(Poplar1, encoded):
        l = Poplar1.Idpf.KEY_SIZE
        key, encoded = encoded[:l], encoded[l:]
        l = Poplar1.Prg.SEED_SIZE
        corr_seed, encoded = encoded[:l], encoded[l:]
        l = Poplar1.Idpf.FieldInner.ENCODED_SIZE \
            * 2 * (Poplar1.Idpf.BITS - 1)
        encoded_corr_inner, encoded = encoded[:l], encoded[l:]
        corr_inner = Poplar1.Idpf.FieldInner.decode_vec(
            encoded_corr_inner)
        l = Poplar1.Idpf.FieldLeaf.ENCODED_SIZE * 2
        encoded_corr_leaf, encoded = encoded[:l], encoded[l:]
        corr_leaf = Poplar1.Idpf.FieldLeaf.decode_vec(
            encoded_corr_leaf)
        if len(encoded) != 0:
            raise ERR_INPUT
        return (key, corr_seed, corr_inner, corr_leaf)

    @classmethod
    def encode_agg_param(Poplar1, level, prefixes):
        if level > 2^16 - 1:
            raise ERR_INPUT # level too deep
        if len(prefixes) > 2^32 - 1:
            raise ERR_INPUT # too many prefixes
        encoded = Bytes()
        encoded += to_be_bytes(level, 2)
        encoded += to_be_bytes(len(prefixes), 4)
        packed = 0
        for (i, prefix) in enumerate(prefixes):
            packed |= prefix << ((level+1) * i)
        l = floor(((level+1) * len(prefixes) + 7) / 8)
        encoded += to_be_bytes(packed, l)
        return encoded

    @classmethod
    def decode_agg_param(Poplar1, encoded):
        encoded_level, encoded = encoded[:2], encoded[2:]
        level = from_be_bytes(encoded_level)
        encoded_prefix_count, encoded = encoded[:4], encoded[4:]
        prefix_count = from_be_bytes(encoded_prefix_count)
        l = floor(((level+1) * prefix_count + 7) / 8)
        encoded_packed, encoded = encoded[:l], encoded[l:]
        packed = from_be_bytes(encoded_packed)
        prefixes = []
        m = 2^(level+1) - 1
        for i in range(prefix_count):
            prefixes.append(packed >> ((level+1) * i) & m)
        if len(encoded) != 0:
            raise ERR_INPUT
        return (level, prefixes)

    @classmethod
    def with_bits(Poplar1, bits: Unsigned):
        TheIdpf = idpf_poplar.IdpfPoplar \
                .with_value_len(2) \
                .with_bits(bits)
        ThePrg = prg.PrgSha3
        class Poplar1WithBits(Poplar1):
            Idpf = TheIdpf
            Prg = ThePrg
            VERIFY_KEY_SIZE = ThePrg.SEED_SIZE
            RAND_SIZE = 3*ThePrg.SEED_SIZE + TheIdpf.RAND_SIZE
            test_vec_name = 'Poplar1'
        return Poplar1WithBits

    @classmethod
    def test_vec_set_type_param(cls, test_vec):
        test_vec['bits'] = int(cls.Idpf.BITS)
        return 'bits'


if __name__ == '__main__':
    test_vdaf(Poplar1.with_bits(15), (15, []), [], [])
    test_vdaf(Poplar1.with_bits(2), (1, [0b11]), [], [0])
    test_vdaf(Poplar1.with_bits(2),
        (0, [0b0, 0b1]),
        [0b10, 0b00, 0b11, 0b01, 0b11],
        [2, 3],
    )
    test_vdaf(Poplar1.with_bits(2),
        (1, [0b00, 0b01]),
        [0b10, 0b00, 0b11, 0b01, 0b01],
        [1, 2],
    )
    test_vdaf(Poplar1.with_bits(16),
        (15, [0b1111000011110000]),
        [0b1111000011110000],
        [1],
    )
    test_vdaf(Poplar1.with_bits(16),
        (14, [0b111100001111000]),
        [
            0b1111000011110000,
            0b1111000011110001,
            0b0111000011110000,
            0b1111000011110010,
            0b1111000000000000,
        ],
        [2],
    )
    test_vdaf(Poplar1.with_bits(128),
        (
            127,
            [from_be_bytes(b'0123456789abcdef')],
        ),
        [
            from_be_bytes(b'0123456789abcdef'),
        ],
        [1],
    )
    test_vdaf(Poplar1.with_bits(256),
        (
            63,
            [
                from_be_bytes(b'00000000'),
                from_be_bytes(b'01234567'),
            ],
        ),
        [
            from_be_bytes(b'0123456789abcdef0123456789abcdef'),
            from_be_bytes(b'01234567890000000000000000000000'),
        ],
        [0, 2],
    )

    # Test `is_valid` returns False on repeated levels, and True otherwise.
    cls = Poplar1.with_bits(256)
    agg_params = [(0, []), (1, [0]), (1, [0, 1])]
    assert cls.is_valid(agg_params[0], [])
    assert cls.is_valid(agg_params[1], agg_params[:1])
    assert not cls.is_valid(agg_params[2], agg_params[:2])

    # Test aggregation parameter encoding.
    cls = Poplar1.with_bits(256)
    want = (0, [])
    assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
    want = (0, [0, 1])
    assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
    want = (2, [0, 1, 2, 3])
    assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
    want = (17, [0, 1, 1233, 2^18 - 1])
    assert want == cls.decode_agg_param(cls.encode_agg_param(*want))
    want = (255, [0, 1, 1233, 2^256 - 1])
    assert want == cls.decode_agg_param(cls.encode_agg_param(*want))

    # Generate test vectors.
    cls = Poplar1.with_bits(4)
    assert cls.ID == 0x00001000
    measurements = [0b1101]
    tests = [
        # (level, prefixes, expected result)
        (0, [0, 1], [0, 1]),
        (1, [0, 1, 2, 3], [0, 0, 0, 1]),
        (2, [0, 2, 4, 6], [0, 0, 0, 1]),
        (3, [1, 3, 5, 7, 9, 13, 15], [0, 0, 0, 0, 0, 1, 0]),
    ]
    for (level, prefixes, expected_result) in tests:
        agg_param = (int(level), list(map(int, prefixes)))
        test_vdaf(cls, agg_param, measurements, expected_result,
                  print_test_vec=TEST_VECTOR, test_vec_instance=level)
