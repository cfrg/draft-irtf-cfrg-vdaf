# The Poplar1 VDAF.

from __future__ import annotations
from copy import deepcopy
from collections import namedtuple
from typing import Tuple, Union
from sagelib.common import ERR_INPUT, ERR_VERIFY, I2OSP, OS2IP, TEST_VECTOR, \
                           VERSION, Bytes, Error, Unsigned, Vec, byte, \
                           gen_rand, vec_add, vec_sub
from sagelib.vdaf import Vdaf, test_vdaf
import sagelib.idpf as idpf
import sagelib.idpf_poplar as idpf_poplar
import sagelib.prg as prg
from sagelib.field import Field2

class Poplar1(Vdaf):
    # Types provided by a concrete instadce of `Poplar1`.
    Idpf = idpf.Idpf

    # Parameters required by `Vdaf`.
    ID = 0x00001000
    VERIFY_KEY_SIZE = None # Set by Idpf.Prg
    SHARES = 2
    ROUNDS = 1

    # Types required by `Vdaf`.
    Measurement = Unsigned
    AggParam = Tuple[Unsigned, Vec[Unsigned]]
    Prep = Tuple[Bytes,
                 Unsigned,
                 Union[Vec[Vec[Union[Idpf.FieldInner, Field2]]]],
                       Vec[Vec[Union[Idpf.FieldLeaf, Field2]]]]
    OutShare = Union[Vec[Vec[Idpf.FieldInner]],
                     Vec[Vec[Idpf.FieldLeaf]]]
    AggResult = Vec[Unsigned]

    @classmethod
    def measurement_to_input_shares(Poplar1, measurement):
        dst = VERSION + I2OSP(Poplar1.ID, 4)
        corr_seed = gen_rand(Poplar1.Idpf.Prg.SEED_SIZE)
        prg = Poplar1.Idpf.Prg(corr_seed, dst + byte(255))

        # Construct the IDPF values for each level of the IDPF tree.
        # Each "data" value is 1; in addition, the Client generates
        # a random "authenticator" value used by the Aggregators to
        # compute the sketch during preparation. This sketch is used
        # to verify the one-hotness of their output shares.

        auth = prg.next_vec(Poplar1.Idpf.FieldInner,
                                      Poplar1.Idpf.BITS - 1)
        beta_inner = [
            [Poplar1.Idpf.FieldInner(1), k, Field2(1)]  \
                for k in auth]
        auth += prg.next_vec(Poplar1.Idpf.FieldLeaf, 1)
        beta_leaf = [Poplar1.Idpf.FieldLeaf(1), auth[-1], Field2(1)]

        # Generate the IDPF keys.
        (public_share, keys) = \
            Poplar1.Idpf.gen(measurement, beta_inner, beta_leaf)
        # Generate correlated randomness used by the Aggregators to
        # compute a sketch over their output shares. PRG seeds are
        # used to encode shares of the `(a, b, c)` triples.
        # (See [BBCGGI21, Appendix C.4].)

        # Generate the correction words
        # For each level of the IDPF tree, the correction word
        # is derived from the prefix of the measurement and the
        # IDPF output shares of both aggregators.
        corr_inner = []
        for level in range(Poplar1.Idpf.BITS):
            prefix = (measurement // (2 ** (Poplar1.Idpf.BITS - 1 - level)))
            Field = Poplar1.Idpf.current_field(level)
            k = auth[level]
            print('randomness\t:', k)
            (leader_data_share, leader_auth_share, leader_indicator_share) = \
                Poplar1.Idpf.eval(0, public_share, keys[0], level, [prefix])[0]
            helper_auth_share = leader_auth_share -k
            helper_data_share = leader_data_share - Field(1)
            w = Poplar1.hash1(level, prefix, \
                    [leader_data_share, leader_auth_share]) + \
                Poplar1.hash1(level, prefix, \
                    [helper_data_share, helper_auth_share])
            if level < Poplar1.Idpf.BITS -1:
                corr_inner.append(w)
            else:
                corr_leaf = w

        input_shares = Poplar1.encode_input_shares(keys, corr_seed)
        # Each input share consists of the Aggregator's IDPF key
        # and the leader's includes the random value k
        # The public share consists of the IDPF public share and
        # the correction words
        public_share = Poplar1.encode_public_share( \
                                                   public_share, \
                                                   corr_inner, \
                                                   corr_leaf)
        return (public_share, input_shares)

    @classmethod
    def prep_init(Poplar1, verify_key, agg_id, agg_param,
                  nonce, public_share, input_share):
        dst = VERSION + I2OSP(Poplar1.ID, 4)
        (level, prefixes) = agg_param
        (idpf_public_share, corr_inner, corr_leaf) = \
            Poplar1.decode_public_share(public_share)
        (key, corr_seed) = Poplar1.decode_input_share(input_share)

        Field = Poplar1.Idpf.current_field(level)

        # Evaluate the IDPF key at the given set of prefixes.
        value = Poplar1.Idpf.eval(agg_id,
                                  idpf_public_share,
                                  key,
                                  level,
                                  prefixes)

        #Leader expands randomness
        if agg_id == 0:
            prg = Poplar1.Idpf.Prg(corr_seed, dst + byte(255))
            auth = prg.next_vec(Poplar1.Idpf.FieldInner,
                                Poplar1.Idpf.BITS - 1)
            auth += prg.next_vec(Poplar1.Idpf.FieldLeaf, 1)

        # Prepare one-hotness and boundnedness verification
        # and output share
        # sum over all prefixes for boundedness verification
        out_share = []
        data_sum = Field(1) if agg_id == 0 else Field(0)
        auth_sum = auth[level] if agg_id == 0 else Field(0)
        print('auth_sum:\t', auth_sum)
        corr_results = []
        correction_word = corr_inner[level] if level < Poplar1.Idpf.BITS-1 \
            else corr_leaf
        for i in range(len(prefixes)):
            (data_share, auth_share, indicator_share) = value[i]
            z = Field(1) if agg_id == 0 else Field(-1)
            corrected_x = Poplar1.hash1(level,
                                        prefixes[i],
                                        [z * data_share, z * auth_share])
            result = Poplar1.correct(corrected_x,
                                     indicator_share,
                                     correction_word)
            corr_results.append(result)
            data_sum -=  z * data_share
            auth_sum -=  z * auth_share
            out_share.append(data_share)

        corr_check = Poplar1.hash3(corr_results, level)

        bound_msg = Poplar1.hash2(data_sum, auth_sum, level) + \
                    Poplar1.hash2(Field(1) + data_sum,
                                  auth[level] + auth_sum,
                                  level) if agg_id == 0 else b''
        check_bound = b'' if agg_id == 0 \
                    else Poplar1.hash2(data_sum, auth_sum, level)

        prep_state = (level,
                      agg_id,
                      out_share,
                      check_bound,
                      corr_check,
                      bound_msg)
        return (b'init', prep_state)

    @classmethod
    def prep_next(Poplar1, prep, inbound):
        (status, prep_state) = prep
        #Send verification messages (1 round only)
        if status == b'init':
            (level, agg_id, out_share, check_bound, corr_check, bound_msg) = \
                                                                    prep_state
            new_prep = (b'finish',(agg_id, check_bound, out_share))
            msg = corr_check + bound_msg
            return (new_prep, msg)
        if status == b'finish':
            (agg_id, check_bound, out_share) = prep_state
            # Helper (only) verifies boundedness
            if (agg_id == 0):
                return out_share
            elif (agg_id == 1) and (inbound == check_bound):
                return out_share
            print('inbound:\t',inbound.hex())
            print('check_bound:\t', check_bound.hex())
            raise ERR_VERIFY #Input is one-hot but the entry is not 1


    @classmethod
    def prep_shares_to_prep(Poplar1, agg_param, prep_shares):
        if len(prep_shares) != 2:
            raise ERR_INPUT # unexpected number of prep shares
        (level, prefixes) = agg_param
        Field = Poplar1.Idpf.current_field(level)

        #Verify one-hotness
        corr_check1 = prep_shares[1]
        l = Poplar1.Idpf.Prg.SEED_SIZE
        (corr_check0, bound_msg) = prep_shares[0][:l], prep_shares[0][l:]
        if corr_check0 != corr_check1:
            raise ERR_VERIFY #Input is not one-hot
        return bound_msg

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
    def encode_input_shares(Poplar1, keys, corr_seed):
        input_shares = []
        leader_encoded = Bytes([0]) + keys[0] + corr_seed
        helper_encoded = Bytes([1]) + keys[1]
        return (leader_encoded, helper_encoded)

    @classmethod
    def encode_public_share(Poplar1, public_share, corr_inner, corr_leaf):
        out = Bytes()
        out += Poplar1.Idpf.FieldInner.encode_vec(corr_inner)
        out += Poplar1.Idpf.FieldLeaf.encode_vec([corr_leaf])
        out += public_share
        return out

    @classmethod
    def decode_public_share(Poplar1, encoded):
        l = Poplar1.Idpf.FieldInner.ENCODED_SIZE \
            * (Poplar1.Idpf.BITS - 1)
        encoded_corr_inner, encoded = encoded[:l], encoded[l:]
        corr_inner = Poplar1.Idpf.FieldInner.decode_vec(
                    encoded_corr_inner)
        l = Poplar1.Idpf.FieldLeaf.ENCODED_SIZE
        encoded_corr_leaf, public_share = encoded[:l], encoded[l:]
        corr_leaf = Poplar1.Idpf.FieldLeaf.decode_vec(encoded_corr_leaf)[0]
        return (public_share, corr_inner, corr_leaf)


    @classmethod
    def decode_input_share(Poplar1, encoded):
        id, encoded = encoded[:1], encoded[1:]
        l = Poplar1.Idpf.KEY_SIZE
        key, encoded = encoded[:l], encoded[l:]
        if id == Bytes([0]):
            l = Poplar1.Idpf.Prg.SEED_SIZE
            corr_seed, encoded = encoded[:l], encoded[l:]
        else:
            corr_seed = None
        return (key, corr_seed)

    @classmethod
    def encode_agg_param(Poplar1, level, prefixes):
        if level > 2^16 - 1:
            raise ERR_INPUT # level too deep
        if len(prefixes) > 2^16 - 1:
            raise ERR_INPUT # too many prefixes
        encoded = Bytes()
        encoded += I2OSP(level, 2)
        encoded += I2OSP(len(prefixes), 2)
        packed = 0
        for (i, prefix) in enumerate(prefixes):
            packed |= prefix << ((level+1) * i)
        l = floor(((level+1) * len(prefixes) + 7) / 8)
        encoded += I2OSP(packed, l)
        # TODO Remove this assertion once agg param encoding is
        # exercised by test_vdaf().
        assert (level, prefixes) == Poplar1.decode_agg_param(encoded)
        return encoded

    @classmethod
    def decode_agg_param(Poplar1, encoded):
        encoded_level, encoded = encoded[:2], encoded[2:]
        level = OS2IP(encoded_level)
        encoded_prefix_count, encoded = encoded[:2], encoded[2:]
        prefix_count = OS2IP(encoded_prefix_count)
        l = floor(((level+1) * prefix_count + 7) / 8)
        encoded_packed, encoded = encoded[:l], encoded[l:]
        packed = OS2IP(encoded_packed)
        prefixes = []
        m = 2^(level+1) - 1
        for i in range(prefix_count):
            prefixes.append(packed >> ((level+1) * i) & m)
        if len(encoded) != 0:
            raise ERR_INPUT
        return (level, prefixes)

    @classmethod
    def verify_context(Poplar1, nonce, level, prefixes):
        if len(nonce) > 255:
            raise ERR_INPUT # nonce too long
        context = Bytes()
        context += byte(254)
        context += byte(len(nonce))
        context += nonce
        context += Poplar1.encode_agg_param(level, prefixes)
        return context

    @classmethod
    def with_idpf(cls, Idpf):
        new_cls = deepcopy(cls)
        new_cls.Idpf = Idpf
        new_cls.VERIFY_KEY_SIZE = Idpf.Prg.SEED_SIZE
        return new_cls

    @classmethod
    def test_vec_set_type_param(cls, test_vec):
        test_vec['bits'] = int(cls.Idpf.BITS)
        return 'bits'

    @classmethod
    def correct(Poplar1, corrected_x, b, correction_word):
        if b == Field2(0):
            return corrected_x
        return correction_word - corrected_x

    @classmethod
    def hash1(Poplar1, level, x, y):
        # XXX Replace this with something secure
        Field = Poplar1.Idpf.current_field(level)
        prg = Poplar1.Idpf.Prg(
            Bytes([5]*Poplar1.Idpf.Prg.SEED_SIZE),
            Bytes([1, level]) + I2OSP(x, Poplar1.Idpf.BITS) + \
                                                            Field.encode_vec(y))
        return prg.next_vec(Field, 1)[0]

    @classmethod
    def hash2(Poplar1, z, y, level):
        Field = Poplar1.Idpf.current_field(level)
        prg = Poplar1.Idpf.Prg(
            Bytes([6]*Poplar1.Idpf.Prg.SEED_SIZE), \
            byte(2)+ Field.encode_vec([z,y]))
        return prg.next(Poplar1.Idpf.Prg.SEED_SIZE)

    @classmethod
    def hash3(Poplar1, v, level):
        cntxt = Poplar1.Idpf.current_field(level).encode_vec(v)
        prg = Poplar1.Idpf.Prg(
            Bytes([7]*Poplar1.Idpf.Prg.SEED_SIZE), \
            Bytes([3])+ cntxt)
        return prg.next(Poplar1.Idpf.Prg.SEED_SIZE)


class Poplar1Aes128(Poplar1):

    @classmethod
    def with_bits(cls, bits):
        return cls.with_idpf(
            idpf_poplar.IdpfPoplar \
                .with_prg(prg.PrgAes128) \
                .with_value_len(3) \
                .with_bits(bits))



if __name__ == '__main__':
    test_vdaf(Poplar1Aes128.with_bits(15), (15, []), [], [])
    test_vdaf(Poplar1Aes128.with_bits(2), (1, [0b11]), [], [0])
    test_vdaf(Poplar1Aes128.with_bits(2),
        (0, [0b0, 0b1]),
        [0b10, 0b00, 0b11, 0b01, 0b11],
        [2, 3],
    )
    test_vdaf(Poplar1Aes128.with_bits(2),
        (1, [0b00, 0b01]),
        [0b10, 0b00, 0b11, 0b01, 0b01],
        [1, 2],
    )
    test_vdaf(Poplar1Aes128.with_bits(16),
        (15, [0b1111000011110000]),
        [0b1111000011110000],
        [1],
    )
    test_vdaf(Poplar1Aes128.with_bits(16),
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
    test_vdaf(Poplar1Aes128.with_bits(128),
        (
            127,
            [OS2IP(b'0123456789abcdef')],
        ),
        [
            OS2IP(b'0123456789abcdef'),
        ],
        [1],
    )
    test_vdaf(Poplar1Aes128.with_bits(256),
        (
            63,
            [
                OS2IP(b'01234567'),
                OS2IP(b'00000000'),
            ],
        ),
        [
            OS2IP(b'0123456789abcdef0123456789abcdef'),
            OS2IP(b'01234567890000000000000000000000'),
        ],
        [2, 0],
    )

    # Generate test vectors.
    cls = Poplar1Aes128.with_bits(4)
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
