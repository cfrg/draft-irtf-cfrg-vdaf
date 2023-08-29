"""Extendable output functions (XOFs)."""

from __future__ import annotations

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHAKE128

from common import (TEST_VECTOR, VERSION, Bytes, Unsigned, concat, format_dst,
                    from_le_bytes, gen_rand, next_power_of_2,
                    print_wrapped_line, to_le_bytes, xor)


class Xof:
    """The base class for XOFs."""

    # Size of the seed.
    SEED_SIZE: Unsigned

    def __init__(self, seed: Bytes["Xof.SEED_SIZE"], dst: Bytes, binder: Bytes):
        """
        Construct a new instance of this XOF from the given seed, domain
        separation tag, and binder string.
        """
        raise NotImplementedError()

    def next(self, length: Unsigned) -> Bytes:
        """Output the next `length` bytes of the XOF stream."""
        raise NotImplementedError()

    @classmethod
    def derive_seed(Xof,
                    seed: Bytes["Xof.SEED_SIZE"],
                    dst: Bytes,
                    binder: Bytes):
        """Derive a new seed."""
        xof = Xof(seed, dst, binder)
        return xof.next(Xof.SEED_SIZE)

    def next_vec(self, Field, length: Unsigned):
        """Output the next `length` elements of `Field`."""
        m = next_power_of_2(Field.MODULUS) - 1
        vec = []
        while len(vec) < length:
            x = from_le_bytes(self.next(Field.ENCODED_SIZE))
            x &= m
            if x < Field.MODULUS:
                vec.append(Field(x))
        return vec

    @classmethod
    def expand_into_vec(Xof,
                        Field,
                        seed: Bytes["Xof.SEED_SIZE"],
                        dst: Bytes,
                        binder: Bytes,
                        length: Unsigned):
        """
        Expand the input `seed` into vector of `length` field elements.
        """
        xof = Xof(seed, dst, binder)
        return xof.next_vec(Field, length)


class XofShake128(Xof):
    """XOF based on SHA-3 (SHAKE128)."""

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters.
    test_vec_name = 'XofShake128'

    def __init__(self, seed, dst, binder):
        # The input is composed of `dst`, the domain separation tag, the
        # `seed`, and the `binder` string.
        self.shake = SHAKE128.new()
        dst_length = to_le_bytes(len(dst), 1)
        self.shake.update(dst_length)
        self.shake.update(dst)
        self.shake.update(seed)
        self.shake.update(binder)

    def next(self, length: Unsigned) -> Bytes:
        return self.shake.read(length)


class XofFixedKeyAes128(Xof):
    """
    XOF based on a circular collision-resistant hash function from
    fixed-key AES.
    """

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters
    test_vec_name = 'XofFixedKeyAes128'

    def __init__(self, seed, dst, binder):
        self.length_consumed = 0

        # Use SHA-3 to derive a key from the binder string and domain
        # separation tag. Note that the AES key does not need to be
        # kept secret from any party. However, when used with
        # IdpfPoplar, we require the binder to be a random nonce.
        #
        # Implementation note: This step can be cached across XOF
        # evaluations with many different seeds.
        shake = SHAKE128.new()
        dst_length = to_le_bytes(len(dst), 1)
        shake.update(dst_length)
        shake.update(dst)
        shake.update(binder)
        fixed_key = shake.read(16)
        self.cipher = AES.new(fixed_key, AES.MODE_ECB)
        # Save seed to be used in `next`.
        self.seed = seed

    def next(self, length: Unsigned) -> Bytes:
        offset = self.length_consumed % 16
        new_length = self.length_consumed + length
        block_range = range(
            self.length_consumed // 16,
            new_length // 16 + 1
        )
        self.length_consumed = new_length

        hashed_blocks = [
            self.hash_block(xor(self.seed, to_le_bytes(i, 16)))
            for i in block_range
        ]
        return concat(hashed_blocks)[offset:offset+length]

    def hash_block(self, block):
        """
        The multi-instance tweakable circular correlation-robust hash
        function of [GKWWY20] (Section 4.2). The tweak here is the key
        that stays constant for all XOF evaluations of the same Client,
        but differs between Clients.

        Function `AES128(key, block)` is the AES-128 blockcipher.
        """
        lo, hi = block[:8], block[8:]
        sigma_block = concat([hi, xor(hi, lo)])
        return xor(self.cipher.encrypt(sigma_block), sigma_block)


##
# TESTS
#

def test_xof(Xof, F, expanded_len):
    dst = format_dst(7, 1337, 2)
    binder = b'a string that binds some protocol artifact to the output'
    seed = gen_rand(Xof.SEED_SIZE)

    # Test next
    expanded_data = Xof(seed, dst, binder).next(expanded_len)
    assert len(expanded_data) == expanded_len

    want = Xof(seed, dst, binder).next(700)
    got = b''
    xof = Xof(seed, dst, binder)
    for i in range(0, 700, 7):
        got += xof.next(7)
    assert got == want

    # Test derive
    derived_seed = Xof.derive_seed(seed, dst, binder)
    assert len(derived_seed) == Xof.SEED_SIZE

    # Test expand_into_vec
    expanded_vec = Xof.expand_into_vec(F, seed, dst, binder, expanded_len)
    assert len(expanded_vec) == expanded_len


if __name__ == '__main__':
    import json
    import os

    from field import Field64, Field128

    # This test case was found through brute-force search using this tool:
    # https://github.com/divergentdave/vdaf-rejection-sampling-search
    expanded_vec = XofShake128.expand_into_vec(
        Field64,
        b'\x23\x1c\x40\x0d\xcb\xaf\xce\x34\x5e\xfd\x3c\xa7\x79\x65\xee\x06',
        b'',  # domain separation tag
        b'',  # binder
        5,
    )
    # TODO: Update the test to account for the change from cSHAKE128 to SHAKE128.
    # assert expanded_vec[-1] == Field64(13681157193520586550)

    for cls in (XofShake128, XofFixedKeyAes128):
        test_xof(cls, Field128, 23)

        if TEST_VECTOR:
            seed = gen_rand(cls.SEED_SIZE)
            dst = b'domain separation tag'
            binder = b'binder string'
            length = 40

            test_vector = {
                'seed': seed.hex(),
                'dst': dst.hex(),
                'binder': binder.hex(),
                'length': length,
                'derived_seed': None,  # set below
                'expanded_vec_field128': None,  # set below
            }

            test_vector['derived_seed'] = cls.derive_seed(
                seed, dst, binder).hex()
            test_vector['expanded_vec_field128'] = Field128.encode_vec(
                cls.expand_into_vec(Field128, seed, dst, binder, length)).hex()

            print('{}:'.format(cls.test_vec_name))
            print('  seed: "{}"'.format(test_vector['seed']))
            print('  dst: "{}"'.format(test_vector['dst']))
            print('  binder: "{}"'.format(test_vector['binder']))
            print('  length: {}'.format(test_vector['length']))
            print('  derived_seed: "{}"'.format(test_vector['derived_seed']))
            print('  expanded_vec_field128: >-')
            print_wrapped_line(test_vector['expanded_vec_field128'], tab=4)

            os.system('mkdir -p test_vec/{:02}'.format(VERSION))
            with open('test_vec/{:02}/{}.json'.format(VERSION, cls.__name__), 'w') as f:
                json.dump(test_vector, f, indent=4, sort_keys=True)
                f.write('\n')
