"""Extendable output functions (XOFs)."""

from __future__ import annotations

from Cryptodome.Cipher import AES
from Cryptodome.Hash import TurboSHAKE128

from common import (TEST_VECTOR, TEST_VECTOR_PATH, Bytes, Unsigned, concat,
                    format_dst, from_le_bytes, gen_rand, next_power_of_2,
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


class XofTurboShake128(Xof):
    """XOF based on SHA-3 (SHAKE128)."""

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters.
    test_vec_name = 'XofTurboShake128'

    def __init__(self, seed, dst, binder):
        '''
        self.l = 0
        self.m = to_le_bytes(len(dst), 1) + dst + seed + binder
        '''
        self.length_consumed = 0
        self.h = TurboSHAKE128.new(domain=1)
        self.h.update(to_le_bytes(len(dst), 1))
        self.h.update(dst)
        self.h.update(seed)
        self.h.update(binder)

    def next(self, length):
        '''
        self.l += length

        # Function `TurboSHAKE128(M, D, L)` is as defined in
        # Section 2.2 of [TurboSHAKE].
        #
        # Implementation note: Rather than re-generate the output
        # stream each time `next()` is invoked, most implementations
        # of TurboSHAKE128 will expose an "absorb-then-squeeze" API that
        # allows stateful handling of the stream.
        stream = TurboSHAKE128(self.m, 1, self.l)
        return stream[-length:]
        '''
        return self.h.read(length)


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

        # Use TurboSHAKE128 to derive a key from the binder string and
        # domain separation tag. Note that the AES key does not need
        # to be kept secret from any party. However, when used with
        # IdpfPoplar, we require the binder to be a random nonce.
        #
        # Implementation note: This step can be cached across XOF
        # evaluations with many different seeds.
        h = TurboSHAKE128.new(domain=2)
        h.update(to_le_bytes(len(dst), 1))
        h.update(dst)
        h.update(binder)
        fixed_key = h.read(16)
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
    expanded_vec = XofTurboShake128.expand_into_vec(
        Field64,
        bytes([0xd1, 0x95, 0xec, 0x90, 0xc1, 0xbc, 0xf1, 0xf2, 0xcb, 0x2c,
               0x7e, 0x74, 0xc5, 0xc5, 0xf6, 0xda]),
        b'',  # domain separation tag
        b'',  # binder
        140,
    )
    assert expanded_vec[-1] == Field64(9734340616212735019)

    for cls in (XofTurboShake128, XofFixedKeyAes128):
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

            os.system('mkdir -p {}'.format(TEST_VECTOR_PATH))
            with open('{}/{}.json'.format(
                    TEST_VECTOR_PATH, cls.__name__), 'w') as f:
                json.dump(test_vector, f, indent=4, sort_keys=True)
                f.write('\n')
