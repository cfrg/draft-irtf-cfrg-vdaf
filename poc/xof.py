"""Extendable output functions (XOFs)."""

from __future__ import annotations

from Cryptodome.Cipher import AES
from Cryptodome.Hash import TurboSHAKE128

from common import concat, from_le_bytes, next_power_of_2, to_le_bytes, xor
from field import Field


class Xof:
    """The base class for XOFs."""

    # Size of the seed.
    SEED_SIZE: int

    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        """
        Construct a new instance of this XOF from the given seed, domain
        separation tag, and binder string.

        Pre-conditions:

            - `len(seed) == self.SEED_SIZE`
        """
        raise NotImplementedError()

    def next(self, length: int) -> bytes:
        """
        Output the next `length` bytes of the XOF stream.

        Pre-conditions:

            - `length > 0`
        """
        raise NotImplementedError()

    @classmethod
    def derive_seed(Xof,
                    seed: bytes,
                    dst: bytes,
                    binder: bytes):
        """
        Derive a new seed.

        Pre-conditions:

            - `len(seed) == Xof.SEED_SIZE`
        """
        xof = Xof(seed, dst, binder)
        return xof.next(Xof.SEED_SIZE)

    def next_vec(self, field: type[Field], length: int):
        """
        Output the next `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `length > 0`
        """
        m = next_power_of_2(field.MODULUS) - 1
        vec: list[Field] = []
        while len(vec) < length:
            x = from_le_bytes(self.next(field.ENCODED_SIZE))
            x &= m
            if x < field.MODULUS:
                vec.append(field(x))
        return vec

    @classmethod
    def expand_into_vec(Xof,
                        field: type,
                        seed: bytes,
                        dst: bytes,
                        binder: bytes,
                        length: int):
        """
        Expand the input `seed` into vector of `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `len(seed) == Xof.SEED_SIZE`
            - `length > 0`
        """
        xof = Xof(seed, dst, binder)
        return xof.next_vec(field, length)


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

    def next(self, length):
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
