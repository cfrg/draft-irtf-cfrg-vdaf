"""Extendable output functions (XOFs)."""

from abc import ABCMeta, abstractmethod
from typing import TypeVar

from Cryptodome.Cipher import AES
from Cryptodome.Hash import TurboSHAKE128

from vdaf_poc.common import (concat, from_le_bytes, next_power_of_2,
                             to_le_bytes, xor)
from vdaf_poc.field import Field

F = TypeVar("F", bound=Field)


class Xof(metaclass=ABCMeta):
    """The base class for XOFs."""

    # Size of the seed.
    SEED_SIZE: int

    # Name of the XOF, for use in test vector filenames.
    test_vec_name: str

    @abstractmethod
    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        """
        Construct a new instance of this XOF from the given seed, domain
        separation tag, and binder string.

        Pre-conditions:

            - `len(seed) == self.SEED_SIZE`
        """
        pass

    @abstractmethod
    def next(self, length: int) -> bytes:
        """
        Output the next `length` bytes of the XOF stream.

        Pre-conditions:

            - `length > 0`
        """
        pass

    # NOTE: The methods derive_seed(), next_vec(), and expand_into_vec()
    # are excerpted in the document, de-indented, as the figure
    # {{xof-derived-methods}}. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    @classmethod
    def derive_seed(cls,
                    seed: bytes,
                    dst: bytes,
                    binder: bytes) -> bytes:
        """
        Derive a new seed.

        Pre-conditions:

            - `len(seed) == Xof.SEED_SIZE`
        """
        xof = cls(seed, dst, binder)
        return xof.next(cls.SEED_SIZE)

    def next_vec(self, field: type[F], length: int) -> list[F]:
        """
        Output the next `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `length > 0`
        """
        m = next_power_of_2(field.MODULUS) - 1
        vec: list[F] = []
        while len(vec) < length:
            x = from_le_bytes(self.next(field.ENCODED_SIZE))
            x &= m
            if x < field.MODULUS:
                vec.append(field(x))
        return vec

    @classmethod
    def expand_into_vec(cls,
                        field: type[F],
                        seed: bytes,
                        dst: bytes,
                        binder: bytes,
                        length: int) -> list[F]:
        """
        Expand the input `seed` into vector of `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `len(seed) == Xof.SEED_SIZE`
            - `length > 0`
        """
        xof = cls(seed, dst, binder)
        return xof.next_vec(field, length)


# NOTE: A simplified implementation of this class is excerpted in the
# document. The contents of the docstrings of methods are used in
# lieu of their actual bodies, because they provide a simpler (though
# inefficient) implementation defined in terms of the
# `TurboSHAKE128(M, D, L)` function, and not a sponge/XOF API. The
# width of the relevant portions of the class should be limited to 69
# columns, to avoid warnings from xml2rfc.
# ===================================================================
class XofTurboShake128(Xof):
    """XOF wrapper for TurboSHAKE128."""

    # Associated parameters
    SEED_SIZE = 16

    # Name of the XOF, for use in test vector filenames.
    test_vec_name = 'XofTurboShake128'

    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        '''
        self.l = 0
        self.m = to_le_bytes(len(dst), 1) + dst + seed + binder
        '''

        if len(seed) != self.SEED_SIZE:
            raise ValueError("incorrect seed size")

        self.length_consumed = 0
        self.h = TurboSHAKE128.new(domain=1)
        self.h.update(to_le_bytes(len(dst), 1))
        self.h.update(dst)
        self.h.update(seed)
        self.h.update(binder)

    def next(self, length: int) -> bytes:
        '''
        self.l += length

        # Function `TurboSHAKE128(M, D, L)` is as defined in
        # Section 2.2 of [TurboSHAKE].
        #
        # Implementation note: Rather than re-generate the output
        # stream each time `next()` is invoked, most implementations
        # of TurboSHAKE128 will expose an "absorb-then-squeeze" API
        # that allows stateful handling of the stream.
        stream = TurboSHAKE128(self.m, 1, self.l)
        return stream[-length:]
        '''
        return self.h.read(length)


# NOTE: A simplified implementation of this class is excerpted in the
# document. The code in the docstrings of some methods is used in
# lieu of their actual bodies, because they provide a simpler
# implementation defined in terms of abstract `TurboSHAKE128(M, D,
# L)` and `AES128(key, plaintext)` functions, and not real
# cryptographic APIs. The width of the relevant portions of the class
# should be limited to 69 columns, to avoid warnings from xml2rfc.
# ===================================================================
class XofFixedKeyAes128(Xof):
    """
    XOF based on a circular collision-resistant hash function from
    fixed-key AES.
    """

    # Associated parameters
    SEED_SIZE = 16

    # Name of the XOF, for use in test vector filenames.
    test_vec_name = 'XofFixedKeyAes128'

    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        """
        if len(seed) != self.SEED_SIZE:
            raise ValueError("incorrect seed size")

        self.length_consumed = 0

        # Use TurboSHAKE128 to derive a key from the binder string
        # and domain separation tag. Note that the AES key does not
        # need to be kept secret from any party. However, when used
        # with an IDPF, we require the binder to be a random nonce.
        #
        # Implementation note: This step can be cached across XOF
        # evaluations with many different seeds.
        dst_length = to_le_bytes(len(dst), 1)
        self.fixed_key = TurboSHAKE128(
            dst_length + dst + binder,
            2,
            16,
        )
        self.seed = seed
        """
        if len(seed) != self.SEED_SIZE:
            raise ValueError("incorrect seed size")

        self.length_consumed = 0

        # Use TurboSHAKE128 to derive a key from the binder string
        # and domain separation tag. Note that the AES key does not
        # need to be kept secret from any party. However, when used
        # with an IDPF, we require the binder to be a random nonce.
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

    def next(self, length: int) -> bytes:
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

    def hash_block(self, block: bytes) -> bytes:
        """
        The multi-instance tweakable circular correlation-robust hash
        function of [GKWWY20] (Section 4.2). The tweak here is the
        key that stays constant for all XOF evaluations of the same
        Client, but differs between Clients.

        Function `AES128(key, block)` is the AES-128 blockcipher.

        ---

        lo, hi = block[:8], block[8:]
        sigma_block = concat([hi, xor(hi, lo)])
        return xor(AES128(self.fixed_key, sigma_block), sigma_block)
        """
        lo, hi = block[:8], block[8:]
        sigma_block = concat([hi, xor(hi, lo)])
        return xor(self.cipher.encrypt(sigma_block), sigma_block)
