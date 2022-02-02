# Pseudorandom number generators (PRGs).

from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long
from sagelib.common import OS2IP, Bytes, Error, Unsigned, zeros


# The base class for PRGs.
class Prg:
    # Size of the seed.
    SEED_SIZE: Unsigned

    # Expand the input `seed` into the number of bytes requested.
    @classmethod
    def expand(cls, seed: Bytes, info: Bytes, length: Unsigned) -> Bytes:
        raise Error("not implemented")

    # Derive a fresh seed from an existing one.
    @classmethod
    def derive(cls, seed: Bytes, info: Bytes) -> Bytes:
        return cls.expand(seed, info, cls.SEED_SIZE)

    # Expand the input `seed` into vector of `length` field elements. This
    # algorithm is based on "hash_to_field" in draft-irtf-cfrg-hash-to-curve13.
    #
    # TODO Overwrite this with whatever algorithm is chosen in
    # https://github.com/cjpatton/vdaf/issues/13.
    @classmethod
    def expand_into_vec(cls,
                        Field,
                        seed: Bytes,
                        info: Bytes,
                        length: Unsigned):
        L = Field.EXPANDED_SIZE
        len_in_Bytes = length * L
        uniform_Bytes = cls.expand(seed, info, len_in_Bytes)

        vec = []
        for i in range(0, len(uniform_Bytes), L):
            tv = uniform_Bytes[i:i+L]
            x = OS2IP(tv)
            vec.append(Field(x))
        return vec


# A pseudorandom generator based on AES128. CMAC {{!RFC4493}} is used to derive
# a key, which is used in CTR-mode for deriving the output.
#
# TODO A more conventional alternative to CMAC would be HMAC.
class PrgAes128(Prg):
    # Associated parameters
    SEED_SIZE = 16

    @classmethod
    def expand(cls, seed, info, length):
        hasher = CMAC.new(seed, ciphermod=AES)
        key = hasher.update(info).digest()
        counter = Counter.new(128, initial_value=bytes_to_long(zeros(16)))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        cipher_stream = cipher.encrypt(zeros(length))
        return cipher_stream


##
# TESTS
#

def test_prg(Prg, F, expanded_len):
    info = b"info string"
    seed = Bytes([i for i in range(Prg.SEED_SIZE)])
    expanded_data = Prg.expand(seed, info, expanded_len)
    assert len(expanded_data) == expanded_len
    derived_seed = Prg.derive(seed, info)
    assert len(derived_seed) == Prg.SEED_SIZE
    expanded_vec = Prg.expand_into_vec(F, seed, info, expanded_len)
    assert len(expanded_vec) == expanded_len


if __name__ == "__main__":
    from sagelib.field import Field128
    test_prg(PrgAes128, Field128, 23)
