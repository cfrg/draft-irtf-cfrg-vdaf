# Pseudorandom number generators (PRGs).

from __future__ import annotations
try:
    # Default: use PyCryptodome installed in its drop-in replacement mode.
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
    from Crypto.Util import Counter
    from Crypto.Util.number import bytes_to_long
except ImportError:
    # Fallback: use PyCryptodome installed independently.
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import CMAC
    from Cryptodome.Util import Counter
    from Cryptodome.Util.number import bytes_to_long
from sagelib.common import OS2IP, Bytes, Error, Unsigned, zeros, gen_rand


# The base class for PRGs.
class Prg:
    # Size of the seed.
    SEED_SIZE: Unsigned

    # Construct a new instnace of this PRG from the given seed and info string.
    def __init__(self, seed: Bytes, info: Bytes) -> Prg:
        raise Error("not implemented")

    # Output the next `length` bytes of the PRG stream.
    def next(self, length: Unsigned) -> Bytes:
        raise Error("not implemented")

    # Derive a new seed.
    @classmethod
    def derive(Prg, seed: Bytes, info: Bytes) -> bytes:
        prg = Prg(seed, info)
        return prg.next(Prg.SEED_SIZE)

    # Expand the input `seed` into vector of `length` field elements.
    @classmethod
    def expand_into_vec(Prg,
                        Field,
                        seed: Bytes,
                        info: Bytes,
                        length: Unsigned):
        prg = Prg(seed, info)
        vec = []
        while len(vec) < length:
            x = OS2IP(prg.next(Field.ENCODED_SIZE))
            if x < Field.MODULUS:
                vec.append(Field(x))
        return vec

class PrgAes128(Prg):
    # Associated parameters
    SEED_SIZE = 16

    def __init__(self, seed, info):
        self.length_consumed = 0

        # Use CMAC as a pseuodorandom function to derive a key.
        hasher = CMAC.new(seed, ciphermod=AES)
        self.key = hasher.update(info).digest()

    def next(self, length: Unsigned) -> Bytes:
        block = int(self.length_consumed / 16)
        offset = self.length_consumed % 16
        self.length_consumed += length

        # CTR-mode encryption of the all-zero string of the desired
        # length and using a fixed, all-zero IV.
        counter = Counter.new(int(128), initial_value=block)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
        stream = cipher.encrypt(zeros(offset + length))
        return stream[-length:]

##
# TESTS
#

def test_prg(Prg, F, expanded_len):
    info = b"info string"
    seed = gen_rand(Prg.SEED_SIZE)

    # Test next
    expanded_data = Prg(seed, info).next(expanded_len)
    assert len(expanded_data) == expanded_len

    want = Prg(seed, info).next(700)
    got = b""
    prg = Prg(seed, info)
    for i in range(0, 700, 7):
        got += prg.next(7)
    assert got == want

    # Test derive
    derived_seed = Prg.derive(seed, info)
    assert len(derived_seed) == Prg.SEED_SIZE

    # Test expand_into_vec
    expanded_vec = Prg.expand_into_vec(F, seed, info, expanded_len)
    assert len(expanded_vec) == expanded_len


if __name__ == "__main__":
    from sagelib.field import Field128
    test_prg(PrgAes128, Field128, 23)
