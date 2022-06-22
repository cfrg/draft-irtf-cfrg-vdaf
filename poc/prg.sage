# Pseudorandom number generators (PRGs).

from __future__ import annotations
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from Cryptodome.Util import Counter
from Cryptodome.Util.number import bytes_to_long
from sagelib.common import DRAFT, OS2IP, TEST_VECTOR, Bytes, Error, Unsigned, \
                           zeros, gen_rand, next_power_of_2, print_wrapped_line


# The base class for PRGs.
class Prg:
    # Size of the seed.
    SEED_SIZE: Unsigned

    # Construct a new instnace of this PRG from the given seed and info string.
    def __init__(self, seed: Bytes, info: Bytes) -> Prg:
        raise Error('not implemented')

    # Output the next `length` bytes of the PRG stream.
    def next(self, length: Unsigned) -> Bytes:
        raise Error('not implemented')

    # Output the next `length` pseudorandom elements of `Field`.
    def next_vec(self, Field, length: Unsigned):
        m = next_power_of_2(Field.MODULUS) - 1
        vec = []
        while len(vec) < length:
            x = OS2IP(self.next(Field.ENCODED_SIZE))
            x &= m
            if x < Field.MODULUS:
                vec.append(Field(x))
        return vec

    # Derive a new seed.
    @classmethod
    def derive_seed(Prg, seed: Bytes, info: Bytes) -> bytes:
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
        return prg.next_vec(Field, length)

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
    info = b'info string'
    seed = gen_rand(Prg.SEED_SIZE)

    # Test next
    expanded_data = Prg(seed, info).next(expanded_len)
    assert len(expanded_data) == expanded_len

    want = Prg(seed, info).next(700)
    got = b''
    prg = Prg(seed, info)
    for i in range(0, 700, 7):
        got += prg.next(7)
    assert got == want

    # Test derive
    derived_seed = Prg.derive_seed(seed, info)
    assert len(derived_seed) == Prg.SEED_SIZE

    # Test expand_into_vec
    expanded_vec = Prg.expand_into_vec(F, seed, info, expanded_len)
    assert len(expanded_vec) == expanded_len


if __name__ == '__main__':
    import json
    from sagelib.field import Field128

    cls = PrgAes128
    test_prg(cls, Field128, 23)

    # These constants were found in a brute-force search, and they test that
    # the PRG performs rejection sampling correctly when raw AES-CTR output
    # exceeds the prime modulus.
    from sagelib.field import Field96
    expanded_vec = PrgAes128.expand_into_vec(
        Field96,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x5f",
        b"",
        146
    )
    assert expanded_vec[-1] == Field96(39729620190871453347343769187)

    if TEST_VECTOR:
        seed = gen_rand(cls.SEED_SIZE)
        info = b'info string'
        length = 40

        test_vector = {
            'seed': seed.hex(),
            'info': info.hex(),
            'length': int(length),
            'derived_seed': None, # set below
            'expanded_vec_field128': None, # set below
        }

        test_vector['derived_seed'] = cls.derive_seed(seed, info).hex()
        test_vector['expanded_vec_field128'] = Field128.encode_vec(
                cls.expand_into_vec(Field128, seed, info, length)).hex()

        print('{}:'.format(cls.__name__))
        print('  seed: "{}"'.format(test_vector['seed']))
        print('  info: "{}"'.format(test_vector['info']))
        print('  length: {}'.format(test_vector['length']))
        print('  derived_seed: "{}"'.format(test_vector['derived_seed']))
        print('  expanded_vec_field128: >-')
        print_wrapped_line(test_vector['expanded_vec_field128'], tab=4)

        os.system('mkdir -p test_vec/{}'.format(DRAFT))
        with open('test_vec/{}/{}.json'.format(DRAFT, cls.__name__), 'w') as f:
            json.dump(test_vector, f, indent=4, sort_keys=True)
            f.write('\n')

