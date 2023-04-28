"""Pseudorandom number generators (PRGs)."""

from __future__ import annotations
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC, cSHAKE128
from Cryptodome.Util import Counter
from Cryptodome.Util.number import bytes_to_long
from common import TEST_VECTOR, VERSION, Bytes, Error, Unsigned, \
                   format_custom, zeros, from_le_bytes, gen_rand, \
                   next_power_of_2, print_wrapped_line, to_be_bytes, \
                   to_le_bytes, xor, concat

class Prg:
    """The base class for PRGs."""

    # Size of the seed.
    SEED_SIZE: Unsigned

    def __init__(self, seed: Bytes[Prg.SEED_SIZE], custom: Bytes, binder: Bytes):
        """
        Construct a new instnace of this PRG from the given seed and info
        string.
        """
        raise Error('not implemented')

    def next(self, length: Unsigned) -> Bytes:
        """Output the next `length` bytes of the PRG stream."""
        raise Error('not implemented')

    @classmethod
    def derive_seed(Prg,
                    seed: Bytes[Prg.SEED_SIZE],
                    custom: Bytes,
                    binder: Bytes):
        """Derive a new seed."""
        prg = Prg(seed, custom, binder)
        return prg.next(Prg.SEED_SIZE)

    def next_vec(self, Field, length: Unsigned):
        """Output the next `length` pseudorandom elements of `Field`."""
        m = next_power_of_2(Field.MODULUS) - 1
        vec = []
        while len(vec) < length:
            x = from_le_bytes(self.next(Field.ENCODED_SIZE))
            x &= m
            if x < Field.MODULUS:
                vec.append(Field(x))
        return vec

    @classmethod
    def expand_into_vec(Prg,
                        Field,
                        seed: Bytes[Prg.SEED_SIZE],
                        custom: Bytes,
                        binder: Bytes,
                        length: Unsigned):
        """
        Expand the input `seed` into vector of `length` field elements.
        """
        prg = Prg(seed, custom, binder)
        return prg.next_vec(Field, length)

class PrgAes128(Prg):
    """WARNING `PrgAes128` has been deprecated in favor of `PrgSha3`."""

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters.
    test_vec_name = 'PrgAes128'

    def __init__(self, seed, custom, binder):
        self.length_consumed = 0

        # Use CMAC as a pseuodorandom function to derive a key.
        hasher = CMAC.new(seed, ciphermod=AES)
        hasher.update(to_be_bytes(len(custom), 2))
        hasher.update(custom)
        hasher.update(binder)
        self.key = hasher.digest()

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

class PrgSha3(Prg):
    """PRG based on SHA-3 (cSHAKE128)."""

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters.
    test_vec_name = 'PrgSha3'

    def __init__(self, seed, custom, binder):
        # `custom` is used as the customization string; `seed || binder` is
        # used as the main input string.
        self.shake = cSHAKE128.new(custom=custom)
        self.shake.update(seed)
        self.shake.update(binder)

    def next(self, length: Unsigned) -> Bytes:
        return self.shake.read(length)

class PrgFixedKeyAes128(Prg):
    """
    PRG based on a circular collision-resistant hash function from
    fixed-key AES.
    """

    # Associated parameters
    SEED_SIZE = 16

    # Operational parameters
    test_vec_name = 'PrgFixedKeyAes128'

    def __init__(self, seed, custom, binder):
        self.length_consumed = 0

        # Use SHA-3 to derive a key from the binder and customization
        # strings. Note that the AES key does not need to be kept
        # secret from any party. However, when used with IdpfPoplar,
        # we require the binder to be a random nonce.
        #
        # Implementation note: This step can be cached across PRG
        # evaluations with many different seeds.
        shake = cSHAKE128.new(custom=custom)
        shake.update(binder)
        fixed_key = shake.read(16)
        self.cipher = AES.new(fixed_key, AES.MODE_ECB)
        # Save seed to be used in `next`.
        self.seed = seed

    def next(self, length: Unsigned) -> Bytes:
        offset = self.length_consumed % 16
        new_length = self.length_consumed + length
        block_range = range(
            int(self.length_consumed / 16),
            int(new_length / 16) + 1)
        self.length_consumed = new_length

        hashed_blocks = [
            self.hash_block(xor(self.seed, to_le_bytes(i, 16))) \
                         for i in block_range
        ]
        return concat(hashed_blocks)[offset:offset+length]

    def hash_block(self, block):
        """
        The multi-instance tweakable circular correlation-robust hash
        function of [GKWWY20] (Section 4.2). The tweak here is the key
        that stays constant for all PRG evaluations of the same Client,
        but differs between Clients.

        Function `AES128(key, block)` is the AES-128 blockcipher.
        """
        lo, hi = block[:8], block[8:]
        sigma_block = concat([hi, xor(hi, lo)])
        return xor(self.cipher.encrypt(sigma_block), sigma_block)



##
# TESTS
#

def test_prg(Prg, F, expanded_len):
    custom = format_custom(7, 1337, 2)
    binder = b'a string that binds some protocol artifact to the output'
    seed = gen_rand(Prg.SEED_SIZE)

    # Test next
    expanded_data = Prg(seed, custom, binder).next(expanded_len)
    assert len(expanded_data) == expanded_len

    want = Prg(seed, custom, binder).next(700)
    got = b''
    prg = Prg(seed, custom, binder)
    for i in range(0, 700, 7):
        got += prg.next(7)
    assert got == want

    # Test derive
    derived_seed = Prg.derive_seed(seed, custom, binder)
    assert len(derived_seed) == Prg.SEED_SIZE

    # Test expand_into_vec
    expanded_vec = Prg.expand_into_vec(F, seed, custom, binder, expanded_len)
    assert len(expanded_vec) == expanded_len


if __name__ == '__main__':
    import json
    from sagelib.field import Field128, Field64, Field96

    # This test case was found through brute-force search using this tool:
    # https://github.com/divergentdave/vdaf-rejection-sampling-search
    expanded_vec = PrgSha3.expand_into_vec(
        Field64,
        b'\x23\x1c\x40\x0d\xcb\xaf\xce\x34\x5e\xfd\x3c\xa7\x79\x65\xee\x06',
        b'', # custom
        b'', # binder
        5,
    )
    assert expanded_vec[-1] == Field64(13681157193520586550)

    for cls in (PrgAes128, PrgSha3, PrgFixedKeyAes128):
        test_prg(cls, Field128, 23)

        if TEST_VECTOR:
            seed = gen_rand(cls.SEED_SIZE)
            custom = b'custom string'
            binder = b'binder string'
            length = 40

            test_vector = {
                'seed': seed.hex(),
                'custom': custom.hex(),
                'binder': binder.hex(),
                'length': int(length),
                'derived_seed': None, # set below
                'expanded_vec_field128': None, # set below
            }

            test_vector['derived_seed'] = cls.derive_seed(seed, custom, binder).hex()
            test_vector['expanded_vec_field128'] = Field128.encode_vec(
                    cls.expand_into_vec(Field128, seed, custom, binder, length)).hex()

            print('{}:'.format(cls.test_vec_name))
            print('  seed: "{}"'.format(test_vector['seed']))
            print('  custom: "{}"'.format(test_vector['custom']))
            print('  binder: "{}"'.format(test_vector['binder']))
            print('  length: {}'.format(test_vector['length']))
            print('  derived_seed: "{}"'.format(test_vector['derived_seed']))
            print('  expanded_vec_field128: >-')
            print_wrapped_line(test_vector['expanded_vec_field128'], tab=4)

            os.system('mkdir -p test_vec/{:02}'.format(VERSION))
            with open('test_vec/{:02}/{}.json'.format(VERSION, cls.__name__), 'w') as f:
                json.dump(test_vector, f, indent=4, sort_keys=True)
                f.write('\n')
