# Functionalities used by other modules.

from functools import reduce
from typing import List, TypeVar
import os
import struct


# If set, then test vectors will be generated. A fixed source of randomness is
# used for `gen_rand()`.
TEST_VECTOR = False

# Document version, reved with each draft that contains breaking changes.
VERSION = 4

# Primitive types
Bool = bool
Bytes = bytes
Unsigned = int
Vec = List


# Base class for errors.
class Error(BaseException):
    def __init__(self, msg):
        self.msg = msg


# Errors
ERR_ABORT = Error('algorithm aborted')
ERR_DECODE = Error('decode failure')
ERR_ENCODE = Error('encode failure')
ERR_INPUT = Error('invalid input parameter')
ERR_VERIFY = Error('verification of the user\'s input failed')


# Return the smallest power of 2 that is larger than or equal to n.
def next_power_of_2(n):
    assert n > 0
    return 2^((n-1).nbits())


# Return the requested number of zero bytes.
def zeros(length):
    return bytes(bytearray(length))


# Return the requested number of random bytes.
def gen_rand(length):
    if TEST_VECTOR:
        return bytes([0x01] * length)
    return os.urandom(length)


# Return the encoding of the input as a byte.
def byte(number) -> bytes:
    return int(number).to_bytes(1, 'big')


# Return the bitwise XOR of the inputs.
def xor(left, right):
    return bytes(map(lambda x: x[0].__xor__(x[1]), zip(left, right)))


# Subtract the right operand from the left and return the result.
def vec_sub(left, right):
    return list(map(lambda x: x[0] - x[1], zip(left, right)))


# Add the right operand to the left and return the result.
def vec_add(left, right):
    return list(map(lambda x: x[0] + x[1], zip(left, right)))

# Negate the input vector.
def vec_neg(vec):
    return list(map(lambda x: -x, vec))

# Convert unsigned integer `val` in range `[0, 2^(8*length))` to a little-endian
# byte string.
def to_le_bytes(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError('bad to_le_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='little')

# Parse an unsigned integer from a little-endian byte string.
def from_le_bytes(encoded):
    return int.from_bytes(encoded, byteorder='little')

# Convert unsigned integer `val` in range `[0, 2^(8*length))` to a big-endian
# byte string.
def to_be_bytes(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError('bad to_be_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='big')

# Parse an unsigned integer from a big-endian byte string.
def from_be_bytes(encoded):
    return int.from_bytes(encoded, byteorder='big')


# Return the concatenated byte strings.
def concat(parts: Vec[Bytes]) -> Bytes:
    return reduce(lambda x, y: x + y, parts)

# Format PRG context for use with a (V)DAF.
def format_custom(algo_class: Unsigned,
                  algo: Unsigned,
                  usage: Unsigned) -> Bytes:
    return to_be_bytes(VERSION, 1) + \
           to_be_bytes(algo_class, 1) + \
           to_be_bytes(algo, 4) + \
           to_be_bytes(usage, 2)

def print_wrapped_line(line, tab):
    width=72
    chunk_len = width - tab
    for start in range(0, len(line), chunk_len):
        end = min(start+chunk_len, len(line))
        print(' ' * tab + line[start:end])
