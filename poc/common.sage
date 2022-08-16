# Functionalities used by other modules.

from functools import reduce
from typing import List, TypeVar
import os
import struct


# If set, then test vectors will be generated. A fixed source of randomness is
# used for `gen_rand()`.
TEST_VECTOR = False

# Document version, reved with each draft that contains breaking changes.
DRAFT = '02'
VERSION = bytes(bytearray('vdaf-{}'.format(DRAFT), 'ascii'))


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

# As defined in {{!RFC3447}}, Section 4.1.
#
# TODO This was copy-pasted from the hash-to-curve reference implementation.
# Instead of copy-pasting it, add hash-to-curve as a git submodule and import
# it, similar to what the voprf draft does.
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError('bad I2OSP call: val=%d length=%d' % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack('=' + 'B' * length, *ret)
    assert OS2IP(ret, True) == val
    return ret


# As defined in {{!RFC3447}}, Section 4.2.
#
# TODO This was copy-pasted from the hash-to-curve reference implementation.
# Instead of copy-pasting it, add hash-to-curve as a git submodule and import
# it, similar to what the voprf draft does.
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack('=' + 'B' * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret

# Return the concatenated byte strings.
def concat(parts: Vec[Bytes]) -> Bytes:
    return reduce(lambda x, y: x + y, parts)

def print_wrapped_line(line, tab):
    width=72
    chunk_len = width - tab
    for start in range(0, len(line), chunk_len):
        end = min(start+chunk_len, len(line))
        print(' ' * tab + line[start:end])
