# Functionalities used by other modules.

from typing import List, TypeVar

import struct
import os


# Document version, reved with each new draft.
#
# NOTE The CFRG has not yet adopted this spec. Version "vdaf-00" will match
# draft-irtf-cfrg-vdaf-00.
VERSION = b"vdaf-00"


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
ERR_ABORT = Error("algorithm aborted")
ERR_DECODE = Error("decode failure")
ERR_ENCODE = Error("encode failure")
ERR_INPUT = Error("invalid input parameter")
ERR_VERIFY = Error("verification of the user's input failed")


# Return the smallest power of 2 that is larger than or equal to n.
def next_power_of_2(n):
    return 2^ceil(log(n) / log(2))


# Return the requested number of zero bytes.
def zeros(length):
    return bytes(bytearray(length))


# Return the requested number of random bytes.
def gen_rand(length):
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


# As defined in {{!RFC3447}}, Section 4.1.
#
# TODO This was copy-pasted from the hash-to-curve reference implementation.
# Instead of copy-pasting it, add hash-to-curve as a git submodule and import
# it, similar to what the voprf draft does.
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret


# As defined in {{!RFC3447}}, Section 4.2.
#
# TODO This was copy-pasted from the hash-to-curve reference implementation.
# Instead of copy-pasting it, add hash-to-curve as a git submodule and import
# it, similar to what the voprf draft does.
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret
