# Functionalities commonly used by other modules.


from typing import List

import struct

# Primitive types.
Vec = List
Unit = type(None)


# Base class for errors.
class Error(BaseException):
    def __init__(self, msg):
        self.msg = msg


# Errors
ErrInvalidInput = Error("invalid input")


# As defined in RFC 3447, Section 4.1.
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


# As defined in RFC 3447, Section 4.2.
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
