"""Functionalities used by other modules."""

import os
from typing import List

# If set, then test vectors will be generated. A fixed source of randomness is
# used for `gen_rand()`.
TEST_VECTOR = False

# Document version, reved with each draft that contains breaking changes.
VERSION = 6

# Primitive types
Bool = bool
Bytes = bytes
Unsigned = int
Vec = List


class Error(Exception):
    """Base class for errors."""

    def __init__(self, msg):
        self.msg = msg


# Errors
ERR_ABORT = Error('algorithm aborted')
ERR_DECODE = Error('decode failure')
ERR_ENCODE = Error('encode failure')
ERR_INPUT = Error('invalid input parameter')
ERR_VERIFY = Error('verification of the user\'s input failed')


def next_power_of_2(n):
    """Return the smallest power of 2 that is larger than or equal to n."""
    assert n > 0
    return 2 ** (int(n - 1).bit_length())


def zeros(length):
    """Return the requested number of zero bytes."""
    return bytes(bytearray(length))


def gen_rand(length):
    """Return the requested number of random bytes."""
    if TEST_VECTOR:
        out = []
        for i in range(length):
            out.append(i % 256)
        return bytes(out)
    return os.urandom(length)


def byte(number) -> bytes:
    """Return the encoding of the input as a byte."""
    return int(number).to_bytes(1, 'big')


def xor(left, right):
    """Return the bitwise XOR of the inputs."""
    return bytes(map(lambda x: x[0] ^ x[1], zip(left, right)))


def vec_sub(left, right):
    """
    Subtract the right operand from the left and return the result.
    """
    return list(map(lambda x: x[0] - x[1], zip(left, right)))


def vec_add(left, right):
    """Add the right operand to the left and return the result."""
    return list(map(lambda x: x[0] + x[1], zip(left, right)))


def vec_neg(vec):
    """Negate the input vector."""
    return list(map(lambda x: -x, vec))


def to_le_bytes(val, length):
    """
    Convert unsigned integer `val` in range `[0, 2^(8*length))` to a
    little-endian byte string.
    """
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError(
            'bad to_le_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='little')


def from_le_bytes(encoded):
    """Parse an unsigned integer from a little-endian byte string."""
    return int.from_bytes(encoded, byteorder='little')


def to_be_bytes(val, length):
    """
    Convert unsigned integer `val` in range `[0, 2^(8*length))` to a big-endian
    byte string.
    """
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError(
            'bad to_be_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='big')


def from_be_bytes(encoded):
    """Parse an unsigned integer from a big-endian byte string."""
    return int.from_bytes(encoded, byteorder='big')


def concat(parts: Vec[Bytes]) -> Bytes:
    """Return the concatenated byte strings."""
    return b''.join(parts)


def front(length, vec):
    """
    Split list `vec` in two and return the front and remainder as a tuple. The
    length of the front is `length`.
    """
    return (vec[:length], vec[length:])


def format_dst(algo_class: Unsigned,
               algo: Unsigned,
               usage: Unsigned) -> Bytes:
    """Format PRG domain separation tag for use within a (V)DAF."""
    return concat([
        to_be_bytes(VERSION, 1),
        to_be_bytes(algo_class, 1),
        to_be_bytes(algo, 4),
        to_be_bytes(usage, 2),
    ])


def print_wrapped_line(line, tab):
    width = 72
    chunk_len = width - tab
    for start in range(0, len(line), chunk_len):
        print(' ' * tab + line[start:start + chunk_len])
