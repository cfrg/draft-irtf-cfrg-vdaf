"""Functionalities used by other modules."""

import os
from typing import Protocol, Self, TypeVar, overload

# Document version, reved with each draft that contains breaking changes.
VERSION = 12


class FieldProtocol(Protocol):
    def __add__(self, other: Self) -> Self:
        ...

    def __sub__(self, other: Self) -> Self:
        ...

    def __neg__(self) -> Self:
        ...


# We use a protocol instead of the Field class itself to avoid circular import
# issues.
F = TypeVar("F", bound=FieldProtocol)


def next_power_of_2(n: int) -> int:
    """Return the smallest power of 2 that is larger than or equal to n."""
    assert n > 0
    return 1 << (int(n - 1).bit_length())


def zeros(length: int) -> bytes:
    """Return the requested number of zero bytes."""
    return bytes(bytearray(length))


def gen_rand(length: int) -> bytes:
    """Return the requested number of random bytes."""
    return os.urandom(length)


def byte(number: int) -> bytes:
    """Return the encoding of the input as a byte."""
    return int(number).to_bytes(1, 'big')


def xor(left: bytes, right: bytes) -> bytes:
    """Return the bitwise XOR of the inputs."""
    return bytes(map(lambda x: x[0] ^ x[1], zip(left, right)))


# NOTE: The vec_sub(), vec_add(), and vec_neg() functions are
# excerpted in the document, as the figure
# {{field-helper-functions}}. Their width should be limited to 69
# columns to avoid warnings from xml2rfc.
# ===================================================================
def vec_sub(left: list[F], right: list[F]) -> list[F]:
    """
    Subtract the right operand from the left and return the result.
    """
    if len(left) != len(right):
        raise ValueError("mismatched vector sizes")
    return list(map(lambda x: x[0] - x[1], zip(left, right)))


def vec_add(left: list[F], right: list[F]) -> list[F]:
    """Add the right operand to the left and return the result."""
    if len(left) != len(right):
        raise ValueError("mismatched vector sizes")
    return list(map(lambda x: x[0] + x[1], zip(left, right)))


def vec_neg(vec: list[F]) -> list[F]:
    """Negate the input vector."""
    return list(map(lambda x: -x, vec))


def to_le_bytes(val: int, length: int) -> bytes:
    """
    Convert unsigned integer `val` in the range `[0, 2 ** (8 * length))` to a
    little-endian byte string.
    """
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError(
            'bad to_le_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='little')


def from_le_bytes(encoded: bytes) -> int:
    """Parse an unsigned integer from a little-endian byte string."""
    return int.from_bytes(encoded, byteorder='little')


def to_be_bytes(val: int, length: int) -> bytes:
    """
    Convert unsigned integer `val` in the range `[0, 2 ** (8 * length))` to a
    big-endian byte string.
    """
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError(
            'bad to_be_bytes call: val=%d length=%d' % (val, length))
    return val.to_bytes(length, byteorder='big')


def from_be_bytes(encoded: bytes) -> int:
    """Parse an unsigned integer from a big-endian byte string."""
    return int.from_bytes(encoded, byteorder='big')


def concat(parts: list[bytes]) -> bytes:
    """Return the concatenated byte strings."""
    return b''.join(parts)


T = TypeVar("T")


@overload
def front(length: int, vec: bytes) -> tuple[bytes, bytes]:
    ...


@overload
def front(length: int, vec: list[T]) -> tuple[list[T], list[T]]:
    ...


def front(
        length: int,
        vec: bytes | list[T]) -> tuple[
            bytes | list[T],
            bytes | list[T]]:
    """
    Split list `vec` in two and return the front and remainder as a tuple. The
    length of the front is `length`.
    """
    assert length <= len(vec)
    return (vec[:length], vec[length:])


# NOTE: This function is excerpted in the document. Its width should
# be limited to 69 columns, to avoid warnings from xml2rfc.
# ===================================================================
def format_dst(algo_class: int,
               algo: int,
               usage: int) -> bytes:
    """
    Format XOF domain separation tag.

    Pre-conditions:

        - `algo_class` in the range `[0, 2**8)`
        - `algo` in the range `[0, 2**32)`
        - `usage` in the range `[0, 2**16)`
    """
    return concat([
        to_be_bytes(VERSION, 1),
        to_be_bytes(algo_class, 1),
        to_be_bytes(algo, 4),
        to_be_bytes(usage, 2),
    ])


def print_wrapped_line(line: str, tab: int) -> None:
    width = 72
    chunk_len = width - tab
    for start in range(0, len(line), chunk_len):
        print(' ' * tab + line[start:start + chunk_len])
