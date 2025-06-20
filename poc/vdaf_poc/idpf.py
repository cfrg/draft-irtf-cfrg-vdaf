"""Definition of IDPFs."""

from abc import ABCMeta, abstractmethod
from typing import Generic, Sequence, TypeAlias, TypeVar

from vdaf_poc.field import Field

FieldInner = TypeVar("FieldInner", bound=Field)
FieldLeaf = TypeVar("FieldLeaf", bound=Field)
PublicShare = TypeVar("PublicShare")

# Type alias for the output of `eval()`.
Output: TypeAlias = list[list[FieldInner]] | list[list[FieldLeaf]]
# Type alias for a vector over the inner or leaf field.
FieldVec: TypeAlias = list[FieldInner] | list[FieldLeaf]


class Idpf(Generic[FieldInner, FieldLeaf, PublicShare], metaclass=ABCMeta):
    """
    An Incremental Distributed Point Function (IDPF).

    Generic type parameters:
    FieldInner -- The finite field used to represent the inner nodes of the
        IDPF tree.
    FieldLeaf -- The finite field used to represent the leaf nodes of the IDPF
        tree.

    Attributes:
    SHARES -- Number of keys generated by the IDPF-key generation algorithm.
    BITS -- Bit length of valid input values (i.e., the length of `alpha`).
    VALUE_LEN -- The length of each output vector (i.e., the length of
        `beta_leaf` and each element of `beta_inner`).
    KEY_SIZE -- Size in bytes of each IDPF key share.
    RAND_SIZE -- Number of random bytes consumed by the `gen()` algorithm.
    field_inner -- Class object for the field used in inner nodes.
    field_leaf -- Class object for the field used in leaf nodes.
    """

    # Number of keys generated by the IDPF-key generation algorithm.
    SHARES: int

    # Bit length of valid input values (i.e., the length of `alpha`).
    BITS: int

    # The length of each output vector (i.e., the length of `beta_leaf` and
    # each element of `beta_inner`).
    VALUE_LEN: int

    # Size in bytes of each IDPF key share.
    KEY_SIZE: int

    # Number of random bytes consumed by the `gen()` algorithm.
    RAND_SIZE: int

    # Number of random bytes in the nonce generated by the client.
    NONCE_SIZE: int

    # Class object for the field used in inner nodes.
    field_inner: type[FieldInner]

    # Class object for the field used in leaf nodes.
    field_leaf: type[FieldLeaf]

    # Name of the IDPF, for use in test vector filenames.
    test_vec_name: str

    @abstractmethod
    def gen(self,
            alpha: tuple[bool, ...],
            beta_inner: list[list[FieldInner]],
            beta_leaf: list[FieldLeaf],
            ctx: bytes,
            nonce: bytes,
            rand: bytes) -> tuple[PublicShare, list[bytes]]:
        """
        Generates an IDPF public share and sequence of IDPF-keys of length
        `SHARES`. Input `alpha` is the index to encode. Inputs `beta_inner` and
        `beta_leaf` are assigned to the values of the nodes on the non-zero
        path of the IDPF tree. It takes two inputs from the higher-level
        application, a context string `ctx`, and a nonce string `nonce`.

        `alpha` is a tuple of booleans, and not a list, because IDPF indices
        need to be immutable and hashable in order to check the uniqueness of
        candidate prefixes efficiently.

        Pre-conditions:

            - `len(alpha) == self.BITS`
            - `len(beta_inner) == self.BITS - 1`
            - `len(beta_inner[level]) == self.VALUE_LEN` for each `level` in
              `[0, self.BITS - 1)`
            - `len(beta_leaf) == self.VALUE_LEN`
            - `len(rand) == self.RAND_SIZE`
        """
        pass

    @abstractmethod
    def eval(self,
             agg_id: int,
             public_share: PublicShare,
             key: bytes,
             level: int,
             prefixes: Sequence[tuple[bool, ...]],
             ctx: bytes,
             nonce: bytes) -> Output:
        """
        Evaluate an IDPF key share public share at a given level of the tree
        and with the given sequence of prefixes. The output is a vector where
        each element is a vector of length `VALUE_LEN`. The output field is
        `FieldLeaf` if `level == BITS` and `FieldInner` otherwise. `ctx` and
        `nonce` must match the context and nonce strings passed by the Client
        to `gen`.

        Each element of `prefixes` is a bit string of length `level + 1`. For
        each element of `prefixes` that is the length-`level + 1` prefix of
        the input encoded by the IDPF-key generation algorithm
        (i.e., `alpha`), the sum of the corresponding output shares will be
        equal to one of the programmed output vectors (i.e., an element of
        `beta_inner + [beta_leaf]`). For all other elements of `prefixes`, the
        corresponding output shares will sum up to the 0-vector.

        Pre-conditions:

            - `agg_id` in the range `[0, self.SHARES)`
            - `level` in the range `[0, self.BITS)`
            - `len(prefix) == level + 1` for each `prefix` in `prefixes`
        """
        pass

    # NOTE: This method is excerpted in the document, de-indented. Its
    # width should be limited to 69 columns after de-indenting, or 73
    # columns before de-indenting, to avoid warnings from xml2rfc.
    # ===================================================================
    def current_field(
            self,
            level: int) -> type[FieldInner] | type[FieldLeaf]:
        if level < self.BITS - 1:
            return self.field_inner
        return self.field_leaf

    def is_prefix(self, x: tuple[bool, ...], y: tuple[bool, ...], level: int) -> bool:
        """
        Returns `True` iff `x` is the prefix of `y` at level `level`.

        Pre-conditions:

            - `level` in the range `[0, self.BITS)`
        """
        return x == y[:level + 1]

    @abstractmethod
    def encode_public_share(self, public_share: PublicShare) -> bytes:
        pass
