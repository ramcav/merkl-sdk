"""Merkle tree and inclusion proofs — the one implementation for all of Merkl.

Moved here from ``merkl_api.merkle.{tree,proof}`` with byte-identical semantics:

* leaves are padded to the next power of two by **repeating the last leaf**;
* an interior node is ``SHA-256(left || right)`` over the raw 32-byte digests;
* a proof is the sibling digest plus its direction at each level, folded
  from the leaf upwards.

Added for receipts (plan D5): subtree roots and leaf-to-subtree proofs, so the
LEFT (leaves 0-3) and RIGHT (leaves 4-7) halves of an eight-leaf tree are
addressable on their own.

Pure: no I/O, no clock, no dependency beyond ``merkl.shared``.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Literal, TypeAlias, cast

from merkl.shared.errors import ValidationError
from merkl.shared.hashing import SHA256Hash

Direction: TypeAlias = Literal["left", "right"]
DIRECTIONS: tuple[Direction, ...] = ("left", "right")


def _hash_pair(left: SHA256Hash, right: SHA256Hash) -> SHA256Hash:
    """The interior-node rule: ``SHA-256(left || right)`` over raw digests."""
    return SHA256Hash.from_bytes(left.bytes + right.bytes)


@dataclasses.dataclass(frozen=True)
class MerkleProof:
    """Value object representing a Merkle inclusion proof.

    Each element in ``siblings`` is a sibling hash along the path from the leaf
    towards the root; the matching element in ``directions`` says whether that
    sibling sits on the ``"left"`` or the ``"right"``. A proof with no siblings
    proves a leaf against itself (single-leaf tree, or a leaf that *is* the
    subtree root being proven against).
    """

    siblings: tuple[SHA256Hash, ...]
    directions: tuple[Direction, ...]

    def __post_init__(self) -> None:
        if len(self.siblings) != len(self.directions):
            raise ValidationError(
                f"Merkle proof has {len(self.siblings)} siblings but "
                f"{len(self.directions)} directions"
            )
        for direction in self.directions:
            if direction not in DIRECTIONS:
                raise ValidationError(
                    f"Merkle proof direction must be left|right, got {direction!r}"
                )

    def derive_root(self, leaf: SHA256Hash) -> SHA256Hash:
        """Fold the proof over ``leaf`` and return the hash it lands on."""
        current = leaf
        for sibling, direction in zip(self.siblings, self.directions, strict=True):
            if direction == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current

    def verify(self, leaf: SHA256Hash, root: SHA256Hash) -> bool:
        """True if folding ``leaf`` through this proof reproduces ``root``."""
        return self.derive_root(leaf) == root

    def to_dict(self) -> dict[str, list[str]]:
        """Plain-JSON form: hex siblings and their directions."""
        return {
            "siblings": [s.hex() for s in self.siblings],
            "directions": list(self.directions),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MerkleProof:
        """Parse the plain-JSON form produced by :meth:`to_dict`."""
        siblings = tuple(SHA256Hash(bytes.fromhex(s)) for s in data["siblings"])
        directions = tuple(cast("list[Direction]", list(data["directions"])))
        return cls(siblings=siblings, directions=directions)


class MerkleTree:
    """Binary Merkle tree built from a list of leaf hashes.

    If the number of leaves is not a power of 2, the last leaf is duplicated
    until it is.
    """

    def __init__(
        self,
        levels: list[list[SHA256Hash]],
        original_leaf_count: int,
    ) -> None:
        self._levels = levels
        self._original_leaf_count = original_leaf_count

    @property
    def root(self) -> SHA256Hash:
        """The root hash of this Merkle tree."""
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        """Number of original (non-padded) leaves."""
        return self._original_leaf_count

    @property
    def padded_leaf_count(self) -> int:
        """Number of leaves after padding to the next power of two."""
        return len(self._levels[0])

    @property
    def depth(self) -> int:
        """Number of levels above the leaves; the root sits at ``depth``."""
        return len(self._levels) - 1

    @property
    def padded_leaves(self) -> tuple[SHA256Hash, ...]:
        """Level 0: the leaves as hashed, including the repeated padding leaves."""
        return tuple(self._levels[0])

    @classmethod
    def build(cls, leaves: list[SHA256Hash]) -> MerkleTree:
        """Construct a Merkle tree from a list of leaf hashes.

        Raises ValidationError if leaves is empty.
        """
        if not leaves:
            raise ValidationError("Cannot build Merkle tree from empty leaves")

        # Pad to next power of 2 by duplicating last leaf
        padded = list(leaves)
        next_pow2 = 1
        while next_pow2 < len(padded):
            next_pow2 *= 2
        while len(padded) < next_pow2:
            padded.append(padded[-1])

        # Build tree bottom-up
        levels: list[list[SHA256Hash]] = [padded]
        current_level = padded
        while len(current_level) > 1:
            next_level: list[SHA256Hash] = []
            for i in range(0, len(current_level), 2):
                next_level.append(_hash_pair(current_level[i], current_level[i + 1]))
            levels.append(next_level)
            current_level = next_level

        return cls(levels=levels, original_leaf_count=len(leaves))

    def level(self, level: int) -> tuple[SHA256Hash, ...]:
        """Every node at ``level`` (0 = padded leaves, ``depth`` = the root)."""
        self._check_level(level)
        return tuple(self._levels[level])

    def subtree_root(self, level: int, index: int) -> SHA256Hash:
        """The root of the subtree covering ``2**level`` leaves starting at
        ``index * 2**level``.

        For an eight-leaf receipt tree, ``subtree_root(2, 0)`` is LEFT (the
        authorization commitment over leaves 0-3) and ``subtree_root(2, 1)`` is
        RIGHT (leaves 4-7). ``subtree_root(depth, 0)`` is the root.
        """
        self._check_level(level)
        nodes = self._levels[level]
        if index < 0 or index >= len(nodes):
            raise IndexError(
                f"Subtree index {index} out of range [0, {len(nodes)}) at level {level}"
            )
        return nodes[index]

    def get_proof(self, index: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at the given index.

        Raises IndexError if index is out of range.
        """
        return self.subtree_proof(index, self.depth)

    def subtree_proof(self, index: int, level: int) -> MerkleProof:
        """Proof of the leaf at ``index`` against the subtree root at ``level``.

        ``subtree_proof(i, depth)`` is the ordinary root proof;
        ``subtree_proof(1, 2)`` proves leaf 1 against LEFT of an eight-leaf tree.
        """
        if index < 0 or index >= self._original_leaf_count:
            raise IndexError(f"Leaf index {index} out of range [0, {self._original_leaf_count})")
        self._check_level(level)

        siblings: list[SHA256Hash] = []
        directions: list[Direction] = []
        idx = index

        for current in self._levels[:level]:
            if idx % 2 == 0:
                siblings.append(current[idx + 1])
                directions.append("right")
            else:
                siblings.append(current[idx - 1])
                directions.append("left")
            idx //= 2

        return MerkleProof(siblings=tuple(siblings), directions=tuple(directions))

    def _check_level(self, level: int) -> None:
        if level < 0 or level >= len(self._levels):
            raise IndexError(f"Level {level} out of range [0, {len(self._levels)})")
