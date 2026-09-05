"""Tree, proof and subtree behaviour, including the padding rule."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from merkl.core.merkle import MerkleProof, MerkleTree
from merkl.shared.errors import ValidationError
from merkl.shared.hashing import SHA256Hash


def _leaf(data: str) -> SHA256Hash:
    return SHA256Hash.from_bytes(data.encode())


def _pair(a: SHA256Hash, b: SHA256Hash) -> SHA256Hash:
    return SHA256Hash.from_bytes(a.bytes + b.bytes)


class TestBuild:
    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            MerkleTree.build([])

    def test_single_leaf_root_equals_leaf(self) -> None:
        leaf = _leaf("test_action_data")
        assert MerkleTree.build([leaf]).root == leaf

    def test_two_leaves_root_is_hash_of_concatenation(self) -> None:
        a, b = _leaf("action_1"), _leaf("action_2")
        assert MerkleTree.build([a, b]).root == _pair(a, b)

    def test_four_leaves_power_of_two(self) -> None:
        leaves = [_leaf(f"action_{i}") for i in range(4)]
        expected = _pair(_pair(leaves[0], leaves[1]), _pair(leaves[2], leaves[3]))
        assert MerkleTree.build(leaves).root == expected

    def test_three_leaves_pad_by_repeating_last(self) -> None:
        leaves = [_leaf(f"action_{i}") for i in range(3)]
        expected = _pair(_pair(leaves[0], leaves[1]), _pair(leaves[2], leaves[2]))
        tree = MerkleTree.build(leaves)
        assert tree.root == expected
        assert tree.padded_leaves == (leaves[0], leaves[1], leaves[2], leaves[2])

    def test_seven_leaves_pad_to_eight(self) -> None:
        leaves = [_leaf(f"action_{i}") for i in range(7)]
        tree = MerkleTree.build(leaves)
        assert tree.leaf_count == 7
        assert tree.padded_leaf_count == 8
        assert tree.depth == 3
        assert tree.padded_leaves[7] == leaves[6]

    def test_root_is_deterministic(self) -> None:
        leaves = [_leaf(f"action_{i}") for i in range(7)]
        assert MerkleTree.build(leaves).root == MerkleTree.build(leaves).root

    def test_order_changes_root(self) -> None:
        a, b, c = _leaf("a"), _leaf("b"), _leaf("c")
        assert MerkleTree.build([a, b, c]).root != MerkleTree.build([b, a, c]).root


class TestProof:
    def test_every_leaf_verifies(self) -> None:
        leaves = [_leaf(f"leaf_{i}") for i in range(16)]
        tree = MerkleTree.build(leaves)
        for i, leaf in enumerate(leaves):
            assert tree.get_proof(i).verify(leaf, tree.root) is True

    def test_tampered_leaf_fails(self) -> None:
        leaves = [_leaf(f"action_{i}") for i in range(8)]
        tree = MerkleTree.build(leaves)
        assert tree.get_proof(3).verify(_leaf("tampered"), tree.root) is False

    def test_single_leaf_proof_is_empty(self) -> None:
        leaf = _leaf("only")
        tree = MerkleTree.build([leaf])
        proof = tree.get_proof(0)
        assert proof.siblings == ()
        assert proof.verify(leaf, tree.root) is True

    def test_index_out_of_range_raises(self) -> None:
        tree = MerkleTree.build([_leaf(f"x_{i}") for i in range(4)])
        with pytest.raises(IndexError):
            tree.get_proof(4)
        with pytest.raises(IndexError):
            tree.get_proof(-1)

    def test_padded_index_is_not_addressable(self) -> None:
        tree = MerkleTree.build([_leaf(f"x_{i}") for i in range(7)])
        with pytest.raises(IndexError):
            tree.get_proof(7)

    def test_wrong_root_fails(self) -> None:
        tree = MerkleTree.build([_leaf(f"x_{i}") for i in range(4)])
        assert tree.get_proof(0).verify(_leaf("x_0"), _leaf("wrong")) is False

    def test_direction_matters(self) -> None:
        a, b = _leaf("a"), _leaf("b")
        root = _pair(a, b)
        assert MerkleProof(siblings=(b,), directions=("right",)).verify(a, root) is True
        assert MerkleProof(siblings=(b,), directions=("left",)).verify(a, root) is False

    def test_proof_is_immutable(self) -> None:
        proof = MerkleProof(siblings=(), directions=())
        with pytest.raises(dataclasses.FrozenInstanceError):
            proof.siblings = ()  # type: ignore[misc]

    def test_mismatched_lengths_rejected(self) -> None:
        with pytest.raises(ValidationError, match="directions"):
            MerkleProof(siblings=(_leaf("a"),), directions=())

    def test_unknown_direction_rejected(self) -> None:
        with pytest.raises(ValidationError, match="left|right"):
            MerkleProof(siblings=(_leaf("a"),), directions=("up",))  # type: ignore[arg-type]

    def test_round_trips_through_json(self) -> None:
        tree = MerkleTree.build([_leaf(f"x_{i}") for i in range(8)])
        proof = tree.get_proof(5)
        assert MerkleProof.from_dict(proof.to_dict()) == proof
        assert proof.to_dict()["directions"] == ["left", "right", "left"]


class TestSubtree:
    def test_left_and_right_of_eight_leaf_tree(self) -> None:
        leaves = [_leaf(f"l{i}") for i in range(8)]
        tree = MerkleTree.build(leaves)
        left = _pair(_pair(leaves[0], leaves[1]), _pair(leaves[2], leaves[3]))
        right = _pair(_pair(leaves[4], leaves[5]), _pair(leaves[6], leaves[7]))
        assert tree.subtree_root(2, 0) == left
        assert tree.subtree_root(2, 1) == right
        assert tree.root == _pair(left, right)
        assert tree.subtree_root(3, 0) == tree.root
        assert tree.subtree_root(0, 4) == leaves[4]

    def test_proof_to_subtree_root(self) -> None:
        leaves = [_leaf(f"l{i}") for i in range(7)]
        tree = MerkleTree.build(leaves)
        for i, leaf in enumerate(leaves):
            half = tree.subtree_root(2, i // 4)
            assert tree.subtree_proof(i, 2).verify(leaf, half) is True
            assert tree.subtree_proof(i, 2).verify(leaf, tree.root) is False

    def test_subtree_proof_at_full_depth_equals_root_proof(self) -> None:
        tree = MerkleTree.build([_leaf(f"l{i}") for i in range(8)])
        assert tree.subtree_proof(3, tree.depth) == tree.get_proof(3)

    def test_level_zero_proof_is_empty(self) -> None:
        tree = MerkleTree.build([_leaf(f"l{i}") for i in range(4)])
        assert tree.subtree_proof(2, 0).siblings == ()

    def test_out_of_range_level_or_index_raises(self) -> None:
        tree = MerkleTree.build([_leaf(f"l{i}") for i in range(4)])
        with pytest.raises(IndexError):
            tree.subtree_root(3, 0)
        with pytest.raises(IndexError):
            tree.subtree_root(1, 2)
        with pytest.raises(IndexError):
            tree.subtree_proof(0, 9)

    def test_level_returns_every_node(self) -> None:
        tree = MerkleTree.build([_leaf(f"l{i}") for i in range(8)])
        assert len(tree.level(0)) == 8
        assert len(tree.level(1)) == 4
        assert len(tree.level(2)) == 2
        assert tree.level(3) == (tree.root,)


_leaf_lists = st.lists(st.binary(min_size=1, max_size=64), min_size=1, max_size=33)


class TestProperties:
    @given(data=_leaf_lists)
    @settings(max_examples=100)
    def test_all_leaves_verifiable(self, data: list[bytes]) -> None:
        leaves = [SHA256Hash.from_bytes(d) for d in data]
        tree = MerkleTree.build(leaves)
        for i, leaf in enumerate(leaves):
            assert tree.get_proof(i).verify(leaf, tree.root) is True

    @given(data=_leaf_lists)
    @settings(max_examples=100)
    def test_tampered_leaf_fails(self, data: list[bytes]) -> None:
        leaves = [SHA256Hash.from_bytes(d) for d in data]
        tree = MerkleTree.build(leaves)
        tampered = SHA256Hash.from_bytes(b"definitely_tampered_data_xyzzy")
        for i, leaf in enumerate(leaves):
            if tampered == leaf:
                continue
            assert tree.get_proof(i).verify(tampered, tree.root) is False

    @given(data=_leaf_lists)
    @settings(max_examples=100)
    def test_every_proof_passes_through_a_subtree_root(self, data: list[bytes]) -> None:
        leaves = [SHA256Hash.from_bytes(d) for d in data]
        tree = MerkleTree.build(leaves)
        for level in range(tree.depth + 1):
            for i, leaf in enumerate(leaves):
                node = tree.subtree_root(level, i >> level)
                assert tree.subtree_proof(i, level).verify(leaf, node) is True

    @given(data=_leaf_lists)
    @settings(max_examples=50)
    def test_padding_repeats_the_last_leaf(self, data: list[bytes]) -> None:
        leaves = [SHA256Hash.from_bytes(d) for d in data]
        tree = MerkleTree.build(leaves)
        padded = tree.padded_leaves
        assert padded[: len(leaves)] == tuple(leaves)
        assert all(h == leaves[-1] for h in padded[len(leaves) :])
        assert tree.padded_leaf_count == 1 << tree.depth

    @given(data=_leaf_lists)
    @settings(max_examples=50)
    def test_root_matches_a_naive_recomputation(self, data: list[bytes]) -> None:
        leaves = [SHA256Hash.from_bytes(d) for d in data]
        level = list(MerkleTree.build(leaves).padded_leaves)
        while len(level) > 1:
            level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        assert level[0] == MerkleTree.build(leaves).root
