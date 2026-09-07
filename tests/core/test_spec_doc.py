"""The spec and the code must not drift apart.

``docs/RECEIPT-SPEC.md`` is normative, so a check name or a domain tag that
exists in one and not the other is a bug in whichever moved last.
"""

from __future__ import annotations

import pathlib

from merkl.core.leaf import ACTION_LEAF_TAG, RECEIPT_LEAF_TAG
from merkl.core.receipt import DEFERRED_CHECKS, LEAF_NAMES, RECEIPT_VERSION, verify_disclosure
from merkl.core.vectors import VECTOR_FILES
from tests.core.factories import make_receipt

SPEC = (pathlib.Path(__file__).parents[2] / "docs" / "RECEIPT-SPEC.md").read_text(encoding="utf-8")


def test_spec_exists_and_is_normative() -> None:
    assert SPEC.startswith("# Merkl receipt format — v1")
    assert "normative" in SPEC


def test_every_domain_tag_is_documented() -> None:
    for tag in (RECEIPT_LEAF_TAG.decode(), ACTION_LEAF_TAG.decode(), RECEIPT_VERSION):
        assert tag in SPEC


def test_every_leaf_name_is_documented() -> None:
    for name in LEAF_NAMES:
        assert f"`{name}`" in SPEC


def test_every_check_name_is_documented() -> None:
    receipt = make_receipt()
    names = {c.name for c in receipt.verify_structure().checks}
    names |= {c.name for c in verify_disclosure(receipt.disclose(["intent"]), receipt.root).checks}
    names |= {name for name, _ in DEFERRED_CHECKS}
    for name in names:
        generic = name
        for leaf_name in LEAF_NAMES:
            generic = generic.replace(f".{leaf_name}", ".<name>")
        assert name in SPEC or generic in SPEC, f"check {name} is not in docs/RECEIPT-SPEC.md"


def test_every_vector_file_is_documented() -> None:
    for name in (*VECTOR_FILES, "manifest.json"):
        assert f"`{name}`" in SPEC


def test_the_no_float_rule_is_stated() -> None:
    assert "no floating-point numbers anywhere" in SPEC
    assert "canonical_bytes" in SPEC


# --------------------------------------------------------------------------- #
# docs/ATTESTATION-VERIFY.md
# --------------------------------------------------------------------------- #

ATTESTATION_SPEC = (
    pathlib.Path(__file__).parents[2] / "docs" / "ATTESTATION-VERIFY.md"
).read_text(encoding="utf-8")


def test_every_attestation_check_is_documented() -> None:
    """The JS verifier in phase 4 implements from this document, not from the code."""
    from merkl.core.verify.attestation import ATTESTATION_CHECKS

    for name in ATTESTATION_CHECKS:
        assert f"`{name}`" in ATTESTATION_SPEC, f"{name} is not in docs/ATTESTATION-VERIFY.md"


def test_the_pinned_root_fingerprint_is_documented() -> None:
    """Two implementations pinning different roots is the worst kind of drift."""
    from merkl.core.verify.attestation import NITRO_ROOT_G1_SHA256, NITRO_ROOT_G1_ZIP_SHA256

    assert NITRO_ROOT_G1_SHA256 in ATTESTATION_SPEC
    assert NITRO_ROOT_G1_ZIP_SHA256 in ATTESTATION_SPEC


def test_every_committed_attestation_case_is_reachable_from_the_spec() -> None:
    import json as _json

    from merkl.core.vectors.attestation import CASES_FILE

    body = _json.loads(CASES_FILE.read_text(encoding="utf-8"))
    assert f"{len(body['cases'])}" in ATTESTATION_SPEC or "cases.json" in ATTESTATION_SPEC
    for file in ("documents.json", "cases.json", "aws-nitro-root-g1.pem"):
        assert f"`{file}`" in ATTESTATION_SPEC
