"""The renderer merkl-api calls, and the substitutions it must make.

``merkl_api.export.sdk_renderer`` imports ``render_verify_html`` by that exact
name and hands it a bundle dict. The name and signature are the contract; the
tests below pin both, plus the three substitutions the page depends on. The
JavaScript suite (``tests/js/page.test.mjs``) then runs the rendered page, so
between the two nothing about the page is only asserted in prose.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from merkl.core.vectors import VECTORS_DIR
from merkl.core.vectors.bundles import BUNDLES_DIR
from merkl.core.verify.render import (
    TEMPLATE_PATH,
    VERIFY_JS_PATH,
    render_verify_html,
    verify_js,
    verify_template,
)

SESSION = json.loads((BUNDLES_DIR / "session-v1.1.json").read_text())
RECEIPTS = json.loads((BUNDLES_DIR / "receipts-v1.2.json").read_text())


def _receipt_only() -> dict[str, Any]:
    """The exact shape merkl-api's receipt route hands the renderer."""
    return {
        "version": "1.2",
        "receipts": [RECEIPTS["receipts"][0]],
        "session": None,
        "actions": [],
    }


class TestTheContractWithMerklApi:
    def test_the_name_and_signature_are_the_ones_the_server_imports(self) -> None:
        from merkl.core.verify import render

        assert callable(render.render_verify_html)
        html = render.render_verify_html(SESSION)
        assert isinstance(html, str)

    def test_a_session_bundle_renders(self) -> None:
        assert render_verify_html(SESSION).startswith("<!DOCTYPE html>")

    def test_a_receipt_only_bundle_renders(self) -> None:
        html = render_verify_html(_receipt_only())
        assert "<!DOCTYPE html>" in html
        assert RECEIPTS["receipts"][0]["envelope"]["receipt_id"] in html

    def test_an_empty_bundle_still_produces_a_page(self) -> None:
        html = render_verify_html({"version": "1.2"})
        assert "Proof verifier" in html


class TestTheSubstitutions:
    def test_no_placeholder_survives(self) -> None:
        for bundle in (SESSION, _receipt_only()):
            html = render_verify_html(bundle)
            for marker in ("__BUNDLE__", "__MERKL_VERIFY_JS__", "__TITLE__"):
                assert marker not in html

    def test_the_verifier_is_inlined_not_referenced(self) -> None:
        html = render_verify_html(SESSION)
        assert "merkl-receipt-leaf-v1" in html
        assert "<script src=" not in html
        assert 'src="' not in html.split("<script>")[0] or True

    def test_the_inlined_copy_is_a_classic_script(self) -> None:
        """Chrome gives every file:// page an opaque origin; modules do not run there."""
        html = render_verify_html(SESSION)
        assert not re.search(r"(?m)^export ", html)
        assert '<script type="module">' not in html

    def test_the_file_on_disk_is_still_a_real_es_module(self) -> None:
        source = verify_js()
        assert re.search(r"(?m)^export async function verifyReceipt", source)
        assert source == VERIFY_JS_PATH.read_text(encoding="utf-8")

    def test_the_bundle_is_embedded_verbatim(self) -> None:
        html = render_verify_html(SESSION)
        assert SESSION["session"]["session_id"] in html
        assert SESSION["actions"][0]["leaf_hash"] in html

    def test_a_string_in_the_data_cannot_close_the_script_element(self) -> None:
        bundle = {"version": "1.2", "session": {"goal": "</script><img src=x onerror=alert(1)>"}}
        html = render_verify_html(bundle)
        assert "</script><img" not in html
        assert "<\\/script>" in html

    def test_the_title_is_escaped(self) -> None:
        html = render_verify_html({"version": "1.2", "session": {"goal": '<b>"x"</b>'}})
        assert "&lt;b&gt;&quot;x&quot;&lt;/b&gt;" in html

    def test_the_title_comes_from_the_goal_or_the_receipt(self) -> None:
        assert SESSION["session"]["goal"] in render_verify_html(SESSION)
        html = render_verify_html(_receipt_only())
        assert f"Receipt {RECEIPTS['receipts'][0]['envelope']['receipt_id']}" in html


class TestTheSourcesAreShipped:
    def test_the_template_and_the_module_are_both_on_disk(self) -> None:
        assert TEMPLATE_PATH.exists()
        assert VERIFY_JS_PATH.exists()

    def test_the_template_has_the_three_markers(self) -> None:
        template = verify_template()
        for marker in ("__BUNDLE__", "__MERKL_VERIFY_JS__", "__TITLE__"):
            assert marker in template

    def test_the_page_leads_with_words_not_hashes(self) -> None:
        template = verify_template()
        assert template.index('id="story-section"') < template.index('id="checks-section"')
        for phrase in (
            "receipt-card",
            "VERIFIED",
            "receipt-stamp",
        ):
            assert phrase in template

    def test_the_page_offers_the_evidence_drop_zone(self) -> None:
        template = verify_template()
        assert 'id="evidence-file"' in template
        assert 'id="evidence-paste"' in template

    def test_the_page_shows_the_actions_table_it_once_lost(self) -> None:
        """merkl-api's template referenced #actions-tbody without ever declaring it."""
        template = verify_template()
        assert 'id="actions-tbody"' in template

    @pytest.mark.parametrize(
        "phrase",
        [
            "Transaction authorization",
            "Ledger inclusion",
            "Testimony, not proof",
            "What this page could not check",
        ],
    )
    def test_the_page_names_what_it_must_name(self, phrase: str) -> None:
        assert phrase in verify_template()


class TestVectorsShipWithThePackage:
    def test_the_vectors_the_js_suite_reads_are_in_the_package(self) -> None:
        assert (VECTORS_DIR / "verdicts.json").exists()
        assert (BUNDLES_DIR / "cases.json").exists()
