"""Render the standalone verifier page.

One page, rendered the same way by ``merkl disclose`` and by merkl-api (plan D7).
The template and the JavaScript live here, in the SDK, next to the Python
verifier they have to agree with; the server calls
:func:`render_verify_html` rather than keeping a copy that can drift.

The page is a single file with no external references. It opens from a USB stick
on a laptop with no network, recomputes everything from the bundle embedded in
it, and reaches a verdict without asking Merkl anything. That is the only kind of
verifier worth shipping: one that still works when the company that wrote it is
gone.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Final

__all__ = ["TEMPLATE_PATH", "VERIFY_JS_PATH", "render_verify_html", "verify_js", "verify_template"]

_HERE: Final = pathlib.Path(__file__).parent

TEMPLATE_PATH: Final = _HERE / "verify.html"
"""The page template, with three placeholders and no other substitution."""

VERIFY_JS_PATH: Final = _HERE / "js" / "merkl-verify.js"
"""The JavaScript verifier, inlined into the page rather than fetched."""

_BUNDLE_MARKER: Final = "__BUNDLE__"
_JS_MARKER: Final = "__MERKL_VERIFY_JS__"
_TITLE_MARKER: Final = "__TITLE__"


def verify_template() -> str:
    """The raw template. Read from disk each call so a dev edit shows up."""
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def verify_js(*, as_module: bool = True) -> str:
    """The verifier, as text. ``as_module=False`` strips the ``export`` keywords.

    The page inlines it as a **classic** script rather than a module. Chrome
    treats every ``file://`` document as an opaque origin, and the one thing this
    page must never depend on is being served: an auditor opens it from a USB
    stick, offline, or the whole design is theatre. Stripping the keyword is a
    one-line transformation with no other effect — the file itself stays a real
    ES module, which is what ``@merkl/verify`` publishes and what the Node suite
    imports.
    """
    source = VERIFY_JS_PATH.read_text(encoding="utf-8")
    if as_module:
        return source
    keywords = "async function|function|class|const|let|var"
    return re.sub(rf"^export (?=({keywords})\b)", "", source, flags=re.MULTILINE)


def _title(bundle: dict[str, Any]) -> str:
    session = bundle.get("session")
    if isinstance(session, dict) and session.get("goal"):
        return str(session["goal"])
    receipts = bundle.get("receipts")
    if isinstance(receipts, list) and len(receipts) == 1:
        envelope = receipts[0].get("envelope") if isinstance(receipts[0], dict) else None
        receipt_id = (
            envelope.get("receipt_id")
            if isinstance(envelope, dict)
            else receipts[0].get("receipt_id")
            if isinstance(receipts[0], dict)
            else None
        )
        if receipt_id:
            return f"Receipt {receipt_id}"
    if isinstance(receipts, list) and receipts:
        return f"{len(receipts)} receipts"
    return "Proof verifier"


def _escape_title(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_verify_html(bundle: dict[str, Any]) -> str:
    """Embed a proof bundle in the verifier page and return the whole file.

    Accepts either shape merkl-api produces: a session bundle (v1.1 or v1.2, with
    ``session``, ``actions`` and optionally ``receipts``) or a receipt-only
    bundle (``{"version": "1.2", "receipts": [...], "session": None}``). The page
    decides what to show from what is present; there is one template because
    there is one format.

    The bundle is embedded as a JSON literal inside the page's script. ``</`` is
    escaped so a string in the data cannot close the script element — the one
    injection this page can suffer, since everything else it renders goes through
    ``textContent`` or an escaper.
    """
    payload = json.dumps(bundle, ensure_ascii=False).replace("</", "<\\/")
    html = verify_template()
    html = html.replace(_JS_MARKER, verify_js(as_module=False))
    html = html.replace(_BUNDLE_MARKER, payload)
    return html.replace(_TITLE_MARKER, _escape_title(_title(bundle)))
