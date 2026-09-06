"""``merkl policy sign`` and ``merkl policy show`` — the non-browser admin path.

The dashboard signs a policy document with a WebAuthn admin credential; this is
the equivalent for an operator who is not sitting in front of a browser. Both
produce and consume the same wire shape — a ``SignedPolicy`` whose ``signature``
is an ``ApprovalAssertion``-shaped object over the 32-byte ``policy_hash`` — so
there is one verification path for either origin (plan D16, extended).
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from merkl.core.canonical import format_instant
from merkl.core.policy.approvals import (
    ADMIN_APPROVER_ID,
    ApprovalAssertion,
    verify_policy_signature,
)
from merkl.core.policy.document import (
    CREDENTIAL_ED25519,
    PolicyDocument,
    PolicyError,
    SignedPolicy,
    asset_key,
)

__all__ = ["sign_command", "show_command"]


def _public_hex(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def sign_command(
    document_path: Path, *, key_path: Path, out: Path | None = None, now: str | None = None
) -> int:
    """Sign a bare policy document with a local Ed25519 admin key.

    Produces the same shape a WebAuthn admin's ceremony would (an
    ``ApprovalAssertion`` over ``policy_hash``), rather than the legacy raw-hex
    scheme — new tooling speaks the one wire format both admin kinds share.
    """
    from merkl.cli.approve import load_approver_key

    try:
        raw = json.loads(document_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {document_path}: {exc}", file=sys.stderr)
        return 2
    try:
        document = PolicyDocument.from_content(raw)
    except PolicyError as exc:
        print(f"{document_path} is not a valid policy document: {exc}", file=sys.stderr)
        return 2

    try:
        key = load_approver_key(key_path)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    signed_at = now or format_instant(datetime.now(tz=UTC))
    digest = bytes.fromhex(document.policy_hash())
    assertion = ApprovalAssertion(
        approver_id=ADMIN_APPROVER_ID,
        credential_type=CREDENTIAL_ED25519,
        signature=key.sign(digest).hex(),
        signed_at=signed_at,
    )
    signer_public_key = _public_hex(key)
    signed = SignedPolicy(
        document=document, signature=assertion.to_content(), signer_public_key=signer_public_key
    )

    if not verify_policy_signature(signed):
        # Not necessarily wrong: a policy_update is checked against the admin
        # the signer already has pinned, which is often a *different* key from
        # the one the new document nominates (that is how an admin rotates).
        print(
            "note: this document's own admin does not name the signing key; the result "
            "will only verify against a signer or verifier that pins this key explicitly",
            file=sys.stderr,
        )

    content = json.dumps(signed.to_content(), indent=2) + "\n"
    if out is not None:
        out.write_text(content)
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(content, end="")
    print(
        f"signed {document.treasury} policy {document.version} "
        f"({document.policy_hash()[:16]}…) with {signer_public_key[:16]}…",
        file=sys.stderr,
    )
    return 0


def show_command(path: Path, *, as_json: bool = False) -> int:
    """Render a policy document — signed or bare — in words."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2

    signed: SignedPolicy | None = None
    try:
        if isinstance(raw, dict) and "document" in raw and "signature" in raw:
            signed = SignedPolicy.from_content(raw)
            document = signed.document
        else:
            document = PolicyDocument.from_content(raw)
    except PolicyError as exc:
        print(f"{path} is not a valid policy document: {exc}", file=sys.stderr)
        return 2

    if as_json:
        content: dict[str, Any] = {
            "document": document.to_content(),
            "policy_hash": document.policy_hash(),
        }
        if signed is not None:
            content["signer_public_key"] = signed.signer_public_key
            content["signature_verifies"] = verify_policy_signature(signed)
        print(json.dumps(content, indent=2))
        return 0

    admin = document.effective_admin
    print(f"policy {document.version}  ({document.policy_hash()[:16]}…)")
    print(f"  treasury   {document.treasury}")
    print(f"  rail       {document.rail}")
    origin_note = f"  origins={list(admin.origins)}" if admin.origins else ""
    print(f"  admin      {admin.credential_type} {admin.public_key[:16]}…{origin_note}")
    if signed is not None:
        verified = verify_policy_signature(signed)
        print(
            f"  signed by  {signed.signer_public_key[:16]}… "
            f"({'verifies' if verified else 'DOES NOT VERIFY'})"
        )
    else:
        print("  signed by  (this is a bare document; not signed)")
    print()

    print(f"agents ({len(document.agents)}):")
    for agent in document.agents:
        print(f"  {agent.agent_id}  key={agent.public_key[:16]}…")
        if agent.allowlist_destinations:
            print(f"    destinations: {', '.join(agent.allowlist_destinations)}")
        if agent.allowlist_assets:
            print(f"    assets: {', '.join(asset_key(a) for a in agent.allowlist_assets)}")
        for cap in agent.per_tx_cap:
            print(f"    per-tx cap: {cap.amount} {cap.key}")
        for window in agent.windows:
            print(f"    window: {window.amount} {window.key} per {window.seconds}s")
        rb = agent.reference_binding
        if rb.required or rb.allowed_kinds or rb.allowlist or rb.hashes:
            print(f"    reference binding: required={rb.required} kinds={list(rb.allowed_kinds)}")
    print()

    human = document.tiers.human
    print(
        f"tiers: instant (below every threshold), human (quorum {human.quorum} of "
        f"{len(document.approvers)}, expires {human.expires_seconds}s)"
    )
    for threshold in human.thresholds:
        print(f"  escalates above {threshold.amount} {threshold.key}")
    print()

    print(f"approvers ({len(document.approvers)}):")
    for approver in document.approvers:
        note = f"  origins={list(approver.origins)}" if approver.origins else ""
        print(f"  {approver.id}  {approver.credential_type}{note}")
    print()
    print(f"risk threshold: {document.risk.threshold}")
    return 0
