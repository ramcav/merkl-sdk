"""``merkl approve`` and ``merkl reject`` — sign an escalation from the terminal.

The Ed25519 half of plan D11, for approvers who are not sitting in front of the
dashboard. The key never leaves this machine, the signature is over the challenge
bytes and nothing else, and the signer verifies it against the credential the
policy holds — this command has no authority of its own.

A rejection is signed too, and for the same reason: an escalation that simply
stops being mentioned proves nothing about whether anybody looked at it.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from merkl.core.policy.approvals import ApprovalAssertion

__all__ = ["approve_command", "load_approver_key", "sign_challenge"]

_KEY_ENV = "MERKL_APPROVER_KEY"


def _default_key_path() -> Path:
    return Path(os.environ.get(_KEY_ENV) or Path.home() / ".merkl" / "approver.key")


def load_approver_key(path: Path) -> Any:
    """Read a 32-byte Ed25519 seed, in hex, from a file only you can read.

    The mode check is not paranoia: an approver key is the thing that turns "the
    policy escalated" into "a person allowed it", and a key readable by every
    process on the box makes that sentence false.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not path.is_file():
        raise FileNotFoundError(
            f"no approver key at {path} — write the 32-byte Ed25519 seed there as hex, "
            f"chmod 600, or set {_KEY_ENV}"
        )
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"{path} is readable by others; chmod 600 it first")
    seed = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    if len(seed) != 32:
        raise ValueError(f"{path} must hold 32 bytes of hex, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def sign_challenge(
    key: Any, challenge: str, approver_id: str, signed_at: str
) -> ApprovalAssertion:
    """One Ed25519 assertion over the raw challenge bytes (spec section 3.3)."""
    raw = bytes.fromhex(challenge)
    if len(raw) != 32:
        raise ValueError("a challenge is 32 bytes of hex")
    return ApprovalAssertion(
        approver_id=approver_id,
        credential_type="ed25519",
        signature=key.sign(raw).hex(),
        signed_at=signed_at,
    )


async def _call(
    action: str,
    challenge: str,
    assertion: ApprovalAssertion,
    *,
    socket_path: Path | None,
    base_url: str | None,
    bearer_token: str | None,
) -> dict[str, Any]:
    from merkl.adapters.signer_dev.client import DevSignerClient

    async with DevSignerClient(
        socket_path=socket_path, base_url=base_url, bearer_token=bearer_token
    ) as client:
        if action == "approve":
            return dict(await client.approve(challenge, [assertion]))
        return dict(await client.reject(challenge, [assertion]))


def approve_command(
    challenge: str,
    *,
    action: str = "approve",
    approver: str | None = None,
    key_path: Path | None = None,
    socket_path: Path | None = None,
    host: str | None = None,
    port: int = 8787,
    now: str | None = None,
    as_json: bool = False,
    bearer_token: str | None = None,
) -> int:
    """Sign a challenge and send it to the signer. Returns the process exit code."""
    from datetime import UTC, datetime

    from merkl.core.canonical import format_instant

    approver_id = approver or os.environ.get("MERKL_APPROVER_ID")
    if not approver_id:
        print(
            "who is approving? pass --approver <id> or set MERKL_APPROVER_ID. It must be "
            "the id the policy document names, or the signer will not count the signature.",
            file=sys.stderr,
        )
        return 2
    try:
        key = load_approver_key(key_path or _default_key_path())
        assertion = sign_challenge(
            key, challenge, approver_id, now or format_instant(datetime.now(tz=UTC))
        )
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if socket_path is None and host is None:
        socket_path = Path(
            os.environ.get("MERKL_SIGNER_SOCKET") or Path.home() / ".merkl" / "signer" / "rpc.sock"
        )
    base_url = f"http://{host}:{port}" if host else None
    bearer_token = bearer_token or os.environ.get("MERKL_RELAY_TOKEN")

    try:
        decision = asyncio.run(
            _call(
                action,
                challenge,
                assertion,
                socket_path=socket_path,
                base_url=base_url,
                bearer_token=bearer_token,
            )
        )
    except Exception as exc:  # noqa: BLE001 - every signer failure is one message here
        print(f"the signer refused or could not be reached: {exc}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps(decision, indent=2))
    else:
        outcome = decision.get("outcome", "?")
        print(f"{approver_id} {action}d {challenge[:16]}…")
        print(f"  the signer's decision is now: {outcome}")
        if decision.get("detail"):
            print(f"  {decision['detail']}")
        accepted = decision.get("approvals_accepted")
        if accepted:
            print(f"  approvals counted: {', '.join(accepted)}")
        print()
        print("  The signature you just made is inside leaf 2 of the receipt. Whoever reads")
        print("  that receipt can check it against the policy without asking anyone.")
    return 0 if decision.get("outcome") in ("allow", "deny") else 1
