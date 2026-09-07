"""``merkl receipt show`` — read one receipt out loud.

``merkl verify`` answers "does this hold up". This answers "what does it say",
which is the question people actually start with. It prints the seven leaves in
plain language, then the verdict, then the leaves' contents if you ask for them.

A receipt id resolves through the local receipt store first — the operator's own
copy, which needs no network and no account — and only then through a configured
notary. The order matters: your own records should not require someone else's
server to be readable.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from merkl.core.receipt import LEAF_NAMES
from merkl.core.verify.card import receipt_card, render_card
from merkl.core.verify.receipt import receipt_from_content, verify_receipt

__all__ = ["LEAF_PLAIN", "receipt_show_command", "resolve_receipt"]

LEAF_PLAIN: dict[str, str] = {
    "instruction": "Who asked for this, and the hash of what they said.",
    "intent": "The payment as the agent proposed it: rail, treasury, destination, amount.",
    "policy_decision": "Every rule the signer ran, the verdict, and any escalation.",
    "signer_attestation": "The enclave document vouching for the policy key, or its absence.",
    "settlement": "The transaction the rail validated, and the policy signature over it.",
    "result": "How the attempt ended, and what moved.",
    "reasoning": "A hash of the model trace. Testimony, not proof.",
}
"""One sentence per leaf, the same seven the page prints."""


def _store_dir(explicit: Path | None) -> Path:
    return explicit or Path(
        os.environ.get("MERKL_RECEIPT_DIR") or Path.home() / ".merkl" / "receipts"
    )


def resolve_receipt(
    ref: str, *, store: Path | None = None, endpoint: str | None = None, api_key: str | None = None
) -> dict[str, Any]:
    """Find a receipt by file path, by id in the local store, or from a notary.

    Raises ``FileNotFoundError`` when none of the three has it, naming all three
    places it looked — a "not found" that does not say where it looked is a
    support ticket waiting to happen.
    """
    path = Path(ref)
    if path.is_file():
        return dict(json.loads(path.read_text(encoding="utf-8")))
    directory = _store_dir(store)
    local = directory / f"{ref}.json"
    if local.is_file():
        return dict(json.loads(local.read_text(encoding="utf-8")))
    if endpoint:
        import httpx

        response = httpx.get(
            f"{endpoint.rstrip('/')}/v1/receipts/{ref}",
            headers={"Authorization": f"Bearer {api_key or ''}"},
            timeout=30.0,
        )
        if response.is_success:
            return dict(response.json())
        raise FileNotFoundError(
            f"the notary at {endpoint} answered {response.status_code} for receipt {ref}"
        )
    raise FileNotFoundError(
        f"no receipt {ref}: not a file, not in {directory}, and no notary is configured "
        "(set MERKL_ENDPOINT or pass --endpoint)"
    )


def receipt_show_command(
    ref: str,
    *,
    store: Path | None = None,
    endpoint: str | None = None,
    api_key: str | None = None,
    show_leaves: bool = False,
    as_json: bool = False,
) -> int:
    """Print one receipt in plain language. Returns the process exit code."""
    try:
        receipt = resolve_receipt(ref, store=store, endpoint=endpoint, api_key=api_key)
        envelope, contents = receipt_from_content(receipt)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    verdict = verify_receipt(
        envelope,
        contents,
        settlement_proof=receipt.get("settlement_proof"),
        policy_document=receipt.get("policy_document"),
    )
    if as_json:
        card = receipt_card(verdict, envelope, contents)
        print(
            json.dumps(
                {"receipt": receipt, "verdict": verdict.to_content(), "card": card.to_content()},
                indent=2,
            )
        )
        return 0 if verdict.ok else 1

    print(render_card(receipt_card(verdict, envelope, contents)))
    print()
    print("  the seven leaves")
    for i, name in enumerate(LEAF_NAMES):
        content = contents[i] if i < len(contents) else None
        state = "absent, and committed as absent" if content is None else "present"
        check = verdict.result.get(f"leaf.{name}")
        mark = "ok" if check and check.status.value == "pass" else "FAIL"
        print(f"    {i}  {name:<20} {mark:<5} {state}")
        print(f"       {LEAF_PLAIN[name]}")
        if show_leaves and content is not None:
            body = json.dumps(content, indent=2, ensure_ascii=False)
            print("\n".join("         " + line for line in body.splitlines()))
    print()
    print(f"  authorization    {verdict.transaction_authorization}")
    print(f"  ledger           {verdict.ledger_inclusion}")
    print(f"  level            {verdict.level}")
    print(f"  verdict          {'nothing contradicted' if verdict.ok else 'CONTRADICTED'}")
    if not verdict.complete:
        names = ", ".join(c.name for c in verdict.result.deferred)
        print(f"  unchecked        {names}")
    print()
    print("  run `merkl verify` on the same file to see every check and what it compared.")
    return 0 if verdict.ok else 1
