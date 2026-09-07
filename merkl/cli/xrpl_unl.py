"""``merkl xrpl pin-unl`` — turn a published validator list into a pinned trust set.

A settlement proof's validator quorum is only as good as the master-key set the
*verifier* pinned — never one the proof nominates itself (``docs/RECEIPT-SPEC.md``
section 7.2). This command does the audit once, offline, and writes the pinned
form both ``merkl verify --validator ...`` and the JavaScript CLI can consume
directly: fetch (or read) a document shaped like ``vl.ripple.com`` or
``vl.altnet.rippletest.net`` publishes, verify the publisher's manifest chain,
the top-level signature over the blob, and every validator's own manifest
inside it (:func:`merkl.core.verify.xrpl.pin_validator_list`), then print
exactly what got pinned and what got skipped, and why.

How to audit the result before trusting it:

* The printed ``publisher master key`` is the identity vouching for this whole
  list — compare it against the key XRPL Foundation or Ripple publish out of
  band (their docs, a signed announcement) before trusting a fetch of their
  URL. This command verifies the *cryptographic chain* from that key to the
  pinned validators; it cannot tell you the key itself is the right one.
* Every skipped entry is printed with why — a validator whose manifest failed
  to verify is excluded, not silently dropped.
* The output file's ``validators`` map is the pinned master-key set; rerun this
  command periodically (a UNL changes membership over time) and re-audit
  before replacing a pinned file already in use.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from merkl.core.crypto import CryptoError
from merkl.core.verify.xrpl import PinnedUNLReading, pin_validator_list


def _load_document(source: str) -> dict[str, Any]:
    path = Path(source)
    if path.exists():
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        return dict(data)
    import httpx

    response = httpx.get(source, timeout=15.0)
    response.raise_for_status()
    fetched: Any = response.json()
    return dict(fetched)


def pin_unl_command(
    source: str,
    *,
    out: Path | None = None,
    quorum_fraction: float = 0.8,
) -> int:
    """Audit ``source`` (a URL or a local file) and print/write the pinned form."""
    try:
        document = _load_document(source)
    except (OSError, json.JSONDecodeError, ImportError) as exc:
        print(f"cannot read {source}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - any transport failure is a usage error, not a crash
        print(f"cannot fetch {source}: {exc}", file=sys.stderr)
        return 2

    try:
        reading: PinnedUNLReading = pin_validator_list(document)
    except (ValueError, CryptoError) as exc:
        print(f"this list does not verify: {exc}", file=sys.stderr)
        return 1

    quorum = reading.quorum(quorum_fraction)
    print(f"publisher master key   {reading.publisher_key}")
    print(f"list sequence          {reading.sequence}")
    print(f"list expiration        {reading.expiration}")
    print(f"pinned validators      {len(reading.masters)}")
    print(f"quorum (>= {quorum_fraction:.0%})      {quorum}")
    if reading.skipped:
        print(f"skipped ({len(reading.skipped)}):")
        for entry in reading.skipped:
            print(f"  {entry}")
    print()
    print("pin with:")
    for master in reading.masters:
        print(f"  --validator {master}={master}")
    print(f"  --quorum {quorum}")

    pinned = {
        "rail": "xrpl",
        "publisher_key": reading.publisher_key,
        "sequence": reading.sequence,
        "validators": {m: m for m in reading.masters},
        "quorum": quorum,
    }
    if out is not None:
        out.write_text(json.dumps(pinned, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {out}")
    return 0
