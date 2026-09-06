"""Build ``cases.json`` from the real testnet material in ``fixtures.json``.

Three kinds of case, one per thing :mod:`merkl.core.verify.xrpl` proves:

``shamap_cases``
    The whole transaction set of a real testnet ledger, and the path from one
    of its transactions to the root. The root must equal that ledger's own
    ``transaction_hash`` — the fixture's header came from the same ``ledger``
    RPC call, so this is not a round-trip through our own encoding, it is
    agreement with rippled. A tampered-sibling variant proves the fold
    actually depends on every byte of the path.

``validation_cases``
    Two validators' real ``STValidation`` messages (captured from the
    ``validations`` stream) and the manifests in effect when they signed,
    checked against the pinned masters from ``unl.blob``. Tamper variants
    (forged signature, a different ledger hash, a master key nobody pinned)
    are byte-level mutations of the same real material, not synthetic ones.

``unl_cases``
    The testnet UNL document itself (``vl.altnet.rippletest.net``), and one
    mutation of its top-level signature that must make the whole list refuse
    to be pinned.

Run ``--check`` in CI: a stale ``cases.json`` means the fixtures and
:mod:`merkl.core.verify.xrpl` have drifted apart.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Final

from merkl.core.canonical import JSONObject, JSONValue
from merkl.core.rail import tx_id_from_blob
from merkl.core.vectors.xrpl import CASES_FILE, FIXTURES_FILE
from merkl.core.verify.xrpl import (
    CryptoError,
    build_tx_path,
    evaluate_validation,
    fold_tx_path,
    pin_validator_list,
)

SPEC: Final = "docs/RECEIPT-SPEC.md section 7.2"


def _fixtures() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURES_FILE.read_text(encoding="utf-8"))
    return data


def _tx_items(transactions: list[dict[str, str]]) -> list[tuple[bytes, bytes, bytes]]:
    items = []
    for tx in transactions:
        tx_id = bytes.fromhex(tx_id_from_blob("xrpl", tx["tx_blob"]) or "")
        items.append((tx_id, bytes.fromhex(tx["tx_blob"]), bytes.fromhex(tx["meta"])))
    return items


def _shamap_cases(fixtures: dict[str, Any]) -> list[JSONObject]:
    ledger = fixtures["ledger"]
    header = ledger["header"]
    items = _tx_items(ledger["transactions"])
    target = items[0]
    root_hex, path = build_tx_path(target[0], items)
    assert root_hex.lower() == header["transaction_hash"].lower(), (
        "the built SHAMap root does not match the real ledger header — "
        "the fixture or the builder has drifted"
    )
    folded = fold_tx_path(target[0].hex(), target[1].hex(), target[2].hex(), path)
    assert folded == root_hex

    first_siblings = path[0]["siblings"]
    assert path and isinstance(first_siblings, list) and first_siblings, (
        "need a path with at least one sibling to tamper with"
    )
    tampered_path = [dict(step) for step in path]
    siblings: list[JSONValue] = list(first_siblings)
    siblings[0] = "ee" * 32
    tampered_path[0]["siblings"] = siblings

    return [
        {
            "name": "testnet-ledger-root-and-path",
            "description": (
                f"ledger {ledger['ledger_index']} on XRPL testnet, {len(items)} transactions. "
                "The path from the first transaction folds to the header's own "
                "transaction_hash."
            ),
            "ledger_index": ledger["ledger_index"],
            "transactions": ledger["transactions"],
            "target_tx_id": target[0].hex(),
            "expect_root": header["transaction_hash"].lower(),
            "expect_path": path,
        },
        {
            "name": "testnet-ledger-tampered-sibling",
            "description": (
                "The same path with one sibling hash edited. Folding it must land "
                "somewhere other than the real transaction_hash."
            ),
            "target_tx_id": target[0].hex(),
            "target_tx_blob": target[1].hex(),
            "target_tx_meta": target[2].hex(),
            "path": tampered_path,
            "expect_root_mismatch": header["transaction_hash"].lower(),
        },
    ]


def _validation_cases(fixtures: dict[str, Any]) -> list[JSONObject]:
    unl_reading = pin_validator_list(fixtures["unl"])
    masters = list(unl_reading.masters)
    masters_json: list[JSONValue] = list(masters)
    cases: list[JSONObject] = []
    for i, entry in enumerate(fixtures["validations"]):
        good = evaluate_validation(entry, ledger_hash=entry["ledger_hash"], pinned_masters=masters)
        assert good is not None and good.outcome == "agree", (
            f"real validation entry {i} did not verify against the real testnet UNL: {good}"
        )
        cases.append(
            {
                "name": f"real-validation-{i}-agrees",
                "description": "A real testnet validation, checked against the real UNL.",
                "data": entry["data"],
                "manifest": entry["manifest"],
                "ledger_hash": entry["ledger_hash"],
                "pinned_masters": masters_json,
                "expect_outcome": "agree",
                "expect_master_key": good.master_key,
            }
        )

        forged_data = entry["data"][:-2] + ("00" if entry["data"][-2:] != "00" else "01")
        cases.append(
            {
                "name": f"real-validation-{i}-forged-signature",
                "description": (
                    "The last signature byte flipped. The manifest still resolves; "
                    "the signature does not verify."
                ),
                "data": forged_data,
                "manifest": entry["manifest"],
                "ledger_hash": entry["ledger_hash"],
                "pinned_masters": masters_json,
                "expect_outcome": "disagree",
                "expect_master_key": good.master_key,
            }
        )

        lh_offset = entry["data"].index(entry["ledger_hash"])
        wrong_ledger = entry["data"][:lh_offset] + ("00" * 32) + entry["data"][lh_offset + 64 :]
        cases.append(
            {
                "name": f"real-validation-{i}-wrong-ledger-hash",
                "description": (
                    "The embedded LedgerHash zeroed out. A validator signing a "
                    "different ledger does not count toward this one's quorum."
                ),
                "data": wrong_ledger,
                "manifest": entry["manifest"],
                "ledger_hash": entry["ledger_hash"],
                "pinned_masters": masters_json,
                "expect_outcome": "disagree",
                "expect_master_key": good.master_key,
            }
        )

    cases.append(
        {
            "name": "validator-outside-the-pinned-list",
            "description": (
                "A real, valid validation and manifest, but the pinned set names "
                "nobody who could have signed it."
            ),
            "data": fixtures["validations"][0]["data"],
            "manifest": fixtures["validations"][0]["manifest"],
            "ledger_hash": fixtures["validations"][0]["ledger_hash"],
            "pinned_masters": ["ed" + "11" * 32],
            "expect_outcome": None,
            "expect_master_key": None,
        }
    )
    cases.append(
        {
            "name": "no-manifest-captured",
            "description": (
                "The raw validation without its manifest: agreement is counted, not proved."
            ),
            "data": fixtures["validations"][0]["data"],
            "manifest": None,
            "ledger_hash": fixtures["validations"][0]["ledger_hash"],
            "pinned_masters": masters_json,
            "expect_outcome": "unchecked",
            "expect_master_key": None,
        }
    )
    return cases


def _unl_cases(fixtures: dict[str, Any]) -> list[JSONObject]:
    unl = fixtures["unl"]
    reading = pin_validator_list(unl)
    masters_json: list[JSONValue] = list(reading.masters)

    tampered = dict(unl)
    sig = bytearray(bytes.fromhex(tampered["signature"]))
    sig[0] ^= 0xFF
    tampered["signature"] = sig.hex()

    error = None
    try:
        pin_validator_list(tampered)
    except (ValueError, CryptoError) as exc:
        error = str(exc)
    assert error is not None, "a forged top-level UNL signature must be refused"

    return [
        {
            "name": "testnet-unl",
            "description": (
                "The real testnet UNL (vl.altnet.rippletest.net). Every validator's "
                "manifest verifies."
            ),
            "document": unl,
            "expect_master_count": len(reading.masters),
            "expect_skipped_count": len(reading.skipped),
            "expect_quorum": reading.quorum(),
            "masters": masters_json,
        },
        {
            "name": "testnet-unl-forged-top-level-signature",
            "description": (
                "One byte of the top-level signature flipped. The whole list is "
                "untrustworthy, not just one entry."
            ),
            "document": tampered,
            "expect_error": True,
        },
    ]


def build_cases() -> JSONObject:
    fixtures = _fixtures()
    return {
        "description": (
            "Offline ledger inclusion over real XRPL testnet material: a ledger's "
            "transaction SHAMap, two validators' STValidation messages and "
            "manifests, and the testnet UNL that pins them. A second "
            "implementation passes when it reproduces every named value from the "
            "same fixtures, not when it reaches the same boolean."
        ),
        "spec": SPEC,
        "generator": "python -m merkl.core.vectors.xrpl.generate",
        "source": fixtures["source"],
        "shamap_cases": _shamap_cases(fixtures),
        "validation_cases": _validation_cases(fixtures),
        "unl_cases": _unl_cases(fixtures),
    }


def _serialize(content: JSONObject) -> str:
    return json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(path: pathlib.Path = CASES_FILE) -> pathlib.Path:
    path.write_text(_serialize(build_cases()), encoding="utf-8")
    return path


def check(path: pathlib.Path = CASES_FILE) -> bool:
    return path.exists() and path.read_text(encoding="utf-8") == _serialize(build_cases())


def main(argv: list[str]) -> int:
    if "--check" in argv:
        if not check():
            print(f"stale: {CASES_FILE.name}", file=sys.stderr)
            print("regenerate with: python -m merkl.core.vectors.xrpl.generate", file=sys.stderr)
            return 1
        print("xrpl vectors are up to date")
        return 0
    print(f"wrote {write()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
