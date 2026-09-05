# Merkl receipt format — v1

This is the normative description of every byte Merkl hashes into a co-signer
receipt. A verifier implementing this document can check any Merkl receipt with no
access to Merkl's code or servers.

It extends `merkl-api/docs/SPEC.md` (the v1 proof format) and changes nothing in
it. Sections 1, 2, 3 and 6 of that document — canonical content hashing, the
`merkl-leaf-v1` action leaf, the session tree, the log tree — apply unchanged and
are referenced here rather than restated.

All hashes are SHA-256. Text is UTF-8. `NUL` is the single byte `0x00`. Hex is
lowercase unless a field says otherwise. Every structure carries a domain tag, so
a digest from one structure can never be read as a digest from another and a
future v2 changes the tag rather than the meaning of an existing one.

Reference implementation: `merkl.core` (Python), in this repository.
Test vectors: `merkl/core/vectors/*.json`.

## 1. Canonicalization (inherited, v1)

```
canonical_bytes(v) = json.dumps(v, sort_keys=True, default=str, separators=(",", ":")).encode()
content_hash(v)    = SHA-256(canonical_bytes(v))
```

Sorted keys, no whitespace, non-ASCII escaped as `\uXXXX`. This is the same
function the SDK, the Claude Code hook and the server already use
(`merkl.shared.hashing.canonical_bytes`); receipts introduce no second
canonicalization. JCS is a possible v2 tag, not this one.

### 1.1 The content subset receipts may use

`canonical_bytes` accepts anything and falls back to `str()` for types JSON does
not cover. Receipt content does not rely on that fallback. A receipt leaf content
is restricted to:

* objects with string keys, arrays, strings, booleans, integers, and `null`;
* **no floating-point numbers anywhere**, at any depth. Money is a decimal string
  (`"250.00"`), never a JSON number. `0.1 + 0.2` is a bug in a payments system;
* integers within ±(2^53 − 1), so a JavaScript verifier reads every number
  exactly;
* no other types. `Decimal`, `datetime`, `bytes` and enums are converted to
  strings by the producer, never by the serializer.

A producer that cannot satisfy this rejects the receipt rather than emitting it
(`merkl.core.canonical.ensure_canonical_content`). A verifier that meets a
fractional number in a receipt fails the leaf; it does not round it.

### 1.2 Field formats

| Format | Rule |
|--------|------|
| digest | 64 lowercase hex characters |
| token | non-empty, no whitespace and no control characters (accounts, ids, keys, blobs) |
| text | free-form human text, no control characters |
| instant | RFC 3339 UTC ending in `Z`: `2026-01-02T03:04:05Z`, optionally `.ffffff` |
| decimal | `0` or `[1-9][0-9]*`, optional `.` and 1-30 digits; no sign (unless the field says signed), no exponent, no leading zeros |

Optional members are **omitted** from the canonical object when absent. They are
never serialized as `null`. The single exception is a whole leaf content, which
is the literal `null` when the leaf is absent (section 3).

## 2. Receipt leaf (`merkl-receipt-leaf-v1`)

```
leaf = SHA-256(
  "merkl-receipt-leaf-v1" || NUL || leaf_name || NUL || canonical_bytes(content)
)
```

`leaf_name` is one of the seven names in section 3, UTF-8, no length prefix — the
`NUL` separators are what make the encoding unambiguous. Binding the name into
the hash is what stops two leaves being exchanged without changing the tree.

Absent content is the literal JSON `null`, i.e. `canonical_bytes(None)` is the
four bytes `null`. A receipt with no attestation therefore commits to *having no
attestation*: the absence is a proven fact, not a gap.

## 3. The seven leaves

Order is part of the format. Index 0 is hashed first and no leaf ever moves.

| # | leaf_name | content |
|---|-----------|---------|
| 0 | `instruction` | `source` (`human_input` \| `mandate` \| `system`), `content_hash` (digest), `signature`?, `ref`? |
| 1 | `intent` | see section 3.1 |
| 2 | `policy_decision` | `policy_hash` (digest), `rules[]` of `{name, outcome, detail}`, `outcome` (`allow` \| `deny` \| `escalate`), `tier`, `escalation`? |
| 3 | `signer_attestation` | `{format, document, policy_public_key}` or `null` |
| 4 | `settlement` | `rail`, `tx_hash`, `ledger_index` (integer), `close_time` (instant), `signed_tx_blob`?, `observed_anchor`?, `settlement_proof_ref`? |
| 5 | `result` | `outcome` (`settled` \| `denied` \| `failed` \| `expired`), `engine_result`?, `balance_deltas[]`, `outcome_hash`?, `detail` |
| 6 | `reasoning` | `testimony: true`, `content_hash` (digest), `source`?, `note` |

Leaves 0, 1 and 2 are present in every receipt, including a denied one. Any leaf
may be `null`; a denied payment has `null` at 3 and 4 because there was no
enclave signature to record and nothing was submitted.

`escalation` is `{challenge (digest), expires_at (instant), quorum (integer ≥ 1),
approvals[]}`. `challenge` is `LEFT_pre` — LEFT computed before the decision leaf
was final — which is what approvers sign. Each entry of `approvals` is a
canonical JSON object; its shape (WebAuthn envelope or Ed25519 assertion) is
pinned in a later phase, and until then it is committed verbatim and checked only
for being canonical content.

`balance_deltas` entries are `{account, currency, value}` where `value` is a
*signed* decimal string and `currency` follows section 3.1.

Leaf 6 is **testimony**, and says so in its own content. The receipt proves what
was asked, what the policy decided and what settled. It does not prove that the
model's account of itself is true; it proves only that the account was fixed
before the outcome was known.

### 3.1 Intent v1

```json
{"type": "payment",
 "rail": "xrpl",
 "treasury": "rTREASURY...",
 "destination": "rSUPPLIER...",
 "amount": {"value": "250.00", "currency": {"code": "RLUSD", "issuer": "rISSUER..."}},
 "reference": {"kind": "invoice", "id": "INV-2026-0042", "hash": "<digest>"},
 "policy_version": "2026.01.0",
 "agent_public_key": "<token>",
 "nonce": "<token>",
 "expires_at": "2026-01-02T03:09:05Z"}
```

`type` is `payment`; it is the only type in v1, and other types are additive.
`amount.value` is a positive decimal string. `amount.currency` is either a native
asset code matching `[A-Z0-9]{1,20}` (`"XRP"`) or an object `{code, issuer}`.
`reference` is optional and omitted when absent. Unknown members are rejected: a
verifier must not accept an intent it does not fully understand.

## 4. Tree

The seven leaf hashes are padded to eight **by repeating the last leaf**, exactly
as a session tree pads (SPEC.md section 3). Interior nodes are
`SHA-256(left || right)` over raw 32-byte digests.

```
leaf_hashes[7] = leaf_hashes[6]                       the only padding the format allows

LEFT  = H( H(leaf0 || leaf1) || H(leaf2 || leaf3) )   leaves 0-3
RIGHT = H( H(leaf4 || leaf5) || H(leaf6 || leaf7) )   leaves 4-7
ROOT  = H( LEFT || RIGHT )
```

**LEFT is the authorization commitment.** It exists before anything settles, it
is what the policy key signs, and it is the value carried in the rail's anchor
field (on XRPL, memo `MemoType=merkl/receipt-v1`, `MemoData=LEFT` in hex). RIGHT
is appended after settlement. A receipt is therefore built in two moves, and the
second cannot change the first.

Inclusion proofs are the sibling digest and its direction (`left`/`right`) at each
level, folded from the leaf upwards, as in SPEC.md section 3. A proof to LEFT or
RIGHT is the same fold stopped at level 2; that is how a reader checks a leaf
against the authorization commitment alone, without the settlement half.

## 5. Envelope

```json
{"receipt_id": "01936b2e-2222-7000-8000-000000000001",
 "version": "merkl-receipt-v1",
 "root": "<hex>",
 "left": "<hex>",
 "leaf_hashes": ["<hex>", … 8 entries],
 "rail": "xrpl",
 "treasury": "rTREASURY...",
 "agent_id": "agent-accounts-payable",
 "policy_hash": "<digest>",
 "signer_public_key": "<token>",
 "session_locator": {"session_id": "...", "leaf_index": 7}}
```

`session_locator` is optional and omitted when absent. `rail` and `treasury`
repeat the intent leaf, and `policy_hash` repeats the decision leaf; a verifier
checks the repetition rather than trusting it.

```
envelope_hash = SHA-256(canonical_bytes(envelope))
```

This digest is committed as the `input_hash` of one action (`action_type =
transaction`) in the enclosing session, which is how a receipt inherits log
inclusion, the checkpoint signature and Bitcoin anchoring without a second chain.
Because it has to equal `content_hash(envelope)` from SPEC.md section 1, the
envelope hash carries **no separate domain prefix**: its tag is the `version`
member inside the object.

Receipt ids are UUIDv7.

## 6. Selective disclosure

A disclosure reveals some leaves and withholds the rest behind their hashes.

```json
{"receipt_id": "...",
 "version": "merkl-receipt-v1",
 "root": "<hex>",
 "left": "<hex>",
 "leaf_hashes": ["<hex>", … 8 entries],
 "leaves": [{"index": 1,
             "name": "intent",
             "content": { … },
             "proof": {"siblings": ["<hex>", …], "directions": ["right", "left", "right"]}}]}
```

All eight leaf hashes travel with it, so a reader can recompute LEFT, RIGHT and
ROOT and see the whole commitment while learning nothing about the withheld
content. `index` and `name` must agree with the table in section 3.

The root a disclosure is checked against is an **input** to verification — taken
from the envelope, the session log, or wherever the reader pinned it. A
disclosure never gets to assert its own root.

## 7. Verification

Checks run in this order and are reported individually. Each has a stable name,
which is what the test vectors record. A verifier reports two lines: `ok` (nothing
was contradicted) and `complete` (every check actually ran). Never a single
verdict that hides which half was checked.

| # | Check | Status in this phase |
|---|-------|---------------------|
| 1 | `receipt.version` — the version tag is one this verifier knows | implemented |
| 2 | `leaves.count` — seven leaf contents | implemented |
| 3 | `leaves.required_present` — leaves 0-2 are not null | implemented |
| 4 | `leaf.<name>` (×7) — content rehashes to the committed leaf hash | implemented |
| 5 | `leaves.padding` — `leaf_hashes[7] == leaf_hashes[6]` | implemented |
| 6 | `commitment.left` — leaves 0-3 fold to the committed LEFT | implemented |
| 7 | `policy.signature` — the policy key signed the tx blob (XRPL) or LEFT | phase 2 |
| 8 | `signer.attestation` — the attestation document and its PCR allowlist | phase 3 |
| 9 | `intent.matches_settled_fields` — destination, amount and currency agree | phase 2 |
| 10 | `settlement.anchor_equals_left` — the rail memo equals LEFT | phase 2 |
| 11 | `settlement.signed_blob` — the tx hash re-derives from the signed blob | phase 2 |
| 12 | `settlement.ledger_inclusion` — inclusion proof against pinned validators | phase 2 |
| 13 | `commitment.right` — leaves 4-6 (plus padding) fold to RIGHT | implemented |
| 14 | `commitment.root` — `ROOT == H(LEFT \|\| RIGHT)` | implemented |
| 15 | `envelope.rail` / `envelope.treasury` — match the intent leaf | implemented |
| 16 | `envelope.policy_hash` — matches the decision leaf | implemented |
| 17 | `session.log_join` — the envelope hash is committed in the log (level 2) | phase 4 |

A deferred check is reported as `not_implemented`. That is not a pass. When a
later phase implements one, the check keeps its name and the vectors move it from
`not_implemented` to `pass`.

A disclosure is verified with the same names plus `disclosure.root` (the
disclosure's root equals the one the reader pinned) and `proof.<name>` (the
disclosed proof folds to that root).

Two failure modes deserve naming, because both are silent otherwise:

* if a leaf's content cannot be hashed at all (a fractional number, a missing
  leaf), the half it belongs to **fails** rather than passing unchecked;
* a receipt whose leaf hashes are internally consistent but whose LEFT was never
  signed proves nothing about authorization. That is check 7, and it is not in
  this phase.

## 8. Action leaf (`merkl-leaf-v1`, frozen)

Unchanged from SPEC.md section 2, byte for byte. `merkl.core.leaf.action_leaf`
computes it from plain fields rather than from a server-side record, and is pinned
against merkl-api's own implementation by
`tests/core/test_action_leaf_identity.py`, whose fixture is generated by that
implementation.

Two encodings inside it are worth restating, because they are the ones a
non-Python verifier gets wrong: `drift_score` is Python's `str()` of the float
(`0.0` renders `"0.0"`, `1e-05` renders `"1e-05"`), and `timestamp` is the exact
ISO 8601 string that was transmitted. Both must be taken verbatim from the record,
never re-rendered from a number or a date object. The test vectors carry the exact
strings for that reason.

## 9. Test vectors

`merkl/core/vectors/` — plain JSON, lowercase hex, no floats, loadable by any
implementation.

| File | Contents |
|------|----------|
| `merkle.json` | trees of 1-16 leaves: levels, roots, every inclusion proof, every subtree proof |
| `action_leaf.json` | `merkl-leaf-v1` leaves including unicode, empty fields, unsorted `depends_on`, exponent drift scores |
| `receipt_leaf.json` | `merkl-receipt-leaf-v1` leaves including a null leaf per name, unicode, key-order pairs, scalars |
| `receipts.json` | three complete receipts (allow, deny, escalated-then-approved) with leaf hashes, halves, root, envelope hash, proofs, disclosure and the full verification result |
| `tampered.json` | receipts and disclosures that must fail, each with the exact set of check names a conforming verifier reports |
| `manifest.json` | index, spec version, generator seed |

Regenerate with `python -m merkl.core.vectors.generate`; `--check` fails if the
committed files are stale. The generator refuses to emit a tamper case whose
declared failures disagree with what the verifier reports, so the fixtures cannot
drift into agreeing with a bug.

## Compatibility

`merkl-receipt-leaf-v1` and `merkl-receipt-v1` are frozen once released, on the
same terms as `merkl-leaf-v1`, `merkl-binding-v1` and `merkl-entry-v1`: any change
to a structure's fields or encoding requires a new tag, and a verifier rejects
tags it does not know. Adding an intent `type`, a rule outcome, or an optional
member of an existing content object is additive and keeps the tag; changing the
order of the seven leaves, the padding rule, or the canonicalization does not.
