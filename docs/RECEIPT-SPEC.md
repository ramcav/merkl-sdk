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
| 4 | `settlement` | `rail`, `tx_hash`, `ledger_index` (integer), `close_time` (instant), `signed_tx_blob`?, `observed_anchor`?, `settlement_proof_ref`?, `policy_signature`? |
| 5 | `result` | `outcome` (`settled` \| `denied` \| `failed` \| `expired`), `engine_result`?, `balance_deltas[]`, `outcome_hash`?, `detail` |
| 6 | `reasoning` | `testimony: true`, `content_hash` (digest), `source`?, `note` |

Leaves 0, 1 and 2 are present in every receipt, including a denied one. Any leaf
may be `null`; a denied payment has `null` at 3 and 4 because there was no
enclave signature to record and nothing was submitted.

`escalation` is `{challenge (digest), expires_at (instant), quorum (integer ≥ 1),
approvals[]}`. `challenge` is `LEFT_pre` (section 3.2), which is what approvers
sign; each entry of `approvals` is an assertion in the shape of section 3.3.

`balance_deltas` entries are `{account, currency, value}` where `value` is a
*signed* decimal string and `currency` follows section 3.1.

`policy_signature` is `{algorithm, public_key (token), signature (token), payload
(token)}`. `payload` is the hex of the **exact bytes the policy key signed** — on
XRPL, the multisigning pre-image of the submitted transaction — carried verbatim
so the signature can be checked offline rather than taken on trust. LEFT must
appear inside those bytes; the signer put it there (section 3.4). The signature
lives in leaf 4 and not leaf 3 because it is a signature *over* LEFT, and LEFT
covers leaves 0-3: a signature stored inside its own input could never be
computed.

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

An asset's **key** — used to match policy rules and window state to an amount — is
the native code itself, or `code.issuer` for an issued currency. A native code
cannot contain `.`, so two assets never collide.

### 3.2 `LEFT_pre`, the escalation challenge

```
LEFT_pre = LEFT over leaves 0-3, where leaf 2's content
           omits `escalation` and has `outcome` = "escalate"
```

Approvers sign these 32 raw bytes. The challenge has to leave the escalation out
because the approvals go *inside* it — a challenge that grew with each approval
could not be signed by more than one person — and it fixes `outcome` at
`escalate` because resolving an escalation is exactly what changes that member.

Those two edits are the **only** difference the format allows between the
decision as it escalated and the decision as it was recorded. The `rules` array
in particular does not change: whether the quorum was reached is derived by
counting valid approvals, never asserted as an extra rule. That is what lets a
reader holding only the finished receipt recompute `LEFT_pre` and check that the
approvers signed *this* payment.

### 3.3 Approval assertions

Each entry of `escalation.approvals[]`:

```json
{"approver_id": "alice@example.com",
 "credential_type": "webauthn",
 "signature": "<hex>",
 "client_data_json": "<hex>",
 "authenticator_data": "<hex>",
 "signed_at": "2026-01-02T03:20:11Z"}
```

`credential_type` is `webauthn` or `ed25519`. Every binary member is lowercase
hex of the exact bytes, `client_data_json` included: those bytes are what was
signed, and re-serializing the JSON inside them is how an implementation breaks a
valid assertion. The `challenge` member *inside* clientDataJSON stays base64url,
because that is what WebAuthn puts there and the browser is not ours to change.

| `credential_type` | public key | signature | message |
|---|---|---|---|
| `ed25519` | 32-byte raw key, hex | 64 bytes, hex | the 32 challenge bytes |
| `webauthn` | uncompressed SEC1 P-256 point (`0x04 ‖ X ‖ Y`), hex | ECDSA DER, hex | `authenticator_data ‖ SHA-256(client_data_json)` |

An Ed25519 assertion carries neither `client_data_json` nor
`authenticator_data`; a WebAuthn assertion carries both. A WebAuthn assertion is
accepted only when `type` is `webauthn.get`, the decoded challenge equals the
challenge, the origin is one the approver's credential allows, the first 32 bytes
of `authenticator_data` are `SHA-256(rp_id)`, the user-present flag is set, and
the user-verified flag is set if the credential requires it.

Quorum counts **distinct** `approver_id`s whose assertion verifies against the
credential the policy holds for that id. Five assertions from one approver are
one approval; a valid signature from someone the policy does not name is nothing.

### 3.4 The anchor placeholder

LEFT covers the policy decision, so it does not exist until the signer has
decided — yet the transaction the signer signs has to carry LEFT in its anchor
field. The resolution is a placeholder:

1. the adapter prepares the transaction with **32 zero bytes** where the anchor
   goes, and reports the byte offset of that field inside the signing payload;
2. the signer checks those 32 bytes are still zero and that no other 32-zero run
   exists in the payload, decides, writes LEFT over them itself, and signs;
3. the adapter prepares the same transaction again with the real commitment and
   requires the result to equal the bytes the signer signed, byte for byte.

The signer therefore never has to parse a rail's binary format to know that the
anchor it authorized is the anchor that will settle: it wrote the anchor. Step 3
closes the loop from the other end, and the ledger closes it a third time, since
`observed_anchor` is read back from the validated transaction.

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
| 6b | `policy.document` — the supplied policy hashes to the one the decision names, and the pinned admin key signed it | implemented |
| 6c | `policy.escalation_challenge` — the challenge is `LEFT_pre` over these leaves | implemented |
| 6d | `policy.approval_quorum` — enough distinct approvers the policy names signed it | implemented |
| 7 | `policy.signature` — the policy key signed a payload carrying LEFT | implemented |
| 8 | `signer.attestation` — the attestation document and its PCR allowlist | implemented |
| 9 | `intent.matches_settled_fields` — destination, amount and currency agree | implemented |
| 10 | `settlement.anchor_equals_left` — the rail memo equals LEFT | implemented |
| 11 | `settlement.signed_blob` — the tx hash re-derives from the signed blob | implemented |
| 11b | `settlement.proof_matches_receipt` — the capture is about this transaction in this ledger | implemented |
| 11c | `settlement.ledger_header` — the header hashes to the ledger hash it claims | implemented |
| 11d | `settlement.validator_quorum` — enough pinned validators signed that ledger hash | implemented |
| 12 | `settlement.ledger_inclusion` — the composite: is this transaction in that ledger | implemented |
| 13 | `commitment.right` — leaves 4-6 (plus padding) fold to RIGHT | implemented |
| 14 | `commitment.root` — `ROOT == H(LEFT \|\| RIGHT)` | implemented |
| 15 | `envelope.rail` / `envelope.treasury` — match the intent leaf | implemented |
| 16 | `envelope.policy_hash` — matches the decision leaf | implemented |
| 17 | `session.log_join` — the envelope hash is committed in the log (level 2) | implemented |

A deferred check is reported as `not_implemented`. That is not a pass. When a
later phase implements one, the check keeps its name and the vectors move it from
`not_implemented` to `pass`.

Check 8 needs two things the receipt does not contain and must not: the PCR
allowlist and the trust anchor the *verifier* pinned, and the moment to judge the
document at. They are arguments to `verify_receipt_structure`
(`attestation_trust`, `now`). Without them the check reports `not_implemented`
naming what was missing, because no receipt gets to nominate the measurements it
should be judged against. `docs/ATTESTATION-VERIFY.md` specifies the nine
sub-checks it runs, and `merkl/core/vectors/attestation/` holds real
AWS-signed documents both implementations must agree on.

`not_implemented` also covers a check whose *inputs are absent*: check 7 on a
denied receipt has no signature to look at, because nothing settled. Those cases
say so by name too. The absence of data is never reported as agreement.

Checks 7, 9, 10 and 11 are the ones that make a receipt more than an internally
consistent document. A forger who rebuilds the whole tree — envelope, halves,
root, all of it — still cannot produce an Ed25519 signature by the policy key over
a payload containing the LEFT they invented. The tamper vectors
`rebuilt-without-a-policy-signature`,
`rebuilt-with-a-signature-over-another-payload` and
`rebuilt-with-an-anchor-that-is-not-left` are receipts where every structural
check passes and the receipt still proves nothing.

Two facts about check 11 worth stating, since they are per-rail:

| Rail | Transaction id |
|------|----------------|
| `xrpl` | `SHA-512Half("TXN" ‖ signed_blob)`, i.e. `0x54584E00` prefixed, first 32 bytes of SHA-512, uppercase hex |
| `fake` | `SHA-256("merkl-fake-tx-v1" ‖ NUL ‖ signed_blob)`, uppercase hex |

A rail this verifier has no rule for reports `not_implemented`, not `pass`.

### 7.1 The two settlement lines and the level

`verify_receipt_structure` answers everything a receipt can be asked about
itself. `merkl.core.verify.receipt.verify_receipt` runs the rest and reports what
the answers add up to, in the shape plan D9 and D10 require. Never one boolean.

**Transaction authorization** — did the policy key sign the bytes that settled?

| Value | Meaning |
|-------|---------|
| `verified` | check 7 passed, and where the blob is present check 11 passed with it |
| `absent` | nothing settled, or the receipt carries no signature to check |
| `contradicted` | a signature is present and it does not authorize this transaction |

**Ledger inclusion** — is that transaction in a ledger anyone can check?

| Value | Meaning |
|-------|---------|
| `proven-offline` | the header hashes to a ledger a pinned validator quorum signed, and a path folds this transaction into that header's transaction root |
| `verified-live` | the caller queried the rail and saw it validated. Weaker: it trusts whoever answered |
| `supplied-unverified` | the receipt names a ledger and nothing above established inclusion |
| `unchecked` | nothing settled, or no proof was supplied |

**Level** (plan D9) is `1` when the receipt was verified against the signer key,
the rail and itself, and `2` when `session.log_join` also passed — the envelope
hash is the `input_hash` of the action the receipt names, and that action proves
into a session root whose checkpoint and log inclusion were checked here. Level 1
is not a lesser verdict; it is a different question, answered fully.

### 7.2 What a settlement capture can prove

A capture taken at settlement time (plan D20) is read as three separate checks,
because collapsing them is how a verifier claims more than it holds.
`settlement.ledger_header` recomputes the ledger hash from the header — for XRPL
that is `SHA-512Half("LWR\0" ‖ ledger_index(4) ‖ total_coins(8) ‖ parent_hash(32)
‖ transaction_hash(32) ‖ account_hash(32) ‖ parent_close_time(4) ‖ close_time(4)
‖ close_time_resolution(1) ‖ close_flags(1))` — which is what binds the ledger's
transaction-set root to the identity validators sign.
`settlement.validator_quorum` counts *distinct* pinned validators whose
validation names that hash. And `settlement.ledger_inclusion` needs one more
link: `tx_path` folding the transaction into the header's `transaction_hash`.

The fake rail's path is a plain binary Merkle tree, `SHA-256(left ‖ right)` at
every level, `{"siblings": [...], "directions": ["left"|"right", ...]}`. XRPL's
is the real thing — a 16-ary radix trie (rippled's SHAMap), and both
implementations build and fold it byte for byte
(`merkl.core.verify.xrpl`, `merkl-verify.js`'s XRPL primitives):

```
tx leaf hash    = SHA-512Half("SND\0" ‖ VL(tx_blob) ‖ VL(meta_blob) ‖ tx_id)
inner node hash = SHA-512Half("MIN\0" ‖ child[0] ‖ child[1] ‖ ... ‖ child[15])
                  (empty branch = 32 zero bytes; an inner node with no branches
                  at all hashes to the all-zero value, XRPL's empty-tree root)
```

`VL(bytes)` is XRPL's variable-length prefix (1, 2 or 3 bytes depending on
length, XRPL's standard binary-format encoding). A branch is selected by one
nibble (4 bits) of the 256-bit transaction id per level, most significant
nibble first; a subtree collapses to a leaf directly wherever only one
transaction lives under a given prefix, so a path is one step per level the
tree actually materializes, not 64. `tx_path` for XRPL is
`{"tx_blob": hex, "tx_meta": hex, "steps": [{"nibble": 0-15, "siblings": [15
hex hashes, branches 0-15 excluding "nibble", in order]}, ...]}`, leaf-to-root.
The verifier recomputes the leaf from `tx_blob`/`tx_meta` themselves — the path
is tied to this transaction's actual bytes, never to a hash the proof merely
hands over — and folds `steps` in order; the result must equal the header's own
`transaction_hash`.

Validator quorum on XRPL is verified, not counted. Each `validations` entry
carries the raw `STValidation` blob the `validations` stream publishes (`data`,
hex) and the manifest in effect for that validator when it signed (`manifest`,
base64, fetched separately by the adapter via the `manifest` RPC). Verifying
one entry:

```
validation signing hash = SHA-512Half("VAL\0" ‖ every STValidation field except
                                       Signature, in canonical field order)
manifest signing hash   = SHA-512Half("MAN\0" ‖ every manifest field except
                                       Signature and MasterSignature)
```

secp256k1 signatures are ECDSA over that digest (DER-encoded, the compressed
SEC1 public key — `0x02`/`0x03` ‖ X); Ed25519 signatures (`0xED` ‖ key) are
verified over the preimage directly, no extra hashing. Fields are read with a
minimal STObject walker: a field header (1-2 bytes: type nibble, field nibble,
or a following byte when either is zero), then a fixed width for integers and
hashes or a `VL`-prefixed blob — the same field types (`Sequence`, `PublicKey`,
`SigningPubKey`, `Signature`, `MasterSignature`, `Domain`, `LedgerHash`,
`LedgerSequence`) both a `Validation` and a `Manifest` object use, per
rippled's own templates for each. A validation counts as one pinned validator's
agreement only when: its manifest verifies (both signatures), the manifest's
`SigningPubKey` is the exact key that signed *this* validation, the manifest's
`PublicKey` (the master key) is in the verifier's pinned set, and the
validation's own `LedgerHash` matches the recomputed ledger hash. The master-key
set is pinned in advance — never taken from the proof — the same way a
published validator list (`vl.ripple.com`, `vl.xrplf.org`,
`vl.altnet.rippletest.net`) is audited offline into a pinned form (`merkl xrpl
pin-unl`, `merkl.core.verify.xrpl.pin_validator_list`): the publisher's own
manifest chain, the top-level signature over the raw `blob` bytes (made with
the publisher's ephemeral key), and every validator's own manifest inside it.

The fake rail plays the same two roles under tags of its own that are **not**
any real rail's encoding, so `proven-offline` is a state both implementations
reach and both test suites assert on a rail that needs no network:

```
fake ledger hash = SHA-256("merkl-fake-ledger-v1" ‖ NUL ‖ ledger_index(8, BE)
                           ‖ transaction_hash(32))
fake validation  = Ed25519 over "merkl-fake-validation-v1" ‖ NUL
                                ‖ ledger_hash(32) ‖ ledger_index(8, BE)
```

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
| `approvals.json` | WebAuthn and Ed25519 assertions over a challenge, valid and invalid, plus quorum counting cases |
| `policies.json` | admin signatures over a policy document — the legacy Ed25519-over-pre-image form and the newer ApprovalAssertion-over-`policy_hash` form (Ed25519 or WebAuthn) — valid and tampered (wrong admin, edited rule after signing, WebAuthn origin not allowed) |
| `receipts.json` | four complete receipts (allow, deny, escalated-then-approved, and an unattested allow settled on the fake rail) with leaf hashes, halves, root, envelope hash, proofs, disclosure and the full structural verification result |
| `verdicts.json` | the full reading of each of those receipts — every check, both settlement lines, the level — beside the exact material the verifier was given to reach it |
| `tampered.json` | receipts and disclosures that must fail, each with the exact set of check names a conforming verifier reports |
| `bundles/` | proof bundles merkl-api actually exported (v1.1, v1.1 with a continuation, v1.2 with a receipt) plus mutations of them, in `bundles/cases.json` |
| `attestation/` | three documents AWS actually signed, and the cases over them |
| `manifest.json` | index, spec version, generator seed |

Regenerate with `python -m merkl.core.vectors.generate`; `--check` fails if the
committed files are stale. The generator refuses to emit a tamper case whose
declared failures disagree with what the verifier reports, so the fixtures cannot
drift into agreeing with a bug. `bundles/` and `attestation/` have their own
generators (`python -m merkl.core.vectors.bundles.generate`,
`python -m merkl.core.vectors.attestation.generate`) because their inputs are
files on disk rather than anything this repository computes.

`verdicts.json` is the one that pins the *arguments* as tightly as the answers.
Each case records the settlement proof, the validator key set and quorum, the
policy document and the admin key the verifier was handed, and then the verdict
those produce. A verifier that reached the same verdict from different material
would be a different verifier.

## Compatibility

`merkl-receipt-leaf-v1` and `merkl-receipt-v1` are frozen once released, on the
same terms as `merkl-leaf-v1`, `merkl-binding-v1` and `merkl-entry-v1`: any change
to a structure's fields or encoding requires a new tag, and a verifier rejects
tags it does not know. Adding an intent `type`, a rule outcome, or an optional
member of an existing content object is additive and keeps the tag; changing the
order of the seven leaves, the padding rule, or the canonicalization does not.
