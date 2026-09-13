# Phase 4 interfaces — what merkl-api and merkl-dashboard build against

Normative for the two repositories that consume this one. Everything here ships
in the next `merkl-sdk` release — the Unreleased section of `CHANGELOG.md`, which
is 0.2.0 content — and in `@merkl-ai/verify` at the same version, published from the
same tag (plan D19). `release.yml` refuses a tag where the two versions disagree,
because a reader holding one implementation has to be able to assume the other
agrees with it.

Names and signatures in this file are the contract. Check *names* and *statuses*
are too — they are what the vectors record. Prose detail strings are not: they
are written for a human reading the page, and the two implementations match on
them today only because it was cheap to do so.

---

## 1. Rendering verify.html — merkl-api

```python
from merkl.core.verify.render import render_verify_html

html: str = render_verify_html(bundle)   # bundle: dict[str, Any]
```

That is the exact import `merkl_api/export/sdk_renderer.py` already does behind
its feature check. Nothing else about the module needs to change; delete the
fallback once the version floor guarantees the import.

**Both bundle shapes work.** The renderer decides what to show from what is
present:

| Shape | Members | Page shows |
|---|---|---|
| Session bundle (v1.1 / v1.2) | `session`, `actions`, optionally `receipts[]`, `audit_log`, `transparency` | the story per receipt, the action table, the log, the checkpoint, the anchor, the evidence drop-zone |
| Receipt-only bundle | `{"version": "1.2", "receipts": [receipt], "session": None, "actions": []}` | the story, the two settlement lines, the level, every check, the seven leaves |
| Receipt bundle **with its session join** (added in 0.2.0) | the receipt-only members plus `session`, one `actions[]` row, `audit_log`, `transparency`, `scope` | all of the above, at **level 2** — see §2's "A receipt page that reaches level 2" |
| Disclosure bundle | `disclosure` (or `disclosures[]`), a `Disclosure.to_content()` | which leaves were revealed, which are hashes only, and the root the reader must pin elsewhere |

`render_receipt_verifier_html` in `receipt_verifier.py` already passes the second
shape. It does not need to change either.

Other functions in the same module, if you want them:

| | |
|---|---|
| `verify_template() -> str` | the raw template, three placeholders |
| `verify_js(*, as_module=True) -> str` | the verifier source; `as_module=False` strips `export` for inlining |
| `TEMPLATE_PATH`, `VERIFY_JS_PATH` | on-disk paths, both inside the wheel |

**Why the page inlines a classic script.** Chrome gives every `file://` document
an opaque origin and refuses module scripts there. An auditor opening the page
from a USB stick is the primary case, so `render_verify_html` strips the `export`
keywords when inlining. The file on disk stays a real ES module for npm and for
the Node suite.

### Files in merkl-api that become deletable

Once the version floor is in place:

| File | Why |
|---|---|
| `merkl_api/export/verify_js.py` | `CRYPTO_JS` and `CANONICAL_JS` are inside `merkl-verify.js` now, and the canonicalization there is tested against the Python one on every vector |
| the `_HTML_TEMPLATE` string in `merkl_api/export/html_verifier.py`, and `render_bundled_template` | superseded by the SDK template |
| the `_TEMPLATE` string in `merkl_api/export/receipt_verifier.py`, and the fallback branch | same |
| `merkl_api/export/sdk_renderer.py`'s `_load`/`sdk_renderer_available` fallbacks | the import is guaranteed once `pyproject.toml` floors `merkl-sdk>=0.2.0` |

`generate_verifier_html` and `render_receipt_verifier_html` keep their names and
become one-line delegations.

---

## 1b. ReceiptCard — merkl-api and merkl-dashboard

```python
from merkl.core.verify.card import receipt_card, render_card
from merkl.core.verify.receipt import receipt_from_content, verify_receipt

envelope, contents = receipt_from_content(entry)
verdict = verify_receipt(envelope, contents, ...)
card = receipt_card(verdict, envelope, contents)  # .to_content() is the JSON
```

```js
import { receiptCard, verifyReceipt } from '@merkl-ai/verify';
const verdict = await verifyReceipt(entry, options);
const card = receiptCard(verdict, entry.envelope, entry.leaves);
```

`GET /v1/receipts/{id}` should include `card` from the Python call. The dashboard
renders that object (or calls `receiptCard` itself). Do not invent a third
layout. Destination labels are a UI overlay (`labels` / `options.labels`); they
are not in the signed policy.

**A settled trade (added in 0.3.0).** A `swap` intent gives the card a different
body. The labels are exact and both implementations produce them byte for byte:

| status | body lines |
|---|---|
| `SETTLED` | `Bought <buy.amount> <code>` · `Sold <spent> <code> (limit <sell.max_amount> <code>)` · `Rate <spent/buy> <sell>/<buy>` · `From` · `By` · `On` · `Ref` |
| anything else | `Asked to buy <buy.amount> <code> for up to <sell.max_amount> <code>` · `From` · `By` (· `On` when there is one) |

There is no `To` line on a trade: the destination is the treasury, so it would
repeat `From`. When leaf 5 carries no `spent` the `Sold` line reads
`not stated (limit …)` and the `Rate` line is omitted entirely — a price nobody
can compute is not printed as if it could be.

`Rate` is `spent / buy.amount` to at most **six significant digits**, rounded
half to even, trailing fractional zeros stripped, never in scientific notation.
Both implementations compute it by integer arithmetic over the two decimal
strings (`rate_string` in Python, `rateString` in `@merkl-ai/verify`) so no float
and no decimal library is involved; `merkl/core/vectors/cards.json` carries a
`rate_cases` table of ties and repeating decimals that both suites assert
against.

The page `verify.html` already renders the card for a receipt-only bundle.

---
**Two things the SDK page fixes that the API's template had.** The API's
`_HTML_TEMPLATE` references `#actions-tbody`, `#root-hash`, `#total-count` and
`#verified-count` from its JavaScript, but stopped declaring any of them in its
HTML (the `refactor!: remove summaries entirely` commit). Every session page
rendered since then throws at `tbody.appendChild` and shows "Error" in the badge.
The SDK template declares the table. Second, the domain-tag fix on
`phase-4/receipts` (`merkl-leaf-v1`, `merkl-binding-v1`, `merkl-entry-v1`
prefixes) is carried over here — the SDK version was written against the fixed
encoding, and there is a vector for it.

---

## 2. Bundle v1.2 — what the SDK reads

`docs/SPEC.md` §9 describes the additions and the SDK reads them as written. The
members the verifier actually consumes, per entry of `receipts[]`:

| Member | Required | What the verifier does with it |
|---|---|---|
| `envelope` | yes | parsed by `Envelope.from_content`; every field is used |
| `leaves` | yes | the seven contents in order, `null` for an absent leaf |
| `settlement_proof` | optional | read by `read_settlement_proof`; drives the **ledger inclusion** line |
| `policy_document` | optional | looked up **by hash**; enables `policy.document` and `policy.approval_quorum`. Send the `SignedPolicy` form (`{document, signature, signer_public_key}`) so the admin signature can be checked too |
| `approvals` | optional | **not** read by the verifier. The authoritative approvals are inside leaf 2's `escalation`. Keep sending them for the dashboard's queue view, labelled as the notary's own record |
| `verification` | optional | not read. The page recomputes rather than inherits; keep it for the "what the server thought" panel |
| `session_locator`, `action_id` | optional | the join. See below |

**One fixture correction.** The bundle in `merkl/core/vectors/bundles/receipts-v1.2.json`
(taken verbatim from merkl-api's test container) has an action whose `input_hash`
is *not* the receipt's envelope hash, so `session.log_join` fails on it. The plan
(D4) and `merkl/sdk/receipts.py` both make the envelope hash the transaction
action's `input_hash`:

```python
canonical_hash(receipt["envelope"]).hex() == action["input_hash"]
```

The API's receipt-ingest fixture should be built that way; otherwise every
receipt it stores reads as level 1 forever. `merkl/core/vectors/verdicts.json`'s
`allow-settled` case carries a minimal bundle built correctly, if you want a
reference.

### Filing a receipt: the proof goes in the same request (added in 0.2.0)

`POST /v1/receipts` accepts a **`settlement_proof`** member beside `envelope`
and `leaves`:

```json
{
  "envelope": {...},
  "leaves": [ ... seven contents ... ],
  "settlement_proof": {"rail": "xrpl", "proof": { ...SettlementProof.to_content()... }},
  "pending_escalation": {"challenge": "...", "expires_at": "...", "quorum": 2}
}
```

Both extra members are optional, and an absent one is **absent**, never `null`.
`settlement_proof.rail` must equal the receipt's own rail; the API refuses a
mismatch the same way `POST /v1/receipts/{id}/settlement-proof` always has.

Why it belongs on the receipt's own request. Leaf 4 commits a
`settlement_proof_ref` — `"<rail>:<ledger_index>:<first 16 of tx_hash>"` — and
nothing else about the ledger. The header, the transaction and the validators'
signed messages that establish inclusion offline are captured by the rail
adapter at submit time and exist nowhere else. A receipt filed without them is
one whose ledger-inclusion line reads `unchecked` forever, and the SDK is the
only party that ever holds them.

`POST /v1/receipts/{id}/settlement-proof` (unchanged) stays the **late** route,
for a capture that completes after the receipt is on file: validations collected
afterwards, a header fetched on a retry. The SDK takes it through
`ReceiptBuilder.attach_settlement_proof(receipt_id, proof)`.

Neither call is on the decision path (plan D12). `merkl.adapters.notary.HttpNotary`
implements both, and a failure of either is returned on
`ReceiptOutcome.notary_error` rather than raised — a witness that is down does
not turn a settled payment into a failed call, and the SDK keeps its own copy
under `~/.merkl/receipts` regardless (`merkl.sdk.receipt_store.LocalReceiptStore`).

### A receipt page that reaches level 2 (added in 0.2.0)

A receipt page rendered from a receipt alone is level 1 by construction: the
verifier is handed no session, so `session.log_join` reports
`not_implemented` and says so. To reach level 2, `GET /v1/receipts/{id}/verify.html`
(and `GET /v1/receipts/{id}`, which carries the same material as `session_join`)
must supply the join — **scoped to this receipt's action**, not the whole
session:

| Member | What |
|---|---|
| `session` | the session block a full export carries: `session_id`, `root_hash`, `sealed`, `action_count`, `leaf_count`, … |
| `actions` | **exactly one row** — the action whose `input_hash` is this envelope's canonical hash — with its `leaf_hash` and its `proof` to the session root |
| `audit_log` | the entry that sealed that root |
| `transparency` | `checkpoint`, `log_inclusion`, and `anchor` when there is one — byte-identical to what the session bundle carries |
| `scope` | `{"kind": "receipt", "receipt_id", "session_id", "leaf_index", "actions_included", "action_count"}` — says the actions list is deliberately partial |

**The one rule that makes a scoped bundle work.** An action's leaf index is
`action.proof.leaf_index`, not its position in `actions[]`. A full export lists
every action in leaf order so the two always agreed and nothing changes for one;
a scoped bundle lists one row that may be leaf 5 of twelve, and a verifier
reading its position would join the receipt to whatever happened to be first.
Both implementations now read the declared index
(`merkl.core.verify.log.leaf_index_of` / `leafIndexOf`), falling back to the
position only when no proof says otherwise. `log.actions` then honestly reports
"1 of 1 actions rehash to their leaf and prove into the root", and `scope` is
what tells a reader the list was narrowed on purpose.

**A session that is not sealed yet.** Send the `session` block with
`"sealed": false` and no `transparency`. `session.log_join` reports
`not_implemented` with `session <id> is not sealed yet; level 2 becomes
available after sealing`, which appears in the verdict's `not_checked` list and
on the page — rather than the receipt reading as a bare level 1 with no
explanation. Do **not** omit the session block to achieve this: an omitted
session says "no bundle was supplied", which is a different fact.

### Policy documents the verifier can hash

`policy.document` hashes the `document` object **as supplied**:

```
policy_hash = SHA-256("merkl-policy-v1" || NUL || canonical_bytes(document))
```

That is `PolicyDocument.to_content()`'s output. Store what the SDK gave you
rather than a re-serialization from your own ORM, or the hash will not match.

### Rules a document may not carry (added in 0.2.0)

The engine reads `per_tx_cap` and `tiers.human.thresholds` **first match per
asset**, and `windows` **all matches per asset**. So a policy could be signed
with a rule the engine would never run, and `policy_hash` would cover it
faithfully. `PolicyDocument` now refuses five shapes:

| Refused | Why it could never run |
|---|---|
| two `per_tx_cap` for one asset on one agent | only the first is read |
| two `windows` for one (asset, seconds) on one agent | the second is a duplicate of the first |
| two `tiers.human.thresholds` for one asset | only the first is read |
| a cap or window for an asset outside that agent's `allowlist_assets` | the asset rule denies first |
| a threshold for an asset no agent may move | nothing can reach it |
| `may_swap` on an agent with fewer than two `allowlist_assets` (0.3.0) | a trade needs two assets on the allowlist, so no trade could pass the asset rule |

Two windows over the *same asset and different lengths* are fine — an hourly and
a daily limit both apply.

For the dashboard: a policy editor should refuse these before signing, with the
same wording, and `@merkl-ai/verify` exports `unenforceableRules(document)` →
`string[]` to check one. `policyDocumentCheck` runs it before the signature and
before the hash, so a receipt whose policy carries a dead rule reports
`policy.document` as `fail` with that sentence — a valid admin signature over a
matching hash says nothing about whether a rule can run.
`merkl/core/vectors/policies.json`'s `document_cases` pin the sentences for both
implementations.

### `network` — which chain, not just which rail (added in 0.2.0)

`rail` names a settlement *family*; `network` names one ledger in it.

| `rail` | `network` may be |
|---|---|
| `xrpl` | `xrpl-testnet`, `xrpl-mainnet` |
| `fake` | — (a rail with no networks may not name one) |

**Optional, and omitted from the content when unset.** A document that names no
network serialises exactly as it did before the field existed, so every
`policy_hash` signed before 0.2.0 is unchanged to the byte and every admin
signature over one still verifies. Setting it changes the hash, because it is
part of what the admin signs — a network cannot be attached to a policy after
the fact.

For merkl-api and merkl-dashboard:

- Surface it wherever `rail` is surfaced (`GET /v1/policies`, the treasuries
  list). It is `null` for a policy that does not name one; do not invent one.
- Use it to narrow issuer lists. RLUSD is issued by a different account on
  testnet than on mainnet, and an address means nothing in common between the
  two chains, so an issuer picker that ignores `network` will offer the wrong
  one half the time.
- A `null` network means the document does not say, which is not the same as
  "mainnet". Say "not specified".

Signer behaviour, so the dashboard can explain a refusal:

- At boot, if `merkl signer serve` was given a rail endpoint (`--rail-endpoint`
  or `$MERKL_RAIL_ENDPOINT`) whose host it recognises as a different chain, it
  refuses to start (exit 4) rather than co-sign for the wrong ledger. An
  unrecognised host — a private rippled — is not an opinion and does not block.
- Per payment, the XRPL codec refuses a payload whose `NetworkID` names another
  chain. Mainnet is network 0 and testnet is network 1, and rippled rejects a
  `NetworkID` below 1024, so neither chain's Payments carry the field: its
  absence proves nothing, and the boot check above is the real guard.

---

## 3. `@merkl-ai/verify` — merkl-dashboard

```bash
npm i @merkl-ai/verify
```

```js
import { verifyBundle, verifyReceipt, verifyDisclosure } from '@merkl-ai/verify';
```

No dependencies, Web Crypto only, ES module. `src/verification/verify.ts`'s
`verifyMerkleProof` is `deriveRoot(leafHex, siblings, directions)` here; delete
the file.

### The functions the dashboard needs

| Function | Returns |
|---|---|
| `verifyBundle(bundle, {evidence, receiptOptions})` | `{log, receipts[], ok, complete}` — one call for a whole export |
| `verifyReceipt(receipt, options)` | the verdict object below |
| `verifyLogBundle(bundle, {evidence})` | `{result, actions[], evidence[]}` for the Story view |
| `verifyDisclosure(disclosure, root)` | a result; `root` is an argument, never taken from the disclosure |
| `verifyAttestation(bytes, {trust, now, expectedPublicKey, expectedUserData})` | the nine attestation checks |
| `verifyAssertion(assertion, challengeBytes, credential)` | `{approver_id, valid, detail}` — for the approvals queue |
| `verifyQuorum(assertions, challengeBytes, approvers, quorum)` | `{quorum, checks, accepted, reached}` |
| `verifyPolicySignature(signedPolicy, {adminPublicKey, admin})` | `{valid, detail, unsupported?}` — an admin's signature over a policy change (§6) |
| `escalationChallenge(contents)` | `LEFT_pre`, so the queue can show what a passkey will sign |
| `readSettlementProof(proof, {rail, txHash, ledgerIndex, trust, live})` | `{checks, ledger_inclusion, detail}` |
| `notCheckedOf(checks)`, `notCheckedLine(entries)`, `CHECK_LABELS` | the unchecked list and its wording, if you build the line yourself |
| `actionLeafHash`, `receiptLeafHash`, `canonicalHashHex`, `deriveRoot`, `merkleRoot` | the primitives, if you need one directly |

### The verdict object

```ts
{
  receipt_id: string,
  ok: boolean,            // nothing was contradicted
  complete: boolean,      // every check actually ran
  level: 1 | 2,
  level_detail: string,   // one sentence, already naming its level
  not_checked: [{name, label, reason}],   // every check that did not run
  not_checked_line: string,               // "Not checked: a (why), b (why)."
  verdict_line: string,                   // the two above, in order
  settlement: {
    transaction_authorization: 'verified' | 'absent' | 'contradicted',
    transaction_authorization_detail: string,
    ledger_inclusion: 'proven-offline' | 'verified-live' | 'supplied-unverified' | 'unchecked',
    ledger_inclusion_detail: string,
  },
  attested: true | false | null,   // false = leaf 3 is null, an unattested signer
  summary: {                       // render these, not the hashes
    instructed, rule, approved, settled, when, signer, testimony, // string | null
    testimony_note,               // leaf 6's own note, verbatim — not our sentence
  },
  checks: [{name, status: 'pass' | 'fail' | 'not_implemented', detail}],
  log?: {ok, complete, checks, actions, evidence},
  result: { ok, complete, get(name), failures, deferred, checks },
}
```

**Never render `ok` alone.** `ok && !complete` is a common and honest state — a
receipt with nothing contradicted and several checks the page had no material
for. The page in this repo shows a third badge for it (`Consistent · partly
unchecked`); the dashboard should too. `attested === false` must be visible
without expanding anything: it means no enclave vouches for the key that
authorized the payment.

**And never explain `!complete` in the abstract.** Render `verdict_line` (or
`not_checked` yourself), not a sentence of your own: "some checks are not
implemented in this browser or unconfigured" is true of every incomplete
verdict, so a reader learns nothing about *this* receipt from it. `not_checked`
gives each unchecked check a `label` in plain words and a `reason` that is the
check's own `detail`, so the line reads

> Nothing was contradicted. Not checked: enclave attestation (no PCR allowlist
> and moment were pinned, so nothing says which enclave this is), ledger
> inclusion (no settlement proof was supplied with this receipt).

`complete === (not_checked.length === 0)` always; they are two readings of one
fact, and the list covers the log's deferred checks as well as the receipt's.
`CHECK_LABELS` is exported if you want to relabel; a check with no label is
listed under its own name rather than dropped.

**`level_detail` already names its level.** Do not prefix "Level 2." to it — the
page in this repo did, and printed the level twice in one line.

**`summary.testimony_note` is not a sentence of ours.** It is leaf 6's `note`,
verbatim, and belongs on its own line beneath `summary.testimony` in a quieter
style — never concatenated with it. The testimony sentence is the verifier
saying what a committed hash does and does not establish; the note is the agent
describing its own reasoning. Running them together lends one the other's
authority, which is the exact confusion leaf 6's `testimony: true` exists to
prevent. It is `null` when leaf 6 is absent or carries no note.

### Options are trust anchors, and none of them may come from the receipt

```js
await verifyReceipt(receipt, {
  attestationTrust: {pcrs: {0: '…', 8: '…'}, rootPem, maxAgeSeconds, requireProductionMode},
  now: '2026-01-02T03:04:05Z',              // an argument. Never Date.now() inside.
  validatorTrust: {validators: {name: pubkeyHex}, quorum: 2},
  settlementProof, policyDocument, adminPublicKey, sessionBundle, liveSettlement,
});
```

Omitting any of them turns its checks into `not_implemented` with a reason. That
is the correct default for a dashboard that has not been configured with pins
yet — it renders "not checked", not a green tick.

**Ed25519 in the browser.** Where Web Crypto has no Ed25519, `ed25519Verify`
returns `null` and the checks that need it report `not_implemented` naming the
runtime, never `fail` and never a quiet pass. Chrome 137+, Safari 17+ and
Firefox 130+ have it; Node 20+ has it.

---

## 4. Fixtures to test against

All inside the wheel, under `merkl/core/vectors/`:

| Path | Cases | For |
|---|---|---|
| `receipts.json` | 4 receipts | leaf hashes, halves, root, envelope hash, proofs, disclosure |
| `verdicts.json` | 4 verdicts | the whole reading beside the exact material it was reached from |
| `tampered.json` | 28 | receipts and disclosures that must fail, with the exact failing check names |
| `approvals.json` | 10 + quorum cases | WebAuthn and Ed25519 assertions, valid and invalid |
| `policies.json` | 9 | admin signatures over a policy document — legacy and assertion-shaped, valid and tampered (§6) |
| `merkle.json`, `action_leaf.json`, `receipt_leaf.json` | 8 / 10 / 21 | the frozen encodings |
| `bundles/cases.json` | 12 | real merkl-api exports (v1.1, continuation, v1.2) and mutations of them |
| `attestation/cases.json` | 17 | three documents AWS actually signed |
| `xrpl/cases.json` | 12 | a real testnet ledger's SHAMap, two real validators' `STValidation`/manifests, the real testnet UNL — tamper cases for each |

The Node suite in `tests/js/` reads exactly these. Copy its loaders
(`tests/js/vectors.mjs`) rather than writing new ones.

Regenerate with `python -m merkl.core.vectors.generate`,
`… .attestation.generate`, `… .bundles.generate`, `… .xrpl.generate`; each
takes `--check`.

**`validatorTrust` for XRPL is keyed by master key, not by name.** The fake
rail's example above (`{name: pubkeyHex}`) is a display name to an Ed25519 key
that exists only in one test process; XRPL's pinned set is `{masterKeyHex:
masterKeyHex}` — the master key is both the identifier and (mirrored) the
value, because the material actually needed to check a signature (the current
*ephemeral* key) comes from the manifest inside the proof, verified against
that master key, not from anything the verifier pins directly. Produce this
set with `merkl xrpl pin-unl <url|file> -o pinned.json` (or
`merkl.core.verify.xrpl.pin_validator_list` directly) — it audits a published
list (`vl.ripple.com`, `vl.xrplf.org`, `vl.altnet.rippletest.net`) once, offline,
and prints exactly which validators were pinned and which were skipped, and
why. Never take this set from a receipt or a settlement proof.

---

## 5. Signer RPC: `reject`

New method, documented in `docs/SIGNER-RPC.md` §4. `{challenge, assertions}` in,
a `deny` envelope out, with the signed refusals inside leaf 2's escalation and
the reservation released.

**The API's relay is not wired yet.** `POST /v1/escalations/{id}/reject` files the
rejection in the notary's tables. That records what a reviewer clicked; it is not
a decision, and the escalation stays pending in the signer with its reservation
held. The follow-up is to forward `{challenge, assertions}` to the signer's
`reject` and store the returned decision beside the receipt, exactly as `approve`
does. `merkl reject <challenge>` already speaks it, if you want something to
test the signer end against.

---

## 6. Policy signing for the dashboard

Plan D16, extended: an org can now put a policy change into force with a
WebAuthn admin credential from the browser, not only an Ed25519 key on some
operator's machine. `PolicyDocument.admin` names it:

```json
{"credential_type": "webauthn", "public_key": "<hex, uncompressed SEC1 point>",
 "origins": ["https://app.merkl.ai"], "rp_id": "app.merkl.ai", "user_verification": true}
```

The legacy `admin_public_key` field (a bare Ed25519 hex string) still works and
still means exactly what it always did — a document carries one or the other,
never both — and `PolicyDocument.to_content()` emits the legacy field alone
when that is what is set, so `policy_hash` for every document signed before
this phase is **byte-identical**. `merkl/core/vectors/policies.json` is the
proof: regenerating the vectors after this change touched only `manifest.json`.

### The exact WebAuthn challenge

**`policy_hash`, the 32-byte digest — not the pre-image, and not an
escalation's `LEFT_pre`.** Compute it the same way the signer and both
verifiers do:

```
policy_hash = SHA-256("merkl-policy-v1" || NUL || canonical_bytes(document))
```

Hand those 32 bytes to `navigator.credentials.get()` as `publicKey.challenge`
exactly as you would `LEFT_pre` for an approval — same ceremony, same
`AuthenticatorAssertionResponse`, different bytes. Getting this wrong (signing
the pre-image, or a hash of the JSON string instead of `canonical_bytes`)
produces a signature that will never verify against anything, silently, so
check it against `merkl/core/vectors/policies.json`'s `webauthn-admin-valid`
case before wiring it up for real.

### The assertion shape

Package the WebAuthn ceremony's output exactly as an approver's assertion is
packaged (`RECEIPT-SPEC.md` §3.3) — same fields, same encodings, with
`approver_id` fixed to the literal string `"admin"`:

```json
{"approver_id": "admin",
 "credential_type": "webauthn",
 "signature": "<hex DER>",
 "client_data_json": "<hex of the raw clientDataJSON bytes>",
 "authenticator_data": "<hex>",
 "signed_at": "2026-02-01T09:00:00Z"}
```

`client_data_json` is hex of the *exact bytes* the browser produced — not a
re-serialization of the parsed JSON, which would change the bytes the
signature covers and so break it. The inner `challenge` member of
`clientDataJSON` stays base64url, because that is what WebAuthn puts there.

An Ed25519 admin who is not in a browser (`merkl policy sign` — the
non-browser path) produces the same shape, just with `credential_type:
"ed25519"` and no `client_data_json` / `authenticator_data`, signing the raw
32 bytes of `policy_hash` directly. One wire shape either way.

### The POST body the API expects

```json
{"signed_policy": {
  "document": { … PolicyDocument.to_content() … },
  "signature": { … the assertion above, or the legacy hex string … },
  "signer_public_key": "<hex>"
}}
```

That is `SignedPolicy.to_content()`, unmodified, and it is exactly the body
`merkl.signer.engine.SignerEngine.policy_update` and the `policy_update` RPC
method already accept (`docs/SIGNER-RPC.md` §4) — the notary's route is a
relay, the same shape D1 and D11 already establish for `approve`/`reject`:
forward `{signed_policy}` to the signer's `policy_update` verbatim and store
the returned change entry beside the receipt log, never evaluate the
signature itself. `signer_public_key` is the credential's own `public_key`
(the WebAuthn P-256 point, or the Ed25519 key) — the same value that must
appear in `PolicyDocument.admin.public_key` (or `admin_public_key`) for the
document to trust the key that is about to sign it, and the same value the
signer checks the incoming signature against **its own currently-pinned
admin**, never against whatever the incoming document nominates (a forged
document could nominate anything).

### Verifying it — `verifyPolicySignature`

```js
import { verifyPolicySignature } from '@merkl-ai/verify';

const result = await verifyPolicySignature(signedPolicy, { admin: pinnedAdminCredential });
// { valid: boolean, detail: string, unsupported?: true }
```

Mirrors `merkl.core.policy.approvals.verify_policy_signature` exactly, and
like every other function in the package, returns a structured result rather
than a boolean (`README.md`'s "nothing returns a single boolean"). `admin`
pins a full credential — a WebAuthn admin's `origins` included, which matters:
without it, an assertion phished from a lookalike origin would still verify.
`adminPublicKey` pins a legacy Ed25519 key only. Passing neither trusts the
document's own `admin` / `admin_public_key` member, which is exactly what a
forged document exploits by nominating itself — pin one before you act on the
result. A runtime with no Ed25519 in Web Crypto reports `valid: false,
unsupported: true` rather than a quiet failure; this only matters for an
Ed25519 admin, since WebAuthn's ECDSA P-256 has no such gap.

---

## 7. Reconciliation: reading rail history

`SignerEngine.reconcile` (plan D17) compares its own state to the rail's
validated history — but the notary is the party this design assumes may be
compromised, and it must never hold a signing key, so it cannot construct an
`XrplSettlementAdapter` (which needs an `agent_wallet`) just to read
`account_tx`. `merkl.adapters.xrpl.history` is the read-only, wallet-free
answer:

```python
from merkl.adapters.xrpl import history

outflows = await history(treasury, since, json_rpc_url="https://s.altnet.rippletest.net:51234")
```

```
async def history(
    treasury: str,
    since: str = "",
    *,
    json_rpc_url: str,
    ledger_index_min: int | None = None,   # added in 0.2.0
) -> Sequence[Outflow]
```

`ledger_index_min` bounds the `account_tx` read below; `since` filters what
comes back by close time. Unbounded by default, which reads from as far back as
the node has — on a full-history node, genesis. **A caller that knows when its
own interest in the treasury began should say so**: the notary does, from the
ledger of its earliest settled receipt, and reads a window instead of a life.
Pass it only when the installed signature accepts it (`inspect.signature`), the
same way `history` itself is checked for below.

A module-level function, not a method — it builds its own throwaway
`AsyncJsonRpcClient` for `json_rpc_url` and closes over nothing that could
sign anything. It reads `account_tx` and parses the response through
`_outflows_from_response`, the **one** parser
`XrplSettlementAdapter.history` (the wallet-holding method, used by the SDK
and the signer's own reconciliation) also calls — a notary reading the ledger
and a signer reading the ledger read it the same way, by construction, not by
convention.

**How the API should call it.** Check by attribute rather than importing a
name that might not exist in an older `merkl-sdk`:

```python
xrpl_history = getattr(merkl.adapters.xrpl, "history", None)
if xrpl_history is not None:
    outflows = await xrpl_history(treasury, since, json_rpc_url=configured_url)
else:
    outflows = uploaded_outflows  # whatever reconciliation source existed before
```

Absent on an older SDK, the notary falls back to whatever it already had
(uploaded outflows) rather than failing — the same "extend, never replace in
place" rule that governs every other production-facing change in this repo.

**A trade reads back as one transaction with two sides (added in 0.3.0).** A
cross-currency Payment whose `Destination` is the treasury and which carries a
`SendMax` is a trade, not a transfer. `Outflow.value`/`asset` are then what was
actually *spent* — derived from the treasury's balance change in the same
metadata — and two new optional members, `inflow_value` and `inflow_asset`,
carry what arrived. Both are omitted for an ordinary payment, so every outflow
written before trading existed reads back byte-identically, and
`Outflow.is_swap` is the one-line test. When the metadata will not yield the
cost, the transaction's own `SendMax` stands in: an upper bound never
understates an outflow, and understating one is the failure that matters in a
reconciliation. Matching is unchanged — by tx hash, then by anchor — so a trade
the signer never saw is reported as an unmatched outflow exactly as a stray
payment is.

**This reads public ledger data only.** `account_tx` against a `json_rpc_url`
is a public JSON-RPC call any XRPL client can make; nothing about the
treasury's signing keys, the agent's keys, or the policy's admin key is
involved, and nothing here can produce a transaction, only read ones that
already settled. The result is `Outflow` value objects — evidence for
`SignerEngine.reconcile` to compare against state it wrote itself, never a
decision this function or its caller gets to make (the same "evidence, not
instruction" rule the Nitro parent proxy's own history channel follows,
`docs/SIGNER-RPC.md` §6).

---

## 8. What did not change

`merkl-leaf-v1`, `merkl-binding-v1`, `merkl-entry-v1`, `merkl-receipt-leaf-v1`
and `merkl-receipt-v1` are untouched, byte for byte. Every bundle that verified
before still verifies. `merkl.core.verify_receipt_structure` keeps its name and
its behaviour, including reporting `settlement.ledger_inclusion` and
`session.log_join` as `not_implemented`: those two need material a receipt does
not carry, and `merkl.core.verify.receipt.verify_receipt` is where the arguments
for them live.
