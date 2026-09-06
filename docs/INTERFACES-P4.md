# Phase 4 interfaces — what merkl-api and merkl-dashboard build against

Normative for the two repositories that consume this one. Everything here ships
in the next `merkl-sdk` release — the Unreleased section of `CHANGELOG.md`, which
is 0.2.0 content — and in `@merkl/verify` at the same version, published from the
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

### Policy documents the verifier can hash

`policy.document` hashes the `document` object **as supplied**:

```
policy_hash = SHA-256("merkl-policy-v1" || NUL || canonical_bytes(document))
```

That is `PolicyDocument.to_content()`'s output. Store what the SDK gave you
rather than a re-serialization from your own ORM, or the hash will not match.

---

## 3. `@merkl/verify` — merkl-dashboard

```bash
npm i @merkl/verify
```

```js
import { verifyBundle, verifyReceipt, verifyDisclosure } from '@merkl/verify';
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
| `actionLeafHash`, `receiptLeafHash`, `canonicalHashHex`, `deriveRoot`, `merkleRoot` | the primitives, if you need one directly |

### The verdict object

```ts
{
  receipt_id: string,
  ok: boolean,            // nothing was contradicted
  complete: boolean,      // every check actually ran
  level: 1 | 2,
  level_detail: string,
  settlement: {
    transaction_authorization: 'verified' | 'absent' | 'contradicted',
    transaction_authorization_detail: string,
    ledger_inclusion: 'proven-offline' | 'verified-live' | 'supplied-unverified' | 'unchecked',
    ledger_inclusion_detail: string,
  },
  attested: true | false | null,   // false = leaf 3 is null, an unattested signer
  summary: {                       // render these, not the hashes
    instructed, rule, approved, settled, when, signer, testimony  // string | null
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

The Node suite in `tests/js/` reads exactly these. Copy its loaders
(`tests/js/vectors.mjs`) rather than writing new ones.

Regenerate with `python -m merkl.core.vectors.generate`,
`… .attestation.generate`, `… .bundles.generate`; each takes `--check`.

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
import { verifyPolicySignature } from '@merkl/verify';

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

## 7. What did not change

`merkl-leaf-v1`, `merkl-binding-v1`, `merkl-entry-v1`, `merkl-receipt-leaf-v1`
and `merkl-receipt-v1` are untouched, byte for byte. Every bundle that verified
before still verifies. `merkl.core.verify_receipt_structure` keeps its name and
its behaviour, including reporting `settlement.ledger_inclusion` and
`session.log_join` as `not_implemented`: those two need material a receipt does
not carry, and `merkl.core.verify.receipt.verify_receipt` is where the arguments
for them live.
