# @merkl-ai/verify

Verify a Merkl receipt or proof bundle yourself, offline, with nothing installed
but a JavaScript runtime.

One normative spec, one vector set, two implementations. This module is the
JavaScript half; `merkl.core.verify` (PyPI `merkl-sdk`) is the Python half. Both
run against the same fixtures in `merkl/core/vectors/`, report the same check
names with the same statuses, and reach the same verdict from the same material.
A disagreement between them is a bug in one of them.

No dependencies. Web Crypto only, so the same file runs in a browser opening a
`verify.html` with no network and under `node --test` in CI.

```js
import { verifyBundle, verifyReceipt } from '@merkl-ai/verify';

const verdict = await verifyReceipt(bundle.receipts[0], {
  policyDocument: bundle.receipts[0].policy_document,
  settlementProof: bundle.receipts[0].settlement_proof,
  sessionBundle: bundle,
});

verdict.summary.settled;   // "250.00 RLUSD went to rSUPPLIER… on xrpl, transaction 8209…"
verdict.settlement;        // { transaction_authorization: "verified", ledger_inclusion: "…" }
verdict.level;             // 1 (receipt alone) or 2 (joined to a session log)
verdict.checks;            // every check by name, with pass | fail | not_implemented
```

## What it will not do

**It never reads a clock.** `now` is an argument everywhere. A reader's clock is
not evidence, and a verifier that consulted one could not be checked against the
fixtures.

**It never fetches a trust anchor.** The AWS Nitro root is embedded, with its
fingerprint. A verifier that downloads its own root trusts whoever answered the
request.

**It never takes a trust decision from the material it is verifying.** The PCR
allowlist, the validator key set, the policy document, the admin key: all
arguments. No receipt gets to nominate what it should be judged against.

**It never reports a check it did not run as a pass.** A check whose inputs are
absent — no policy document, no settlement proof, no session bundle — comes back
as `not_implemented` with the reason. Two verdict lines are reported, never one:
`ok` (nothing was contradicted) and `complete` (everything ran).

## The two settlement lines

A settlement verdict is two facts, and collapsing them hides which half was
established:

| `transaction_authorization` | |
|---|---|
| `verified` | the policy key signed the bytes that settled |
| `absent` | nothing settled, or no signature to check |
| `contradicted` | a signature is present and authorizes something else |

| `ledger_inclusion` | |
|---|---|
| `proven-offline` | a pinned validator quorum signed a ledger, and a path puts this transaction in it |
| `verified-live` | a live rail query said so. Weaker: it trusts whoever answered |
| `supplied-unverified` | a ledger is named and nothing here established inclusion |
| `unchecked` | nothing settled, or no proof supplied |

## The public API

| | |
|---|---|
| `verifyBundle(bundle, opts)` | a whole export: session log, every receipt in it |
| `verifyReceipt(receipt, opts)` | one receipt, to the depth the material allows |
| `verifyLogBundle(bundle, opts)` | the session, log, checkpoint and evidence half |
| `verifyDisclosure(disclosure, root)` | a partial receipt against a root you pinned |
| `verifyAttestation(bytes, opts)` | one AWS Nitro attestation document |
| `verifyAssertion` / `verifyQuorum` | WebAuthn and Ed25519 approvals |
| `verifyPolicySignature(signedPolicy, opts)` | a policy document's admin signature — Ed25519 or WebAuthn |
| `readSettlementProof(proof, opts)` | what a settlement capture proves |
| `canonicalJson` / `canonicalHashHex` | the one canonicalization, ported byte for byte |
| `actionLeafHash` / `receiptLeafHash` | the frozen leaf encodings |

Every function returns structured results. Nothing returns a single boolean.

## Specifications

- `docs/RECEIPT-SPEC.md` — the receipt format and its verification order
- `docs/ATTESTATION-VERIFY.md` — attestation documents, check by check
- `merkl-api/docs/SPEC.md` — the session log, checkpoints and the bundle
