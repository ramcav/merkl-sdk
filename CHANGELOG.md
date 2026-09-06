# Changelog

All notable changes to `merkl-sdk`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by pushing a `v<version>` tag; see
`.github/workflows/release.yml`.

## [Unreleased]

### Added — phase 6

- **Relay bearer authentication on the signer RPC.** Every method but
  `propose` — `health`, `public_key`, `attestation`, `approve`, `reject`,
  `settle`, `release`, `policy_update` — now accepts an optional relay
  credential: `merkl signer token add|revoke|list` writes SHA-256 digests
  only to the signer's config and prints a fresh token exactly once. Once at
  least one is configured, every non-`propose` method requires
  `Authorization: Bearer <id>:<secret>`, checked in constant time; with none
  configured a signer behaves exactly as it did before this phase. Wired
  through both transports — the HTTP `Authorization` header for the dev
  signer, and a vsock `auth` frame member the Nitro parent proxy forwards
  unchanged from the header it received (`merkl.signer.relay_auth`,
  `docs/SIGNER-RPC.md` §3, "Who may call what"). Not a fund-moving secret: it
  bounds who may push at the signer, not what a push can accomplish.
- **Policy documents may be signed by a WebAuthn admin, not only Ed25519.**
  `PolicyDocument.admin` (`{credential_type, public_key, origins?, rp_id?,
  user_verification?}`) sits beside the legacy `admin_public_key` field —
  mutually exclusive, and the legacy field still emits exactly the bytes it
  always did, so `policy_hash` for every document signed before this phase is
  byte-identical (`merkl/core/vectors/policies.json` proves it: regenerating
  touches only `manifest.json`). `SignedPolicy.signature` may now be an
  `ApprovalAssertion`-shaped object — Ed25519 or WebAuthn — over the 32-byte
  `policy_hash`, with `approver_id` fixed to `"admin"`, verified by
  `merkl.core.policy.approvals.verify_policy_signature`: one function for
  both admins and approvers, no second WebAuthn parser. `merkl policy sign
  <document.json> --key <ed25519>` is the non-browser path; `merkl policy
  show` renders a document — rules, tiers, approvers, admin — in words.
  `verifyPolicySignature` is the `@merkl/verify` mirror
  (`docs/INTERFACES-P4.md` §6, "Policy signing for the dashboard", has the
  exact WebAuthn challenge and the POST body the API relays to
  `policy_update`). `PolicyChange` gains `credential_type`, naming which kind
  of admin authorized the change; it defaults to `ed25519` for change entries
  recorded before this field existed, which every one before this phase was.

## [0.2.0] - 2026-09-06

### Added — phase 5

- **`merkl demo`** — runs the five scenarios end to end and writes each as a
  self-contained `verify.html`, checked by both `merkl verify` and the new
  `@merkl/verify` CLI over the same file before either is written to disk. The
  fake rail always runs; `--xrpl-testnet` (or `MERKL_XRPL_TESTNET=1`) also runs
  the same five stories against the real network, reusing the treasury cached
  under `~/.merkl` (the same wallet files `merkl treasury init` and the pytest
  suite use) so a second run does not re-drain the faucet, and prints a
  transaction hash for every payment that actually settles.
- **`merkl.demo`** — the rig, the five scenarios and the page-writer, as a
  shipped package: a real signer, a real encrypted keystore, real approvals,
  and a swappable `Environment` (`FakeEnvironment`, `XrplEnvironment`) so the
  same five stories run unmodified against either rail. A scenario's claim
  about itself raises `ScenarioError` rather than asserting, so it cannot
  silently disappear under `python -O`.
- **`@merkl/verify`'s CLI** (`merkl/core/verify/js/cli.mjs`, reachable as
  `npx @merkl/verify` or the `merkl-verify` bin once installed) — the same
  checks `merkl verify` runs, over a receipt, a bundle, or a rendered
  `verify.html`, in the other implementation. A scenario page that only
  `merkl verify` had checked would have been checked once; checked by both, it
  has been checked by two programs that share no code.
- **README rewritten** for the co-signer: an ASCII architecture diagram
  (`merkl.sdk` → `merkl.signer` / `merkl.adapters` → `merkl.core`), the trust
  model in plain words (who holds what, what a receipt needs to verify, what
  Merkl never has, what the customer's enclave attests), a pointer to
  `docs/RECEIPT-SPEC.md`, how to add a rail with `merkl.adapters.fake` as the
  worked example, how to run the scenarios, and how to deploy the signer (dev,
  Nitro). Sold as an AI accountability product; XRPL gets one sentence.

Ran the XRPL path for real: bootstrap reused the treasury cached from an
earlier phase, and four of the five scenarios settled with real transaction
hashes recorded (the fifth, the prompt-injection drain, is a denial and
settles nothing — that is what it is testing). Both verifiers agreed on every
page, including the ones built from real testnet transactions.

### Fixed — phase 5

- **`merkl demo --no-node` always exited non-zero, even when nothing was
  wrong.** `PageReport.agreed` requires two verifier readings by design — it
  answers "did both agree" — but with `--no-node` only the Python reading ever
  existed, so it was always `False`. `demo_command` now falls back to the
  single reading's own verdict when the JavaScript verifier was not asked to
  run, rather than reporting disagreement between a verifier and nothing.

### Added

- **Verification is now two implementations of one spec (plan D7).**
  `merkl.core.verify.receipt.verify_receipt` and `@merkl/verify`'s
  `verifyReceipt` compute the same bytes, report the same check names with the
  same statuses, and reach the same verdict from the same material — down to the
  plain-language summary a reader sees. `merkl/core/vectors/verdicts.json`
  records each verdict beside the exact settlement proof, validator set, policy
  document and session bundle it was reached from, and both suites assert
  against it. A divergence is a bug in one of them, never a difference.
- **One verdict, never one boolean.** The settlement result is two lines (plan
  D10): *transaction authorization* (`verified` / `absent` / `contradicted`) and
  *ledger inclusion* (`proven-offline` / `verified-live` / `supplied-unverified`
  / `unchecked`). Above them sits the level (plan D9): level 1 is the receipt
  against the signer key and the rail; level 2 additionally joins the session
  log. And above that, five sentences — what the agent was told, which rule
  allowed it, who approved, what settled, when — because a receipt whose meaning
  only survives as hex has not been verified by anybody who matters.
- **Three checks the format defined and nothing ran.**
  `policy.escalation_challenge` recomputes `LEFT_pre` from the finished receipt,
  so a reader can see the approvers signed *this* payment.
  `policy.approval_quorum` counts distinct approvers the policy names.
  `policy.document` looks the policy up **by hash** — a policy replaced since
  cannot be shown in place of the one that decided — and verifies its admin
  signature when the caller pins the key.
- **`merkl.core.verify.settlement` — what a settlement capture actually proves.**
  Three separate checks, because collapsing them is how a verifier claims more
  than it holds: is the proof about this transaction, does the header hash to the
  ledger hash it claims (XRPL's `LWR\0` preimage, recomputed), and did a quorum
  of validators the *verifier* pinned sign that hash. `settlement.ledger_inclusion`
  needs one more link — a path folding the transaction into the header's
  transaction root — which XRPL captures still lack and name in their own
  `missing` list.
- **`merkl.core.verify.log` — sessions, the transparency log and evidence, in
  Python.** Action leaves, session inclusion, the `merkl-entry-v1` chain, RFC 6962
  log inclusion, the checkpoint body and its Ed25519 signature, the continuation
  binding, and disclosed evidence records. These existed only in JavaScript,
  inside a page merkl-api rendered — one implementation of a normative format,
  living in the wrong repository.
- **`verify.html` and the JavaScript verifier move into the SDK**, rendered by
  `merkl.core.verify.render.render_verify_html(bundle)` — the function merkl-api
  calls, taking a session bundle, a receipt-only bundle or a disclosure. The page
  leads with sentences and keeps every hash behind an expander, shows an
  unattested signer loudly rather than as a missing field, labels reasoning as
  testimony, names every check it could not run, and keeps the evidence
  drop-zone. It is one self-contained file that opens from a USB stick with no
  network.
- **`@merkl/verify`** — the same algorithms in JavaScript, no dependencies, Web
  Crypto only: canonicalization ported escape for escape, the frozen leaf
  encodings, the receipt tree, WebAuthn and Ed25519 approvals, a CBOR reader
  restricted to the attestation profile, an X.509 reader for the four fields a
  chain check needs, AWS Nitro attestation, settlement proofs and the session
  log. 172 tests under `node --test`, no bundler, published from the same tag as
  the PyPI distribution (plan D19).
- **CLI.** `merkl verify <receipt|bundle|verify.html>` — the rendered page an
  auditor was emailed is itself a valid input, so disagreeing with it is
  something you can check. `merkl receipt show` reads the seven leaves out loud.
  `merkl disclose --leaves` ships a selective disclosure whose withheld leaves
  are hashes proving only that they exist unedited, and renders the page locally
  so a disclosure survives the notary being down. `merkl approve` / `merkl
  reject` sign an escalation with a local Ed25519 key. `merkl reconcile` matches
  outflows to receipts in both directions — the direction that matters finds
  money leaving with no co-signed authorization behind it.
- **Signer RPC `reject(challenge, assertions)`** (plan D11). Verified like
  `approve`, records a DENY whose leaf 2 carries the signed refusals, releases
  the reservation. An escalation that simply stops being mentioned proves nothing
  about whether anybody looked at it.
- **`docs/INTERFACES-P4.md`** — the contract merkl-api and merkl-dashboard build
  against: the renderer's name and signature, the bundle v1.2 members the
  verifier reads, the `@merkl/verify` API, the fixtures, and which files in
  merkl-api become deletable.
- **New fixtures.** `verdicts.json` (4), `bundles/` (three real merkl-api exports
  plus 9 mutations), and a fourth receipt settled on the fake rail so
  `proven-offline` is a state both implementations reach rather than a branch
  nobody runs. `py.typed`, so merkl-api's mypy stops seeing this package as
  untyped.

### Fixed

- **The rendered session verifier had been throwing since summaries were
  removed.** merkl-api's template referenced `#actions-tbody`, `#root-hash`,
  `#total-count` and `#verified-count` from its JavaScript but stopped declaring
  any of them in its HTML, so every session page failed at `tbody.appendChild`
  and showed "Error" in the badge. The SDK template declares the table.

### Changed

- `DEFERRED_CHECKS` is empty of phase markers: `settlement.ledger_inclusion` and
  `session.log_join` are implemented, and `verify_receipt_structure` now reports
  them as needing material a receipt cannot carry, naming the function that takes
  it. Its own behaviour is unchanged.
- The fake rail captures a transaction-set root, a path to it and signed
  validations, so its settlement proofs have an empty `missing` list. XRPL still
  names `shamap_path`. `SettlementProof` gains `tx_path`.
- The receipt vectors' `policy_hash` is now a real `PolicyDocument`'s hash rather
  than a digest of a sentence, so `policy.document` and `policy.approval_quorum`
  can be exercised at all. Committed fixtures were regenerated.

### Added — phases 1-3 of this cycle

- **`merkl.core.verify.attestation` — AWS Nitro attestation documents, verified
  offline.** Parses the NSM's COSE_Sign1, walks the certificate chain to the AWS
  Nitro Attestation PKI root embedded in the package (SHA-256
  `641a0321…`, published as a zip whose digest is `8cf60e2b…`), checks the ES384
  signature over a *rebuilt* `Sig_structure`, and reports nine named checks:
  format, chain, certificate validity, signature, freshness, PCR allowlist, debug
  mode, and the two bindings to the receipt. Certificate validity is measured at
  the document's own timestamp rather than at `now` — an NSM leaf certificate
  lives about three hours, and a receipt is read years later. `now` is an
  argument everywhere, so verification is reproducible and `merkl.core` still
  reads no clock.
- **`merkl.core.verify.cbor` — the CBOR profile it needs, stdlib only.**
  Definite lengths, shortest-form heads, no floats, no tags but COSE's, no
  duplicate map keys, bounded depth and element counts. `cbor2` would have been a
  dependency for the auditor, the JS verifier and the enclave image alike, in
  order to accept shapes an attestation document may not contain. The
  deterministic writer is not optional: verifying a COSE_Sign1 means re-encoding
  the `Sig_structure` and checking the signature over *those* bytes.
- **Check 8 runs.** `verify_receipt_structure` takes `attestation_trust` and
  `now`, and holds leaf 3 against the envelope: the attested key must be
  `signer_public_key` and the attested `user_data` must be `policy_hash`. Without
  both, a genuine attestation from any enclave could be stapled to any receipt.
  The allowlist and the moment are arguments, never values read from the receipt.
  A null leaf 3 reports that the receipt *proves* it came from an unattested
  signer, which is a fact rather than a gap.
- **Attestation vectors: three documents AWS actually signed.** From
  `evervault/attestation-doc-validation` (Apache-2.0, commit `10cc232f`), with
  provenance, in `merkl/core/vectors/attestation/`. Seventeen cases including
  tamper cases where the chain does not reach the pinned root, a PCR is edited
  inside the signed payload, the timestamp is moved past the certificate window,
  and a debug-mode enclave is refused. Every document is expired, which is the
  point: only a verifier that takes `now` as an argument can check them at all.
- **`NitroKeystore` and `merkl.signer.attestation`.** The policy key is generated
  inside the enclave from NSM entropy mixed with the process CSPRNG, sealed
  through a two-method `SealingPort` and handed to the parent as a ciphertext;
  later boots open it only if the enclave measures the same. `attestation()`
  asks the NSM for a fresh document on every call, binding the policy public key
  and the current policy hash — read through a callable, so a `policy_update`
  reaches the next attestation on its own. The NSM client is one `ioctl` on
  `/dev/nsm` with CBOR on both sides, so no compiled dependency enters the image
  whose every byte is measured into PCR0.
- **`merkl.signer.vsock` — the same RPC, over the only wire an enclave has.**
  Four bytes of length and then the same JSON. `server.handle_request` is now
  transport-independent and both transports go through it; a test asserts they
  answer byte-identically for the same router.
- **`merkl.adapters.nitro` — KMS with the attestation as the credential.**
  `kms:Decrypt` carrying the enclave's attestation as `Recipient` returns a CMS
  envelope wrapped to an ephemeral key that exists only inside the enclave, so
  the parent proxies the HTTPS and reads nothing. `cryptography` does not do CMS,
  so `cms.py` walks exactly that structure and refuses every other — more than
  one recipient, PKCS#1 v1.5 key transport, `AuthEnvelopedData`, non-minimal or
  indefinite DER lengths. Tested against envelopes `openssl cms` produced. Two
  KMS backends, `kmstool_enclave_cli` and botocore, behind the `[nitro]` extra.
- **`merkl.adapters.signer_nitro`.** A subclass of `DevSignerClient` that adds no
  RPC method — the parent proxy speaks the same contract, so an attested signer
  is a constructor change. It adds `attestation_report()` and `assert_attested()`
  for the question only an attested signer can answer.
- **`nitro/` — the deployment.** Enclave image (installing the rail codec extra,
  because the codec is what makes the policy signature mean something and must be
  measured with the key it protects), parent proxy, and Terraform whose KMS key
  policy conditions `kms:Decrypt` on `kms:RecipientAttestation:PCR0/1/2/8` while
  leaving `kms:Encrypt` unconditioned — that condition key is not evaluated for
  `Encrypt`, and conditioning it would deny the first boot the ability to seal
  the key it just generated. `nitro/README.md` carries the runbook, the threat
  notes, and a table of exactly which artifacts were executed and which were only
  written.
- **`docs/ATTESTATION-VERIFY.md`** — normative for check 8 and for the phase-4
  JavaScript verifier, specified byte by byte.


- **`merkl.core.policy` — the signed policy and the deterministic engine.**
  `PolicyDocument` v1 is hashed and signed over one pre-image under
  `merkl-policy-v1`, so a signature can never be valid for a document with a
  different hash, and a policy update is checked against the admin key the signer
  has *pinned* rather than the key the incoming document nominates.
  `evaluate(intent, policy, state, risk, now)` is a pure function whose output
  serialises byte-for-byte as receipt leaf 2. A denial is a decision with rules
  and a receipt, not an exception. Rule state is an immutable ledger with a
  monotonic sequence: reservations count against a sliding window from the moment
  they exist, settling relabels rather than re-counts, and `reconcile()` compares
  rail history to signer state in both directions.
- **Approval assertions are pinned** (`RECEIPT-SPEC.md` §3.3): WebAuthn passkeys
  and Ed25519 keys, every binary member as hex of the exact bytes, quorum over
  distinct approver ids. `LEFT_pre` is pinned too (§3.2) — LEFT with leaf 2's
  escalation omitted and its outcome set back to `escalate` — so a reader holding
  only the finished receipt can recompute the challenge the approvers signed.
- **Four deferred verification checks now run.** `policy.signature`,
  `intent.matches_settled_fields`, `settlement.anchor_equals_left` and
  `settlement.signed_blob` execute whenever the receipt carries their inputs and
  report `not_implemented` by name when it does not. The settlement leaf gains an
  optional `policy_signature` carrying the exact bytes the policy key signed,
  which is what makes check 7 possible offline; adding an optional member keeps
  the frozen tag. A forger who rebuilds the whole tree consistently still cannot
  produce that signature — three new tamper vectors are receipts where every
  structural check passes and the receipt proves nothing.
- **`merkl.signer` — the co-signer process.** Ed25519 keystore encrypted at rest
  behind a three-method port so a Nitro keystore drops in; agent-signed requests
  with nonce and expiry (`merkl-signer-request-v1`) verified against the key in
  the policy, never the key in the request; sealed, sequenced state that refuses
  to roll back; JSON-RPC over a Unix socket, documented in `docs/SIGNER-RPC.md`
  as the same contract phase 3 speaks over vsock.
- **The anchor placeholder** (`RECEIPT-SPEC.md` §3.4) resolves the ordering
  problem in the split tree. LEFT covers the policy decision, so it cannot exist
  before the signer decides — yet the transaction has to carry it. The adapter
  prepares 32 zero bytes, the signer checks they are untouched, writes LEFT over
  them itself and signs the result, and the adapter reproduces the same bytes
  independently. The signer never parses a rail's binary format to know that the
  memo it authorized is the memo that settles.
- **The signer reads the bytes before signing them.** `merkl.signer.rails`
  decodes the exact payload — after the anchor write — and holds it against the
  intent: transaction type, account, destination, amount (drops for XRP, numeric
  for issued currencies, since XRPL normalises the mantissa), exactly one memo
  whose data is LEFT, and an **allowlist** of fields so `SendMax`, `DeliverMin`,
  `Paths`, `DestinationTag`, `tfPartialPayment` and anything unforeseen are
  findings by construction. The settlement adapter runs in the agent's process,
  so its account of what its bytes encode was the one thing still taken on trust.
  A mismatch is a DENY decision with a `rail.payload_encodes_intent` rule and a
  receipt, and the reservation is released. The codec is resolved at boot from
  the policy's `rail` and the signer refuses to start without one; it loads
  lazily behind the `signer-xrpl` extra so the signer's base stays on
  `merkl.core` and `merkl.shared` alone.
- **`merkl.adapters`** — `fake` (a deterministic in-memory rail that enforces
  2-of-2 quorum and refuses a lone signature with `BAD_QUORUM`), `xrpl`
  (multisigned Payments anchored by memo, treasury bootstrap that installs the
  signer list before disabling the master key and then reads the account back,
  settlement-proof capture from the validations stream), and `signer_dev`
  (SignerPort clients over a socket and in-process).
- **`ReceiptBuilder`** (`merkl/sdk/receipts.py`) — propose → route → co-sign →
  settle → attest. Re-prepares the transaction with the real commitment and
  requires it to equal the bytes the signer signed before submitting; releases
  the reservation when a rail refuses; commits the envelope hash as one
  `transaction` action in the enclosing session, optionally and one-way.
- **`merkl signer serve`, `merkl treasury init --xrpl-testnet`,
  `merkl treasury verify`.** Extras `[xrpl]` and `[signer]`.
- **Scenario suite**: five scenarios (benign payment, prompt-injection drain,
  over-threshold with 2-of-3 approval mixing a passkey and a key, structuring
  across a sliding window, reference mismatch) green against the in-memory rail
  and against XRPL testnet (`MERKL_XRPL_TESTNET=1`, skipped otherwise).
- **New vector file** `approvals.json`: WebAuthn and Ed25519 assertions, valid
  and invalid, plus quorum counting. The three vector receipts now carry real
  Ed25519 policy signatures, anchors equal to their own LEFT and transaction
  hashes that derive from their blobs.

### Changed — phases 1-3 of this cycle

- `Check`, `CheckStatus` and `VerificationResult` moved to `merkl.core.checks`,
  shared by both verifiers. `merkl.core.receipt` re-exports them unchanged.
- `signer.attestation` left `DEFERRED_CHECKS`. Two remain, both phase 4.
- `merkl.signer.server.handle_request` is public and transport-independent.
- `Settlement` gains optional `policy_signature`; `DEFERRED_CHECKS` drops the
  four checks phase 2 implemented, and phase 3 removed a fifth. Two remain:
  `settlement.ledger_inclusion` and `session.log_join`, both phase 4. Committed
  vectors were regenerated for both reasons.
- `PolicyDocument` gains a required `rail` member: a policy that does not say
  which ledger it governs cannot tell the signer which codec to load.
- `merkl.core` now imports `cryptography` — a declared runtime dependency
  already — to *verify* signatures. It still makes none: no private key enters
  the pure core.

- **`merkl.core` — the pure core of Merkl's proof formats.** No HTTP, no
  database, no filesystem, no clock, and no dependency beyond the standard
  library and `merkl.shared`. It holds the Merkle tree and inclusion proofs
  (moved out of merkl-api with byte-identical semantics, plus subtree roots so
  the halves of a receipt tree are addressable), `merkl-leaf-v1` as a function of
  plain fields rather than a server record, and the new co-signer receipt:
  `merkl-receipt-leaf-v1`, Intent v1, the seven-leaf split tree, the envelope,
  selective disclosure and structural verification.
- **`docs/RECEIPT-SPEC.md`** — normative, every byte. Leaf encodings, leaf order,
  the 7-to-8 padding and the LEFT/RIGHT split, the envelope's canonical form, the
  disclosure format, and the verification order with each check marked
  implemented or deferred to a named phase.
- **Test vectors** in `merkl/core/vectors/`: Merkle trees, action leaves, receipt
  leaves, three complete receipts (allowed, denied, escalated-then-approved) and
  22 tamper cases, each naming the exact checks a conforming verifier must fail.
  Plain JSON with lowercase hex and no floats, so a second implementation in
  another language can load the same files. Regenerate with
  `python -m merkl.core.vectors.generate`.

Nothing existing changed: `merkl.shared`, `merkl.sdk`, the hook, the CLI and the
integrations are untouched, and the frozen `merkl-leaf-v1` encoding is pinned
byte-for-byte against merkl-api's own implementation by a committed fixture.

## [0.1.1] - 2026-09-04

### Fixed

- **Claude Code hook lost whole sessions when two notaries were configured.**
  Hook state was keyed on the Claude session id alone, so a machine running the
  hook against both a local dev server and production had the two processes
  share one state file, race to open a session, and then post every later action
  to a session id the other backend had never issued. The 404 failed a bare
  `resp.is_success` check and the action was dropped with no signal — one
  affected workspace recorded 481 `human_input` leaves against 10 `tool_call`s.
  State is now scoped per `(conversation, endpoint, API key)`.
- Hook state is written atomically. Tool calls in one assistant turn run
  concurrently, and a truncated read left the other process with a blank state,
  which opened a duplicate session.
- A session id the notary does not recognise now self-heals: the hook reopens a
  session and retries once, with dependency edges cleared — they pointed at
  leaves in a session that no longer existed.
- Session goal is taken from the `UserPromptSubmit` payload. The session is
  opened before Claude Code flushes the prompt to the transcript, so reading the
  transcript at that moment found nothing and sessions were recorded under the
  placeholder goal `"Claude Code session"`.

### Added

- `MERKL_DEBUG=1` logs rejected posts to stderr. Silence is what let the above
  go unnoticed.
- Hook state files older than seven days are cleaned up. `reset_for_resume()`
  deliberately keeps them past `SessionEnd`, so they accumulated indefinitely.

## [0.1.0] - 2026-09-03

Initial release. Python SDK, Claude Code hook, and `merkl` CLI.
