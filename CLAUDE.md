# merkl-sdk

Thin Python HTTP client for Merkl. This is what agent developers `pip install` to instrument their agents.

Standalone repository, published to PyPI as `merkl-sdk` (split out of the `ramcav/merkl` monorepo on 2026-09-05). The notary (`ramcav/merkl-api`, private) and the dashboard (`ramcav/merkl-dashboard`, private) live in their own repos. merkl-api depends on the *released* `merkl-sdk`, so a change to `merkl/shared/` reaches the server only through a version bump and release.

## What This Package Does

- `merkl.core` — the pure proof core: Merkle trees and proofs, leaf encodings,
  Intent v1, the co-signer receipt, the signed policy document and the
  deterministic policy engine (see below). No I/O, no clock, no new deps
- `merkl.signer` — the co-signer process: keystore, agent-request auth, relay
  bearer auth for every other RPC method, sealed rule state, the authoritative
  decision flow, JSON-RPC over a Unix socket
- `merkl.adapters` — the edge: `fake` (in-memory rail), `xrpl` (multisigned
  Payments + treasury bootstrap, plus a module-level `history()` that reads
  `account_tx` with no wallet, bounded below by `ledger_index_min` — the
  notary's reconciliation path),
  `signer_dev` / `signer_nitro` (SignerPort clients), `nitro` (KMS sealing and
  the CMS envelope it answers with), `notary` (`HttpNotary`: files a receipt and
  its settlement capture with merkl-api, afterwards and never on the decision path)
- `ReceiptBuilder` (`merkl/sdk/receipts.py`) — propose → route → co-sign →
  settle → attest, joining the enclosing session as one `transaction` action and
  filing the receipt with its `SettlementProof` to the local store and the notary
- `merkl.demo` — the six scenarios end to end (benign, prompt-injection drain,
  over-threshold with 2-of-3 approval, structuring, reference mismatch, the
  agent trades — the last needing a rail with a book, so it is skipped on XRPL
  testnet, which has none),
  rail-agnostic (`FakeEnvironment`, `XrplEnvironment`), rendered to a folder of
  `verify.html` pages checked by both verifiers. `merkl demo` is the CLI entry
  point
- `MerklClient` — main entry point (endpoint URL, agent_id, API key)
- `SessionContext` — async context manager for session lifecycle
- `@trace` and `@guardrail` decorators for auto-recording actions (concurrency-safe via `contextvars`)
- `merkl` CLI — `merkl install --claude-code [--global]` writes hooks into
  `settings.json`; `merkl demo [--xrpl-testnet]` runs the scenarios;
  `merkl policy sign|show` and `merkl signer token add|revoke|list` manage
  policy admin signatures and relay bearer tokens
- `HookState` (`merkl/hooks/claude_code.py`) — one tempfile-backed object per Claude Code session, owns session_id, turn rotation, dataflow snippets, sub-agent parent linkage
- Framework integrations: LangChain, OpenAI, Google ADK, CrewAI — all route through `merkl.integrations._common.record_tool_call` so new action fields plumb through one call site
- Shared value objects (`SHA256Hash`, `canonical_hash`, `SessionId`, `ActionId`, `Timestamp`, enums, errors) imported by both SDK and merkl-api

## What This Package Does NOT Do

`merkl.sdk` is a pure HTTP client: no batching, no persistence, no rail clients.
Domain *formats* live in `merkl.core`; domain *services* (the notary, the log,
checkpoints, anchoring) stay in merkl-api.

## merkl/core — the proof core

Pure by construction: no HTTP, no DB, no filesystem, no clock, no rail client.
Everything is a value object or a function over value objects, so a verifier, a
signer and the server all reach the same conclusion from the same bytes. The one
non-stdlib import is `cryptography`, used to *verify* signatures and never to
make them — no private key enters `merkl.core`.

```
merkl/core/
  canonical.py   the JSON subset receipts may contain + field formats
                 (token, text, hex_digest, instant, decimal_string) and
                 instant arithmetic (parse/format/shift, no clock read)
  crypto.py      ed25519 / ECDSA P-256 verification, hex + base64url,
                 the tagged pre-image shape
  merkle.py      MerkleTree, MerkleProof, subtree_root / subtree_proof
  leaf.py        action_leaf() (merkl-leaf-v1, frozen), receipt_leaf()
  intent.py      Intent v1 (payment, swap), Amount, SwapSell/SwapBuy,
                 IssuedCurrency, Reference
  rail.py        UnsignedTx / SignedTx / SettlementRef / SettlementProof,
                 the 32-byte anchor placeholder, per-rail tx-id rules
  ports.py       SettlementPort, SignerPort, ReceiptStorePort,
                 SettlementProofStorePort, NotaryPort, ApprovalPort,
                 RiskPort, ClockPort (Protocols only)
  policy/
    document.py  PolicyDocument v1, SignedPolicy (merkl-policy-v1), approvers,
                 AdminCredential (ed25519 or webauthn; the legacy
                 admin_public_key field stays byte-identical for policy_hash),
                 optional `network` (one ledger inside `rail`, omitted from the
                 content when unset), and unenforceable_rules() — the rules the
                 engine would sign but never run, which construction refuses
    engine.py    evaluate(intent, policy, state, risk, now) -> Decision
    state.py     LedgerState, StateView, StateStore, reconcile()
    approvals.py ApprovalAssertion (WebAuthn + Ed25519), verify_quorum(),
                 verify_policy_signature() — one path for admins and approvers
  receipt.py     the seven leaves, LEFT/RIGHT/ROOT, Envelope, Receipt,
                 selective disclosure, verify_receipt_structure
  checks.py      Check / CheckStatus / VerificationResult, shared by every
                 verifier (receipt.py re-exports them)
  verify/
    cbor.py        the CBOR profile an attestation uses: definite lengths,
                   shortest-form heads, no floats, no tags but COSE's — reader
                   and deterministic writer, stdlib only
    attestation.py AWS Nitro attestation documents: COSE_Sign1, the chain to the
                   embedded AWS root, ES384, PCR allowlist, receipt bindings
    settlement.py  what a settlement capture proves: the proof is about this tx,
                   the header hashes to its ledger hash, a pinned validator
                   quorum signed it, and only then offline inclusion
    xrpl.py        the real XRPL primitives settlement.py's xrpl rail dispatches
                   to: the transaction SHAMap (build + fold), STValidation and
                   manifest verification (secp256k1 and Ed25519), and
                   pin_validator_list (a published UNL -> a pinned master-key
                   set — merkl xrpl pin-unl's engine). No xrpl-py; pure stdlib
                   plus merkl.core.crypto
    log.py         sessions, action leaves, the merkl-entry-v1 chain, RFC 6962
                   log inclusion, checkpoints, continuations, evidence records
    receipt.py     the whole verdict: every check, the two settlement lines of
                   D10, the level of D9, and the plain-language summary
    render.py      render_verify_html(bundle) -> str, the page merkl-api calls
    verify.html    the standalone page: sentences first, hashes behind expanders
    js/            merkl-verify.js — the same algorithms in JavaScript, published
                   as @merkl-ai/verify. No dependencies, Web Crypto only.
                   cli.mjs is its terminal entry point (npx @merkl-ai/verify /
                   the merkl-verify bin), the same checks merkl verify runs
  vectors/       generate.py, fixtures.py + committed JSON fixtures
    attestation/   three documents AWS actually signed, and 17 cases over them
    bundles/       real merkl-api exports, and mutations of them that must fail
    xrpl/          a real testnet ledger, two validators' real STValidation
                   messages and manifests, the real testnet UNL — and tamper
                   cases over each, for both implementations
```

`merkl/signer/` depends on `merkl.core` and `merkl.shared` alone — no rail
client, no HTTP client, no framework — which is what makes it small enough to
audit and small enough to put inside an enclave in phase 3. The one exception is
`merkl/signer/rails/<rail>.py`, a **verify-only** codec that decodes the payload
the signer is about to sign and holds it against the intent; it loads lazily
behind its own extra (`signer-xrpl`), and nothing else imports it at module
level. The settlement adapter runs in the agent's process, so its account of what
its bytes encode is never taken on trust — see `docs/SIGNER-RPC.md` section 5.

`merkl/signer/relay_auth.py` is the relay bearer credential (`docs/SIGNER-RPC.md`
section 3, "Who may call what"): who may call anything but `propose`, checked
in `merkl.signer.server.RpcRouter` and threaded through both transports (an
HTTP `Authorization` header, or a vsock `auth` frame member the Nitro parent
proxy forwards unchanged). Only a token's SHA-256 is ever stored, and a
failure is *raised* rather than logged — this module obeys the same
"the signer says nothing" rule `tests/signer/test_signer_purity.py` enforces
across all of `merkl/signer/`.

`merkl/signer/` also holds the enclave-side pieces (phase 3): `attestation.py`
talks to `/dev/nsm` over one `ioctl` with CBOR on both sides, `keystore.py` gains
`NitroKeystore`, and `vsock.py` carries the same RPC over the only wire an
enclave has. All of it is stdlib plus `merkl.core` — `boto3` lives in
`merkl.adapters.nitro` behind the `[nitro]` extra, because the signer knows a
two-method `SealingPort` and never which cloud is behind it. `nitro/` at the repo
root holds the enclave image, the parent proxy and the Terraform; it is not part
of the wheel.

`docs/RECEIPT-SPEC.md` is normative for all of it, with
`docs/ATTESTATION-VERIFY.md` normative for check 8 in particular and
`docs/INTERFACES-P4.md` recording what merkl-api and merkl-dashboard build
against. Rules:

- **Never change `merkl.shared.hashing`.** One canonicalization, reused.
- **`merkl.core` imports nothing from `merkl.sdk`** (or from `merkl_api`, ever).
  The dependency runs one way: sdk, signer and adapters may import core.
- **No floats in a receipt, at any depth.** Amounts are decimal strings and
  arithmetic goes through `decimal`. `ensure_canonical_content` enforces it.
- **Every hashed structure carries a domain tag**, documented in the spec before
  or with the code. `merkl-leaf-v1`, `merkl-receipt-leaf-v1`, `merkl-receipt-v1`
  are frozen: a change of fields or encoding means a new tag.
- **Verification never hides what it did not check.** Checks a phase has not
  implemented are reported by name as `not_implemented`, never as a pass, and
  live in `DEFERRED_CHECKS` with the phase that will implement them. A check
  whose *inputs* are absent also reports `not_implemented` by name — the absence
  of data is never reported as agreement.
- **The signer never accepts a decision from the caller** (plan D1). If you find
  yourself adding a parameter through which one could be suggested, stop.
- **The signer never signs bytes it has not decoded.** A rail codec is an
  allowlist of fields, not a blocklist of dangerous ones; a mismatch is a DENY
  decision with a `rail.payload_encodes_intent` rule and a receipt, never an
  exception. Adding a rail means adding its codec, or the signer refuses to boot.
- **A policy may not carry a rule the engine would never run.** The engine reads
  caps and thresholds first-match-per-asset and windows all-matches-per-asset,
  so a duplicate would be signed into `policy_hash` and silently ignored.
  `PolicyDocument` refuses one; `@merkl-ai/verify` reports one as a
  `policy.document` failure with the same sentence. If you add a rule list,
  extend `unenforceable_rules` in the same commit — in both implementations.
- **Vectors are the contract with the JS verifier.** Plain JSON, lowercase hex,
  no floats, no Python-specific types. After touching any encoding, run
  `python -m merkl.core.vectors.generate` and commit the diff; the suite fails if
  the committed files are stale. Two vector sets have their own generators
  because their inputs are files on disk rather than Merkl's own encodings:
  `python -m merkl.core.vectors.attestation.generate` (documents AWS signed) and
  `python -m merkl.core.vectors.bundles.generate` (exports merkl-api produced).
- **Two implementations, one spec, one vector set.** `merkl.core.verify` and
  `merkl/core/verify/js/merkl-verify.js` must report the same check names with
  the same statuses and reach the same verdict from the same material.
  `verdicts.json` records each verdict beside the arguments it was reached from,
  and both suites assert against it. A disagreement is a bug in one of them,
  never "a difference between the Python and the JavaScript". Check names and
  statuses are the contract; prose detail strings are not.
- **A verdict is never one boolean.** `ok` (nothing contradicted) and `complete`
  (every check ran) are separate lines, and for a settled receipt so are
  transaction authorization and ledger inclusion (plan D10). Above them, the
  level of plan D9. Above that, five plain sentences — a receipt whose meaning
  only survives as hex has not been verified by anybody who matters.
- **The page must open from a USB stick.** `verify.html` is one self-contained
  file with no external reference, and the verifier is inlined as a *classic*
  script because Chrome refuses module scripts on `file://`. The module on disk
  stays a real ES module for npm and for the Node suite; `render.py` strips the
  `export` keywords when inlining.
- **An attestation is checked against what the *verifier* pinned.** The PCR
  allowlist, the trust anchor and `now` are arguments, never values read out of
  the receipt. No receipt gets to nominate the measurements it should be judged
  against, and an empty allowlist reports `not_implemented` rather than passing.
- **Never fetch a trust anchor at verification time.** The AWS Nitro root is
  embedded in `merkl/core/verify/attestation.py` with its fingerprint. A verifier
  that downloads its own root trusts whoever answered the request.
- `merkl-leaf-v1` byte-identity with merkl-api is pinned by
  `tests/core/test_action_leaf_identity.py` against a fixture generated by
  merkl-api's own code (`tests/core/reference/gen_merkl_api_reference.py`, run
  with merkl-api's interpreter). The SDK test must never import `merkl_api`.

## merkl/demo — the six scenarios, as pages

Not a mock of anything: a real `SignerEngine`, a real encrypted keystore, real
signed approvals, against a swappable rail. Ships in the wheel — `merkl demo`
is a real customer-facing entry point, not a dev-only script.

```
merkl/demo/
  rig.py         one signer, one keystore, one policy, wired the way a real
                 deployment is; every key derived from a public label so a run
                 replays byte-identically
  scenarios.py   the six scenarios, rail-agnostic over an Environment
                 (FakeEnvironment, XrplEnvironment); require() raises
                 ScenarioError rather than asserting, so a claim can't
                 disappear under python -O
  pages.py       scenario -> verify.html -> both verifiers, to a folder;
                 PageReport.agreed is true only when both ran and both passed
  xrpl_env.py    the same scenarios against XRPL testnet (all but the trade,
                 which needs a book the public testnet does not have); bootstrap is
                 cached under ~/.merkl (same wallet files merkl treasury init
                 and tests/scenarios/test_xrpl_testnet.py use) so a second run
                 does not re-drain the faucet
```

## Key Files

- `merkl/sdk/client.py` — `MerklClient`: creates sessions, holds transport
- `merkl/sdk/session_context.py` — `SessionContext`: async with, `record_action()`, auto-close; binds itself to the `_current_session` contextvar on enter
- `merkl/sdk/transport.py` — `AsyncTransport`: httpx with retry + buffering
- `merkl/sdk/receipt_store.py` — `LocalReceiptStore`: `~/.merkl/receipts/{id}.json`
  (`$MERKL_RECEIPT_DIR`), the receipt *and* its settlement proof in one file, in
  the shape `merkl disclose` and `merkl receipt show` read. A `ReceiptStorePort`
  and a `SettlementProofStorePort`; the latter is probed for, never assumed, so
  an older store keeps working
- `merkl/adapters/notary.py` — `HttpNotary`: `POST /v1/receipts` with
  `settlement_proof` inline, and `POST /v1/receipts/{id}/settlement-proof` for a
  capture that completed late. Filing never raises at the payer
- `merkl/sdk/decorators.py` — `@trace`, `@guardrail` + `set_current_session` / `reset_current_session` backed by `contextvars`
- `merkl/integrations/_common.py` — `record_tool_call()` shared by every framework adapter
- `merkl/integrations/` — langchain.py, openai.py, google_adk.py, crewai.py
- `merkl/hooks/claude_code.py` — Claude Code PostToolUse + SessionEnd hook; `HookState` class owns all per-session scratch state
- `merkl/cli/main.py` — the CLI: `verify`, `receipt show`, `disclose`, `approve`,
  `reject`, `reconcile`, `install`, `signer serve|token`, `policy sign|show`,
  `treasury init --xrpl-testnet|--xrpl-mainnet [--trust CODE.issuer]`, `demo`
- `merkl/cli/verify.py` — `merkl verify` over a receipt, a bundle or a rendered
  verify.html; exit 0 nothing contradicted, 1 contradicted, 2 unreadable
- `merkl/cli/demo.py` — `merkl demo`: fake rail always, XRPL testnet with
  `--xrpl-testnet` / `MERKL_XRPL_TESTNET=1`; writes a folder of `verify.html`
  and exits non-zero if a page does not verify cleanly
- `merkl/cli/policy.py` — `merkl policy sign` (the non-browser admin path: an
  Ed25519 key over `policy_hash`, in the same `ApprovalAssertion` shape a
  WebAuthn admin's ceremony produces) and `merkl policy show` (a document
  rendered in words)
- `merkl/cli/signer.py` — `merkl signer serve` (loads `relay-tokens.json` from
  `--home` if present; resolves the keystore passphrase from
  `$MERKL_SIGNER_PASSPHRASE` or a prompt and never writes one; refuses to start
  when `--rail-endpoint`/`$MERKL_RAIL_ENDPOINT` names a different chain than the
  policy's `network`) and `merkl signer token add|revoke|list`
- `merkl/cli/xrpl_unl.py` — `merkl xrpl pin-unl <url|file>`: audits a published
  validator list and writes the pinned master-key set (§ verify.py's
  `--validator`, `merkl.core.verify.xrpl.pin_validator_list`)
- `merkl/cli/receipt.py`, `merkl/cli/approve.py`, `merkl/cli/reconcile.py`
- `merkl/demo/scenarios.py`, `merkl/demo/pages.py`, `merkl/demo/xrpl_env.py` —
  the six scenarios, the page-writer, and the XRPL testnet environment
- `merkl/shared/hashing.py` — `SHA256Hash`, `canonical_hash()`, `canonical_bytes()` (deterministic JSON-sorted-keys hashing shared by SDK, hook, and server-side leaf verification)
- `merkl/core/verify/attestation.py` — the attestation verifier and the embedded AWS Nitro root
- `merkl/signer/vsock.py` — the length-prefixed JSON framing the enclave speaks
- `nitro/README.md` — build, PCR pinning, runbook, threat notes, and what was executed versus only written
- `merkl/shared/` — ids.py, timestamps.py, enums.py, errors.py, events.py

## Usage

```python
from merkl.sdk import MerklClient

client = MerklClient(endpoint="http://localhost:8000", agent_id="my-agent", api_key="mk_...")
async with client.session(goal="Process refunds", allowed_tools=["query_db"]) as session:
    result = await session.record_action(tool_name="query_db", input_data="SELECT ...", output_data={...})
    # result includes leaf_index
```

## Testing

```bash
uv pip install -p .venv/bin/python -e ".[dev,xrpl,signer,signer-xrpl]"
pytest                                          # 1598 tests, 10 skipped
npm test                                        # 257 JS tests, node --test, no bundler
mypy --strict merkl/core merkl/signer merkl/adapters merkl/sdk/receipts.py merkl/sdk/receipt_store.py nitro merkl/demo merkl/cli
ruff check merkl/ tests/
ruff format --check merkl/ tests/
python -m merkl.core.vectors.generate --check              # fixtures are current
python -m merkl.core.vectors.attestation.generate --check  # and the attestation ones
python -m merkl.core.vectors.bundles.generate --check      # and the bundle ones
python -m merkl.core.vectors.xrpl.generate --check          # and the xrpl ones

# the five scenarios, rendered and double-verified, on the fake rail
merkl demo

# XRPL testnet: opt-in, funds from the faucet the first time, submits real
# transactions, then reuses the treasury cached under ~/.merkl
MERKL_XRPL_TESTNET=1 pytest tests/scenarios/test_xrpl_testnet.py -v -s
MERKL_XRPL_TESTNET=1 pytest tests/demo/test_xrpl_demo.py -v -s
MERKL_XRPL_TESTNET=1 merkl demo --xrpl-testnet
```

## Releasing

```bash
# bump the version in BOTH pyproject.toml and merkl/core/verify/js/package.json,
# add a CHANGELOG.md section, commit, then:
git tag v0.2.0 && git push origin v0.2.0
```

`CHANGELOG.md` carries a drafted `[0.2.0]` section already (the co-signer:
scenarios, `merkl demo`, the README rewrite); `pyproject.toml` and
`merkl/core/verify/js/package.json` are still `0.1.1` until that bump actually
happens — drafting the notes is not cutting the release.

The tag is the release decision: `.github/workflows/release.yml` refuses a tag that disagrees with `pyproject.toml` **or** with `@merkl-ai/verify`'s `package.json`, runs both suites and all three vector checks, builds, publishes to PyPI via Trusted Publishing (OIDC, gated by the `pypi` environment) and `@merkl-ai/verify` to npm with provenance (gated by the `npm` environment), and creates a GitHub Release from the matching CHANGELOG section. The two packages are versioned in lockstep because they are two implementations of one spec (plan D19): a reader holding one has to be able to assume the other agrees with it. `examples/` holds runnable demo agents against a local notary; `docs/adr/` records the shared-kernel design decisions.

## Guidelines

- Keep the client thin. Server logic belongs in the merkl-api package; proof
  formats belong in `merkl/core/` (see its rules above).
- `merkl/shared/` is imported by both the SDK and the merkl-api server (via the PyPI release) — changes affect both, and `canonical_hash` / leaf encodings are proof-format-critical. Bump the version and release before merkl-api can pick a change up.
- Framework integrations should end at `record_tool_call()` in `_common.py`, not call `session.record_action()` directly. New action fields flow through one site.
- Input/output hashing must go through `canonical_hash()`. Raw `str()` is non-deterministic for dicts; the SDK and the Claude Code hook must produce identical leaf hashes for the same logical payload.
- The SDK must never import from `merkl_api.*`.
- Dependencies must stay minimal (uuid6, httpx, cryptography). This ships to
  customers. `merkl.core` uses only the standard library, `merkl.shared` and
  `cryptography` (verification only); `xrpl-py` lives behind the `[xrpl]` extra
  and is imported by `merkl.adapters.xrpl` and nothing else.
- **Never print or log a seed, a passphrase or a private key**, and add the
  gitignore entry before writing any file that could hold one. The same applies
  to the parent proxy's request and response bodies, which carry destinations,
  decisions and signatures: it logs method names and status codes.

## Known Issues

- `@trace` and `@guardrail` decorators only wrap async functions; sync is passthrough
- `@guardrail` runs client-side policy (allowlist or callable); no server-side evaluation yet
