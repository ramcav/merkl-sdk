# merkl-sdk

Thin Python HTTP client for Merkl. This is what agent developers `pip install` to instrument their agents.

Standalone repository, published to PyPI as `merkl-sdk` (split out of the `ramcav/merkl` monorepo on 2026-09-05). The notary (`ramcav/merkl-api`, private) and the dashboard (`ramcav/merkl-dashboard`, private) live in their own repos. merkl-api depends on the *released* `merkl-sdk`, so a change to `merkl/shared/` reaches the server only through a version bump and release.

## What This Package Does

- `merkl.core` — the pure proof core: Merkle trees and proofs, leaf encodings,
  Intent v1, the co-signer receipt, the signed policy document and the
  deterministic policy engine (see below). No I/O, no clock, no new deps
- `merkl.signer` — the co-signer process: keystore, agent-request auth, sealed
  rule state, the authoritative decision flow, JSON-RPC over a Unix socket
- `merkl.adapters` — the edge: `fake` (in-memory rail), `xrpl` (multisigned
  Payments + treasury bootstrap), `signer_dev` (SignerPort clients)
- `ReceiptBuilder` (`merkl/sdk/receipts.py`) — propose → route → co-sign →
  settle → attest, joining the enclosing session as one `transaction` action
- `MerklClient` — main entry point (endpoint URL, agent_id, API key)
- `SessionContext` — async context manager for session lifecycle
- `@trace` and `@guardrail` decorators for auto-recording actions (concurrency-safe via `contextvars`)
- `merkl` CLI — `merkl install --claude-code [--global]` writes hooks into `settings.json`
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
  intent.py      Intent v1 (payment), Amount, IssuedCurrency, Reference
  rail.py        UnsignedTx / SignedTx / SettlementRef / SettlementProof,
                 the 32-byte anchor placeholder, per-rail tx-id rules
  ports.py       SettlementPort, SignerPort, ReceiptStorePort, ApprovalPort,
                 RiskPort, ClockPort (Protocols only)
  policy/
    document.py  PolicyDocument v1, SignedPolicy (merkl-policy-v1), approvers
    engine.py    evaluate(intent, policy, state, risk, now) -> Decision
    state.py     LedgerState, StateView, StateStore, reconcile()
    approvals.py ApprovalAssertion (WebAuthn + Ed25519), verify_quorum()
  receipt.py     the seven leaves, LEFT/RIGHT/ROOT, Envelope, Receipt,
                 selective disclosure, verify_receipt_structure
  vectors/       generate.py, fixtures.py + committed JSON fixtures
```

`merkl/signer/` depends on `merkl.core` and `merkl.shared` alone — no rail
client, no HTTP client, no framework — which is what makes it small enough to
audit and small enough to put inside an enclave in phase 3.
`docs/SIGNER-RPC.md` is its contract, and section 4 states what it cannot yet
verify.

`docs/RECEIPT-SPEC.md` is normative for all of it. Rules:

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
- **Vectors are the contract with the JS verifier.** Plain JSON, lowercase hex,
  no floats, no Python-specific types. After touching any encoding, run
  `python -m merkl.core.vectors.generate` and commit the diff; the suite fails if
  the committed files are stale.
- `merkl-leaf-v1` byte-identity with merkl-api is pinned by
  `tests/core/test_action_leaf_identity.py` against a fixture generated by
  merkl-api's own code (`tests/core/reference/gen_merkl_api_reference.py`, run
  with merkl-api's interpreter). The SDK test must never import `merkl_api`.

## Key Files

- `merkl/sdk/client.py` — `MerklClient`: creates sessions, holds transport
- `merkl/sdk/session_context.py` — `SessionContext`: async with, `record_action()`, auto-close; binds itself to the `_current_session` contextvar on enter
- `merkl/sdk/transport.py` — `AsyncTransport`: httpx with retry + buffering
- `merkl/sdk/decorators.py` — `@trace`, `@guardrail` + `set_current_session` / `reset_current_session` backed by `contextvars`
- `merkl/integrations/_common.py` — `record_tool_call()` shared by every framework adapter
- `merkl/integrations/` — langchain.py, openai.py, google_adk.py, crewai.py
- `merkl/hooks/claude_code.py` — Claude Code PostToolUse + SessionEnd hook; `HookState` class owns all per-session scratch state
- `merkl/cli/main.py` — `merkl install --claude-code` CLI
- `merkl/shared/hashing.py` — `SHA256Hash`, `canonical_hash()`, `canonical_bytes()` (deterministic JSON-sorted-keys hashing shared by SDK, hook, and server-side leaf verification)
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
uv pip install -p .venv/bin/python -e ".[dev,xrpl,signer]"
pytest                                          # 771 tests, 7 skipped
mypy --strict merkl/core merkl/signer merkl/adapters merkl/sdk/receipts.py
ruff check merkl/core merkl/signer merkl/adapters tests/core tests/signer
python -m merkl.core.vectors.generate --check   # fixtures are current

# XRPL testnet: opt-in, funds from the faucet, submits real transactions
MERKL_XRPL_TESTNET=1 pytest tests/scenarios/test_xrpl_testnet.py -v -s
```

## Releasing

```bash
# bump version in pyproject.toml, add a CHANGELOG.md section, commit, then:
git tag v0.1.2 && git push origin v0.1.2
```

The tag is the release decision: `.github/workflows/release.yml` refuses a tag that disagrees with `pyproject.toml`, runs the suite, builds, publishes to PyPI via Trusted Publishing (OIDC, gated by the `pypi` environment), and creates a GitHub Release from the matching CHANGELOG section. `examples/` holds runnable demo agents against a local notary; `docs/adr/` records the shared-kernel design decisions.

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
  gitignore entry before writing any file that could hold one.

## Known Issues

- `@trace` and `@guardrail` decorators only wrap async functions; sync is passthrough
- `@guardrail` runs client-side policy (allowlist or callable); no server-side evaluation yet
