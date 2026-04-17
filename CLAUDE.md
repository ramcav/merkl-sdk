# merkl-sdk

Thin Python HTTP client for Merkl. This is what agent developers `pip install` to instrument their agents.

## What This Package Does

- `MerklClient` — main entry point (endpoint URL, agent_id, API key)
- `SessionContext` — async context manager for session lifecycle
- `@trace` and `@guardrail` decorators for auto-recording actions (concurrency-safe via `contextvars`)
- `merkl` CLI — `merkl install --claude-code [--global]` writes hooks into `settings.json`
- `HookState` (`merkl/hooks/claude_code.py`) — one tempfile-backed object per Claude Code session, owns session_id, turn rotation, dataflow snippets, sub-agent parent linkage
- Framework integrations: LangChain, OpenAI, Google ADK, CrewAI — all route through `merkl.integrations._common.record_tool_call` so new action fields plumb through one call site
- Shared value objects (`SHA256Hash`, `canonical_hash`, `SessionId`, `ActionId`, `Timestamp`, enums, errors) imported by both SDK and merkl-api

## What This Package Does NOT Do

No domain logic, no Merkle trees, no batching, no Solana, no persistence. Pure HTTP client.

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
from witness.sdk import MerklClient

client = MerklClient(endpoint="http://localhost:8000", agent_id="my-agent", api_key="mk_...")
async with client.session(goal="Process refunds", allowed_tools=["query_db"]) as session:
    result = await session.record_action(tool_name="query_db", input_data="SELECT ...", output_data={...})
    # result includes leaf_index
```

## Testing

```bash
pip install -e ".[dev]"
pytest  # 100 tests
```

## Guidelines

- Keep it thin. Server logic belongs in the merkl-api package.
- `merkl/shared/` is imported by both SDK and merkl-api — changes affect both.
- Framework integrations should end at `record_tool_call()` in `_common.py`, not call `session.record_action()` directly. New action fields flow through one site.
- Input/output hashing must go through `canonical_hash()`. Raw `str()` is non-deterministic for dicts; the SDK and the Claude Code hook must produce identical leaf hashes for the same logical payload.
- The SDK must never import from `merkl_api.*`.
- Dependencies must stay minimal (uuid6, httpx, cryptography). This ships to customers.

## Known Issues

- `@trace` and `@guardrail` decorators only wrap async functions; sync is passthrough
- `@guardrail` runs client-side policy (allowlist or callable); no server-side evaluation yet
