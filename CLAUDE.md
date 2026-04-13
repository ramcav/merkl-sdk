# merkl-sdk

Thin Python HTTP client for Merkl. This is what agent developers `pip install` to instrument their agents.

## What This Package Does

- `MerklClient` — main entry point (endpoint URL, agent_id, API key)
- `SessionContext` — async context manager for session lifecycle
- `@trace` and `@guardrail` decorators for auto-recording actions
- Framework integrations: LangChain, OpenAI, Google ADK, CrewAI
- Shared value objects (SHA256Hash, SessionId, ActionId, Timestamp, enums, errors) imported by both SDK and merkl-api

## What This Package Does NOT Do

No domain logic, no Merkle trees, no batching, no Solana, no persistence. Pure HTTP client.

## Key Files

- `merkl/sdk/client.py` — MerklClient: creates sessions, holds transport
- `merkl/sdk/session_context.py` — SessionContext: async with, record_action(), auto-close
- `merkl/sdk/transport.py` — AsyncTransport: httpx with retry + buffering
- `merkl/sdk/decorators.py` — @trace, @guardrail decorators
- `merkl/integrations/` — langchain.py, openai.py, google_adk.py, crewai.py
- `merkl/shared/` — hashing.py, ids.py, timestamps.py, enums.py, errors.py, events.py

## Usage

```python
from witness.sdk import MerklClient

client = MerklClient(endpoint="http://localhost:8000", agent_id="my-agent", api_key="mk_...")
async with client.session(goal="Process refunds", allowed_tools=["query_db"]) as session:
    result = await session.record_action(tool_name="query_db", input_data="SELECT ...", output_data={...})
    # result includes batch_id and leaf_index
```

## Testing

```bash
pip install -e ".[dev]"
pytest  # 66 tests
```

## Guidelines

- Keep it thin. Server logic belongs in the merkl-api package.
- `merkl/shared/` is imported by both SDK and merkl-api — changes affect both.
- Framework integrations follow the same pattern: intercept tool calls → session.record_action().
- The SDK must never import from `merkl_api.*`.
- Dependencies must stay minimal (uuid6, httpx, cryptography). This ships to customers.

## Known Issues

- `@trace` decorator only works for async functions; sync is passthrough
- `@guardrail` decorator only checks tool allowlist, doesn't call server-side evaluation
- `_current_session` global is not thread-safe (should use contextvars)
