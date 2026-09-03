# merkl-sdk

The accountability layer for AI agents. Every action is hashed on your machine and committed to a signed, append-only log — independently verifiable proof of what happened. Raw payloads stay on disk; the notary only ever sees hashes, tool names, and metadata.

Homepage: [merkl.ai](https://merkl.ai) · Dashboard: [app.merkl.ai](https://app.merkl.ai)

## Install (Claude Code)

```bash
pip install merkl-sdk
merkl install --claude-code --global
```

The installer asks for an API key (`mk_...` from [app.merkl.ai](https://app.merkl.ai)) and wires Claude Code. Restart Claude Code or run `/hooks`. After that, every session records automatically.

To have the agent do the install for you, point it at `INSTALL.md`.

## Python

```python
from merkl.sdk import MerklClient

client = MerklClient(
    endpoint="https://api.merkl.ai",
    agent_id="my-agent",
    api_key="mk_...",
)
async with client.session(goal="Process refunds") as session:
    await session.record_action(
        tool_name="query_db",
        input_data="SELECT ...",
        output_data={"rows": 42},
    )
```

The session seals on exit. Plaintext previews are off by default (`include_previews=True` to send them). The Claude Code hook is the same: opt in with `MERKL_INCLUDE_PREVIEWS=1`.

LangChain, OpenAI, CrewAI, and Google ADK adapters live in `merkl.integrations.*`. They work; Claude Code is the supported launch path.

## Disclose

```bash
merkl disclose <action_id>
```

Writes a folder with `verify.html` and one-line `evidence.jsonl`. An auditor opens the page offline — no account, nothing to install.

## Environment

| Variable | What |
|---|---|
| `MERKL_API_KEY` | API key (`mk_...`) |
| `MERKL_ENDPOINT` | API URL (default `https://api.merkl.ai`) |
| `MERKL_AGENT_ID` | Label in the dashboard (default `claude-code` for the hook) |
| `MERKL_INCLUDE_PREVIEWS` | `1` to send short plaintext previews |
| `MERKL_EVIDENCE_DIR` | Local evidence log (default `~/.merkl/evidence/`; `off` to disable) |

## Development

```bash
pip install -e ".[dev]"
pytest
```
