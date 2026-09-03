---
name: merkl-install
description: Install Merkl into the user's Claude Code and verify it records a real session, with minimal prompting. Use for first-time setup, reconnect, or "why isn't Merkl recording?".
---

# merkl install

You are driving this install. Do as much as you can yourself; ask the user only for the one thing you cannot get — their API key — and only when you actually need it. After every step, verify before moving on.

Merkl records what an AI agent does, hashes each action into a Merkle tree, and lets anyone verify what happened later. Installing it into Claude Code means registering a hook that fires on every tool call. Full reference: `README.md`.

## Install prompt contract

- Prefer running commands over telling the user to run them.
- The user must do exactly two things you cannot: (1) get an API key from their dashboard, (2) reload hooks (`/hooks` or restart) — Claude Code loads hooks at session start, so a freshly written hook is not live in the current session. Everything else is yours.
- Do not print the API key back to the user or paste it into any file they can commit. It goes into the hook command and shell profile only.
- Verify with a real recorded action, not by assuming the config is correct.

## 1. Install the package

```bash
pip install merkl-sdk
merkl --help
```

If `merkl: command not found` after a successful `pip install`, the package installed into an environment whose scripts are not on `PATH`. Escalate from the actual cause:

- **A pyenv/conda/system Python mismatch** → install with the interpreter Claude Code's hooks will use. `pipx install merkl-sdk` (or `uvx merkl`) puts a stable global `merkl` on `PATH` and is the most robust choice. Prefer it.
- **A project venv** → the install is fine, just not global; either activate that venv or use `pipx`.

Confirm `command -v merkl` prints a path before continuing.

## 2. Get the API key (the one thing you must ask for)

The key authenticates the hook. Only the user can mint it.

- If `MERKL_API_KEY` is already set in the environment, use it — do not ask.
- Otherwise ask the user to: open their Merkl dashboard → create an org if they have not → API Keys → create one → copy the `mk_...` value (shown once). While they do this, wait and re-check; do not move on without it.
- Self-hosted only: also note their API URL for `--endpoint`. The default is `api.merkl.ai`, hardcoded — do not pass `--endpoint` for the hosted service.

## 3. Install the hook

```bash
merkl install --claude-code --global
```

The installer prompts for the API key if `MERKL_API_KEY` is unset and bakes it into the hook command, so no shell-profile editing is needed. If you already have the key, pass it non-interactively:

```bash
merkl install --claude-code --global --api-key mk_...
```

This registers five events (PostToolUse, SessionEnd, UserPromptSubmit, PermissionRequest, PermissionDenied) in the global settings and uses the current interpreter, not a bare `python`. Read back the written settings file and confirm the hook command contains `merkl.hooks.claude_code` and the key.

## 4. Load the hook

Hooks load at session start, so the hook you just wrote is not active in this session. Tell the user to either run `/hooks` once (reloads config) or start a new Claude Code session. You cannot do this for them — `/hooks` is a user UI action.

## 5. Verify it records — do this, do not assume

Fire a synthetic PostToolUse payload through the hook exactly as Claude Code would, then check the session landed. Use the same interpreter the hook uses.

```bash
echo '{"session_id":"merkl-install-check","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":"hi","transcript_path":"/nonexistent"}' \
  | MERKL_API_KEY=<key> python -m merkl.hooks.claude_code
echo "hook exit: $?"
```

Then confirm the server received it:

```bash
curl -s -H "Authorization: Bearer <key>" https://api.merkl.ai/v1/sessions | head -c 400
```

A session with `agent_id` `claude-code` (or the `MERKL_AGENT_ID` you set) and `action_count >= 1` means it works. If you see it, you are done — tell the user their next real Claude Code session records automatically, and point them at their dashboard.

## Troubleshooting — read the error, escalate from there

Do not restart from step 1. Match the symptom:

- **Hook exits 0 but no session appears** → the hook swallows errors (`2>/dev/null || true`), so a silent failure looks like success. Re-run the hook payload *without* the `2>/dev/null || true` suppression to see the real error, then match below.
- **HTTP 401 / "Invalid API key"** → the key is wrong, revoked, or from a different Merkl instance than the endpoint. Re-copy it from the dashboard; confirm the endpoint matches where the key was minted.
- **Connection refused / DNS failure on the endpoint** → for self-hosted, the API URL is wrong or the server is down. For the hosted service, confirm `api.merkl.ai` resolves. Never silently fall back to a different endpoint.
- **`/hooks` shows "0 hooks configured"** → the settings file you wrote is not the one this session reads. Claude Code loads hooks from the config dir for the session's project root; confirm you wrote to the right scope (`--global` writes `~/.claude/settings.json`; a project install writes `<project>/.claude/settings.json`). If the user runs a non-default `CLAUDE_CONFIG_DIR`, write there.
- **Session is created but `action_count` stays 0** → the session opened (create succeeded) but PostToolUse never fired for a real tool. Have the user run any tool (read a file, run a command) in a hook-loaded session, then re-check.
- **Hook command runs `python` and that Python lacks merkl** → an older install wrote a bare `python`. Re-run `merkl install` (it now uses the full interpreter path), or edit the hook command to the absolute path from `command -v python` in the install env.
- **Dev/self-hosted: sessions vanished after a server restart** → the server is running in-memory (no `DATABASE_URL`). That is expected for dev; use Postgres for anything you want to keep.
- **Everything looks right but still nothing** → clear stale hook state and retry: `rm -f "$TMPDIR"/merkl_hookstate_*.json`. Stale state points at session ids the server may not have.

## What "installed" means

- `merkl` on `PATH`, hook registered in the correct settings file with the key baked in, hooks reloaded, and a verification action visible in the dashboard or via the sessions API.
- Nothing about the user's real payloads left their machine: only hashes and tool names go to Merkl; raw data stays in `~/.merkl/evidence/`. If the user wants zero plaintext at all, that is already the default; previews are opt-in via `MERKL_INCLUDE_PREVIEWS=1`.
