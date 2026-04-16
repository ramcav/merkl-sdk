"""Merkl CLI — install and manage integrations.

Usage:
    merkl install --claude-code            # install hook in .claude/settings.json
    merkl install --claude-code --global   # install in ~/.claude/settings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _ensure_hook(hooks: dict, event: str, command: str, matcher_entry: dict) -> None:
    """Append a hook matcher for `event` if one with the same command isn't already registered."""
    bucket: list[dict] = hooks.setdefault(event, [])
    for matcher in bucket:
        for h in matcher.get("hooks", []):
            if h.get("command") == command:
                return
    bucket.append(matcher_entry)


def _install_claude_code(global_: bool = False) -> None:
    """Write PostToolUse + SessionEnd hook entries into Claude Code's settings.json.

    PostToolUse records every tool call into Merkl. SessionEnd seals the
    Merkl session when the user runs /exit, /clear, or closes the window,
    so the dashboard flips the session out of "Live" immediately instead
    of waiting for the idle timeout.
    """
    if global_:
        settings_path = Path.home() / ".claude" / "settings.json"
        scope = "global"
    else:
        settings_path = Path(".claude") / "settings.json"
        scope = "project"

    settings_path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            print(f"Warning: {settings_path} contains invalid JSON — will overwrite.", file=sys.stderr)

    hook_command = "python -m merkl.hooks.claude_code"
    hook_entry = {"type": "command", "command": hook_command}

    hooks = existing.setdefault("hooks", {})
    _ensure_hook(hooks, "PostToolUse", hook_command, {"matcher": ".*", "hooks": [hook_entry]})
    # SessionEnd payloads have no tool; matcher is omitted per Claude Code
    # docs for non-tool events.
    _ensure_hook(hooks, "SessionEnd", hook_command, {"hooks": [hook_entry]})

    settings_path.write_text(json.dumps(existing, indent=2) + "\n")

    print(f"Merkl hook installed ({scope}): {settings_path}")
    print()
    print("Add to your shell profile (~/.zshrc or ~/.bashrc):")
    print()
    print("  export MERKL_API_KEY=mk_...   # your Merkl API key")
    print()
    print("Optional (only needed for self-hosted):")
    print("  export MERKL_ENDPOINT=https://your-instance.example.com")
    print()
    print("Each Claude Code session will automatically create a Merkl session and")
    print("record every tool call. View results at https://app.merkl.ai")


def _uninstall_claude_code(global_: bool = False) -> None:
    """Remove Merkl hook entries (PostToolUse + SessionEnd) from settings.json."""
    if global_:
        settings_path = Path.home() / ".claude" / "settings.json"
        scope = "global"
    else:
        settings_path = Path(".claude") / "settings.json"
        scope = "project"

    if not settings_path.exists():
        print(f"No settings file found at {settings_path}")
        return

    existing: dict = json.loads(settings_path.read_text())
    hook_command = "python -m merkl.hooks.claude_code"
    hooks = existing.get("hooks", {})

    removed_any = False
    for event in ("PostToolUse", "SessionEnd"):
        bucket = hooks.get(event, [])
        new_matchers = []
        for matcher in bucket:
            new_hooks = [h for h in matcher.get("hooks", []) if h.get("command") != hook_command]
            if len(new_hooks) < len(matcher.get("hooks", [])):
                removed_any = True
            if new_hooks:
                new_matchers.append({**matcher, "hooks": new_hooks})
        hooks[event] = new_matchers

    if not removed_any:
        print("Merkl hook not found in settings.")
        return

    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    print(f"Merkl hook removed ({scope}): {settings_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="merkl",
        description="Merkl SDK — install and manage integrations",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # install
    install_p = sub.add_parser("install", help="Install an integration")
    install_p.add_argument(
        "--claude-code",
        action="store_true",
        help="Install PostToolUse hook for Claude Code",
    )
    install_p.add_argument(
        "--global",
        dest="global_",
        action="store_true",
        help="Write to ~/.claude/settings.json instead of .claude/settings.json",
    )

    # uninstall
    uninstall_p = sub.add_parser("uninstall", help="Remove an integration")
    uninstall_p.add_argument(
        "--claude-code",
        action="store_true",
        help="Remove PostToolUse hook for Claude Code",
    )
    uninstall_p.add_argument(
        "--global",
        dest="global_",
        action="store_true",
        help="Target ~/.claude/settings.json",
    )

    args = parser.parse_args()

    if args.command == "install":
        if args.claude_code:
            _install_claude_code(global_=args.global_)
        else:
            install_p.print_help()
    elif args.command == "uninstall":
        if args.claude_code:
            _uninstall_claude_code(global_=args.global_)
        else:
            uninstall_p.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
