"""Merkl CLI — install integrations, run the signer, prepare disclosures.

Usage:
    merkl install --claude-code            # install hook in .claude/settings.json
    merkl install --claude-code --global   # install in ~/.claude/settings.json
    merkl disclose <action_id>             # package one action's evidence for an auditor
    merkl signer serve --policy p.json     # run the dev co-signer
    merkl treasury init --xrpl-testnet     # fund and lock down a testnet treasury
    merkl treasury verify <address>        # check the signer list and master key
"""

from __future__ import annotations

import argparse
import json
import os
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


def _resolve_api_key(cli_value: str | None) -> str | None:
    """API key for the hook command: flag > env > interactive prompt."""
    if cli_value:
        return cli_value
    if env := os.environ.get("MERKL_API_KEY"):
        return env
    if sys.stdin.isatty():
        entered = input("Merkl API key (mk_..., from your dashboard — enter to skip): ").strip()
        return entered or None
    return None


def _install_claude_code(
    global_: bool = False,
    api_key: str | None = None,
    endpoint: str | None = None,
) -> None:
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
            print(
                f"Warning: {settings_path} contains invalid JSON — will overwrite.",
                file=sys.stderr,
            )

    # sys.executable, not bare "python": the hook must run under the
    # interpreter that actually has merkl installed, and hook commands
    # inherit no shell profile.
    resolved_key = _resolve_api_key(api_key)
    env_prefix = ""
    if resolved_key:
        env_prefix += f"MERKL_API_KEY={resolved_key} "
    if endpoint:
        env_prefix += f"MERKL_ENDPOINT={endpoint} "
    hook_command = f"{env_prefix}{sys.executable} -m merkl.hooks.claude_code"
    hook_entry = {"type": "command", "command": hook_command}

    hooks = existing.setdefault("hooks", {})
    _ensure_hook(hooks, "PostToolUse", hook_command, {"matcher": ".*", "hooks": [hook_entry]})
    # Non-tool events (matcher omitted per Claude Code docs): SessionEnd
    # seals + commits the transcript; UserPromptSubmit records the human's
    # instruction; PermissionRequest/Denied record approval decisions.
    for event in ("SessionEnd", "UserPromptSubmit", "PermissionRequest", "PermissionDenied"):
        _ensure_hook(hooks, event, hook_command, {"hooks": [hook_entry]})

    settings_path.write_text(json.dumps(existing, indent=2) + "\n")

    print(f"Merkl hook installed ({scope}): {settings_path}")
    print()
    if resolved_key:
        print("API key baked into the hook — you're done. Restart Claude Code")
        print("(or run /hooks) and every session records automatically.")
    else:
        print("No API key provided. Add to your shell profile before it records:")
        print()
        print("  export MERKL_API_KEY=mk_...   # from your dashboard")
    print()
    print("View sessions at https://app.merkl.ai")


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
    hooks = existing.get("hooks", {})

    removed_any = False
    for event in (
        "PostToolUse", "SessionEnd", "UserPromptSubmit",
        "PermissionRequest", "PermissionDenied",
    ):
        bucket = hooks.get(event, [])
        new_matchers = []
        for matcher in bucket:
            new_hooks = [
                h for h in matcher.get("hooks", [])
                if "merkl.hooks.claude_code" not in h.get("command", "")
            ]
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
    install_p.add_argument(
        "--api-key", default=None,
        help="API key to bake into the hook (default: $MERKL_API_KEY, else prompt)",
    )
    install_p.add_argument(
        "--endpoint", default=None,
        help="Self-hosted API URL (default: api.merkl.ai, hardcoded in the hook)",
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

    # disclose
    disclose_p = sub.add_parser(
        "disclose", help="Package one action's evidence + verifier for an auditor"
    )
    disclose_p.add_argument("action_id", help="Action to disclose (from dashboard or API)")
    disclose_p.add_argument(
        "--evidence-dir", type=Path, default=None,
        help="Evidence directory (default: $MERKL_EVIDENCE_DIR or ~/.merkl/evidence)",
    )
    disclose_p.add_argument(
        "--endpoint", default=None, help="Merkl API base URL (default: $MERKL_ENDPOINT)"
    )
    disclose_p.add_argument(
        "--api-key", default=None, help="API key (default: $MERKL_API_KEY)"
    )
    disclose_p.add_argument(
        "--out", type=Path, default=None, help="Output folder (default: ./disclosure-<id>)"
    )

    # signer
    signer_p = sub.add_parser("signer", help="Run the Merkl co-signer")
    signer_sub = signer_p.add_subparsers(dest="signer_command", metavar="<subcommand>")
    serve_p = signer_sub.add_parser("serve", help="Serve the signer RPC")
    serve_p.add_argument(
        "--policy", type=Path, required=True, help="Signed policy document (JSON)"
    )
    serve_p.add_argument(
        "--home", type=Path, default=None, help="Keystore and state directory (~/.merkl/signer)"
    )
    serve_p.add_argument(
        "--socket", type=Path, default=None, help="Unix socket to bind (preferred)"
    )
    serve_p.add_argument("--host", default="127.0.0.1", help="Loopback address to bind instead")
    serve_p.add_argument("--port", type=int, default=8787, help="Port for --host")
    serve_p.add_argument(
        "--blocklist", nargs="*", default=[], help="Destinations the risk scorer refuses"
    )

    # treasury
    treasury_p = sub.add_parser("treasury", help="Set up and check a co-signed treasury")
    treasury_sub = treasury_p.add_subparsers(dest="treasury_command", metavar="<subcommand>")
    init_p = treasury_sub.add_parser("init", help="Fund and lock down a treasury")
    init_p.add_argument(
        "--xrpl-testnet", action="store_true", help="Bootstrap on the XRPL testnet"
    )
    init_p.add_argument("--agents", type=int, default=1, help="How many agent keys (default 1)")
    init_p.add_argument("--home", type=Path, default=None, help="Signer keystore directory")
    init_p.add_argument(
        "--wallet-file", type=Path, default=None, help="Where to write seeds (0600)"
    )
    verify_p = treasury_sub.add_parser("verify", help="Check a treasury's flags and signer list")
    verify_p.add_argument("address", help="Treasury account address")

    args = parser.parse_args()

    if args.command == "signer":
        from merkl.cli.signer import serve_command

        if args.signer_command != "serve":
            signer_p.print_help()
            return
        raise SystemExit(
            serve_command(
                policy_path=args.policy,
                home=args.home,
                socket_path=args.socket,
                host=args.host,
                port=args.port,
                blocklist=tuple(args.blocklist),
            )
        )
    elif args.command == "treasury":
        from merkl.cli.treasury import init_command, verify_command

        if args.treasury_command == "init":
            if not args.xrpl_testnet:
                print("only --xrpl-testnet is supported today", file=sys.stderr)
                raise SystemExit(2)
            raise SystemExit(
                init_command(home=args.home, agents=args.agents, wallet_file=args.wallet_file)
            )
        if args.treasury_command == "verify":
            raise SystemExit(verify_command(args.address))
        treasury_p.print_help()
    elif args.command == "disclose":
        from merkl.cli.disclose import disclose

        disclose(
            args.action_id,
            evidence_dir=args.evidence_dir,
            endpoint=args.endpoint,
            api_key=args.api_key,
            out_dir=args.out,
        )
    elif args.command == "install":
        if args.claude_code:
            _install_claude_code(
                global_=args.global_, api_key=args.api_key, endpoint=args.endpoint
            )
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
