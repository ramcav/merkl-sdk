"""Merkl CLI — verify, disclose, approve, reconcile, and run the signer.

Usage:
    merkl verify <file>                    # check a receipt, bundle or verify.html offline
    merkl receipt show <id|file>           # read one receipt in plain language
    merkl disclose <action_id> [--leaves]  # package evidence and a verifier for an auditor
    merkl approve <challenge>              # sign an escalation with a local Ed25519 key
    merkl reject <challenge>               # refuse one, signed, because refusals are evidence
    merkl reconcile --treasury <id>        # outflows against receipts, both directions
    merkl install --claude-code            # install hook in .claude/settings.json
    merkl signer serve --policy p.json     # run the dev co-signer
    merkl treasury init --xrpl-testnet     # keys, ledger, agent bundle, in one run
    merkl treasury enrol --enrol T --notary U  # re-send an enrolment that failed
    merkl treasury verify <address>        # check the signer list and master key
    merkl xrpl pin-unl <url|file> -o u.json  # audit a validator list, pin its master keys
    merkl demo [--xrpl-testnet]            # run the five scenarios, write pages to open

Every verification command is offline. Trust anchors — the PCR allowlist, the
validator key set, the policy document, the admin key — are flags, never values
read out of the material being checked, and a flag nobody passed produces a named
unchecked line rather than a pass.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

HOME_HELP = (
    "Everything this signer owns: keystore, seeds, relay tokens, policy "
    "(default: $MERKL_HOME, else ~/.merkl/signer)"
)

MAINNET_CONFIRMATION = "disable the master key on mainnet"
"""Repeated here for the help text alone; ``merkl.cli.treasury`` is normative."""


def _add_enrolment_flags(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    """``--enrol``/``--notary``/``--agent-dir``/``--bundle-to-notary``, shared by two commands."""
    parser.add_argument(
        "--enrol",
        default=None,
        required=required,
        metavar="TOKEN",
        help="The one-shot enrolment token the dashboard printed (enr_…)",
    )
    parser.add_argument(
        "--notary",
        default=None,
        required=required,
        metavar="URL",
        help="The notary to enrol with (https://api.merkl.ai)",
    )
    parser.add_argument(
        "--agent-dir",
        type=Path,
        default=None,
        help="Where to write the agent bundle (default: /agent if it exists, "
        "else <home>/agents/<id>/bundle)",
    )
    parser.add_argument(
        "--bundle-to-notary",
        action="store_true",
        help="Send the agent bundle to the notary instead of writing it, for a signer "
        "Merkl runs. The dashboard hands it to the customer once.",
    )


def _ensure_hook(
    hooks: dict[str, Any], event: str, command: str, matcher_entry: dict[str, Any]
) -> None:
    """Append a hook matcher for `event` if one with the same command isn't already registered."""
    bucket: list[dict[str, Any]] = hooks.setdefault(event, [])
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

    existing: dict[str, Any] = {}
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

    existing: dict[str, Any] = json.loads(settings_path.read_text())
    hooks = existing.get("hooks", {})

    removed_any = False
    for event in (
        "PostToolUse",
        "SessionEnd",
        "UserPromptSubmit",
        "PermissionRequest",
        "PermissionDenied",
    ):
        bucket = hooks.get(event, [])
        new_matchers = []
        for matcher in bucket:
            new_hooks = [
                h
                for h in matcher.get("hooks", [])
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
        description="Merkl — record what an agent did, and let anyone check it",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # verify
    verify_p = sub.add_parser(
        "verify", help="Check a receipt, a proof bundle or a verify.html, offline"
    )
    verify_p.add_argument("file", type=Path, help="receipt.json, bundle.json or verify.html")
    verify_p.add_argument("--json", dest="as_json", action="store_true", help="Structured output")
    verify_p.add_argument("--all", action="store_true", help="List the checks that passed too")
    verify_p.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero when a check could not run, not only when one failed",
    )
    verify_p.add_argument("--policy", type=Path, help="The signed policy document, by hash")
    verify_p.add_argument("--admin-key", help="Hex Ed25519 key the policy must be signed by")
    verify_p.add_argument("--proof", type=Path, help="A settlement proof captured at settlement")
    verify_p.add_argument("--evidence", type=Path, help="Disclosed evidence records (.jsonl)")
    verify_p.add_argument(
        "--pcr",
        action="append",
        metavar="N=HEX",
        help="Pin a PCR the enclave must report. Repeatable. Without one, the "
        "attestation check reports unchecked rather than passing.",
    )
    verify_p.add_argument(
        "--validator",
        action="append",
        metavar="NAME=HEX",
        help="Pin a validator key. Repeatable. Use NAME= with no key for a validator "
        "whose signatures this capture cannot carry.",
    )
    verify_p.add_argument("--quorum", type=int, default=0, help="Validators that must agree")
    verify_p.add_argument("--now", help="The moment to judge the attestation at (ISO 8601)")
    verify_p.add_argument("--max-age", type=int, help="Freshness bound for the attestation")

    # receipt
    receipt_p = sub.add_parser("receipt", help="Read receipts")
    receipt_sub = receipt_p.add_subparsers(dest="receipt_command", metavar="<subcommand>")
    show_p = receipt_sub.add_parser("show", help="Print one receipt in plain language")
    show_p.add_argument("ref", help="Receipt id or path to a receipt JSON file")
    show_p.add_argument("--store", type=Path, help="Local receipt directory")
    show_p.add_argument("--endpoint", help="Notary base URL (default: $MERKL_ENDPOINT)")
    show_p.add_argument("--api-key", help="API key (default: $MERKL_API_KEY)")
    show_p.add_argument("--leaves", action="store_true", help="Print each leaf's content")
    show_p.add_argument("--json", dest="as_json", action="store_true", help="Structured output")

    # approve / reject
    for name, blurb in (
        ("approve", "Sign an escalation challenge with a local Ed25519 key"),
        ("reject", "Refuse an escalation, signed — rejections are evidence too"),
    ):
        p = sub.add_parser(name, help=blurb)
        p.add_argument("challenge", help="The 32-byte challenge, hex (LEFT_pre)")
        p.add_argument("--approver", help="Your id in the policy (default: $MERKL_APPROVER_ID)")
        p.add_argument("--key", dest="key_path", type=Path, help="Ed25519 seed file, hex, 0600")
        p.add_argument("--socket", dest="socket_path", type=Path, help="Signer Unix socket")
        p.add_argument("--host", help="Signer host, instead of a socket")
        p.add_argument("--port", type=int, default=8787, help="Signer port for --host")
        p.add_argument("--json", dest="as_json", action="store_true", help="Structured output")
        p.add_argument(
            "--relay-token",
            help="Relay bearer token (default: $MERKL_RELAY_TOKEN). Only needed once the "
            'signer has relay tokens configured (docs/SIGNER-RPC.md, "Who may call what")',
        )

    # reconcile
    reconcile_p = sub.add_parser(
        "reconcile", help="Match treasury outflows to receipts, in both directions"
    )
    reconcile_p.add_argument("--treasury", required=True, help="Treasury account")
    reconcile_p.add_argument(
        "--history", type=Path, help="JSON array of validated outflows from the rail"
    )
    reconcile_p.add_argument("--store", type=Path, help="Local receipt directory")
    reconcile_p.add_argument("--endpoint", help="Notary base URL (default: $MERKL_ENDPOINT)")
    reconcile_p.add_argument("--api-key", help="API key (default: $MERKL_API_KEY)")
    reconcile_p.add_argument(
        "--json", dest="as_json", action="store_true", help="Structured output"
    )

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
        "--api-key",
        default=None,
        help="API key to bake into the hook (default: $MERKL_API_KEY, else prompt)",
    )
    install_p.add_argument(
        "--endpoint",
        default=None,
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
        "--evidence-dir",
        type=Path,
        default=None,
        help="Evidence directory (default: $MERKL_EVIDENCE_DIR or ~/.merkl/evidence)",
    )
    disclose_p.add_argument(
        "--endpoint", default=None, help="Merkl API base URL (default: $MERKL_ENDPOINT)"
    )
    disclose_p.add_argument("--api-key", default=None, help="API key (default: $MERKL_API_KEY)")
    disclose_p.add_argument(
        "--out", type=Path, default=None, help="Output folder (default: ./disclosure-<id>)"
    )
    disclose_p.add_argument(
        "--leaves",
        default=None,
        help="Comma-separated receipt leaves to reveal (instruction, intent, "
        "policy_decision, signer_attestation, settlement, result, reasoning). "
        "Every other leaf ships as a hash only.",
    )
    disclose_p.add_argument(
        "--receipt-dir", type=Path, default=None, help="Local receipt directory"
    )

    # signer
    signer_p = sub.add_parser("signer", help="Run the Merkl co-signer")
    signer_sub = signer_p.add_subparsers(dest="signer_command", metavar="<subcommand>")
    serve_p = signer_sub.add_parser("serve", help="Serve the signer RPC")
    serve_p.add_argument(
        "--policy", type=Path, required=True, help="Signed policy document (JSON)"
    )
    serve_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)
    serve_p.add_argument(
        "--socket", type=Path, default=None, help="Unix socket to bind (preferred)"
    )
    serve_p.add_argument("--host", default="127.0.0.1", help="Loopback address to bind instead")
    serve_p.add_argument("--port", type=int, default=8787, help="Port for --host")
    serve_p.add_argument(
        "--blocklist", nargs="*", default=[], help="Destinations the risk scorer refuses"
    )
    serve_p.add_argument(
        "--rail-endpoint",
        default=None,
        help=(
            "The rail JSON-RPC URL this deployment settles through ($MERKL_RAIL_ENDPOINT). "
            "The signer never calls it; it refuses to start if the URL names a different "
            "chain than the policy's network."
        ),
    )

    token_p = signer_sub.add_parser(
        "token", help='Manage relay bearer tokens (docs/SIGNER-RPC.md, "Who may call what")'
    )
    token_sub = token_p.add_subparsers(dest="token_command", metavar="<subcommand>")
    token_add_p = token_sub.add_parser("add", help="Register a new relay token; prints it once")
    token_add_p.add_argument("id", help="A label for this token (e.g. 'dashboard', 'ci')")
    token_add_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)
    token_revoke_p = token_sub.add_parser("revoke", help="Remove a relay token by id")
    token_revoke_p.add_argument("id", help="The token id to remove")
    token_revoke_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)
    token_list_p = token_sub.add_parser("list", help="List relay token ids (never the tokens)")
    token_list_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)

    # treasury
    treasury_p = sub.add_parser("treasury", help="Set up and check a co-signed treasury")
    treasury_sub = treasury_p.add_subparsers(dest="treasury_command", metavar="<subcommand>")
    init_p = treasury_sub.add_parser("init", help="Fund and lock down a treasury")
    init_p.add_argument(
        "--xrpl-testnet", action="store_true", help="Bootstrap on the XRPL testnet"
    )
    init_p.add_argument(
        "--xrpl-mainnet",
        action="store_true",
        help="Bootstrap on XRPL mainnet: no faucet, seeds read from --wallet-file, "
        "reserves printed and a typed confirmation required",
    )
    init_p.add_argument("--agents", type=int, default=1, help="How many agent keys (default 1)")
    init_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)
    init_p.add_argument(
        "--wallet-file", type=Path, default=None, help="Where to write seeds (0600)"
    )
    init_p.add_argument(
        "--trust",
        action="append",
        default=[],
        metavar="CODE.issuer",
        help="A trust line to set before the master key is disabled (repeatable)",
    )
    _add_enrolment_flags(init_p)
    init_p.add_argument(
        "--confirm",
        default=None,
        metavar="SENTENCE",
        help=f"Skip the mainnet prompt by typing it here: {MAINNET_CONFIRMATION!r}. "
        "Anything else is not a confirmation.",
    )

    enrol_p = treasury_sub.add_parser(
        "enrol",
        help="Re-send enrol and ready to the notary from what is already on disk",
    )
    enrol_p.add_argument("--home", type=Path, default=None, help=HOME_HELP)
    _add_enrolment_flags(enrol_p, required=True)

    verify_p = treasury_sub.add_parser("verify", help="Check a treasury's flags and signer list")
    verify_p.add_argument("address", help="Treasury account address")

    # xrpl
    xrpl_p = sub.add_parser("xrpl", help="XRPL-specific offline tools")
    xrpl_sub = xrpl_p.add_subparsers(dest="xrpl_command", metavar="<subcommand>")
    pin_unl_p = xrpl_sub.add_parser(
        "pin-unl", help="Audit a published validator list and pin its master keys"
    )
    pin_unl_p.add_argument(
        "source", help="A validator-list URL (vl.ripple.com, ...) or a local JSON file"
    )
    pin_unl_p.add_argument(
        "-o", "--out", type=Path, default=None, help="Write the pinned form here"
    )
    pin_unl_p.add_argument(
        "--quorum-fraction",
        type=float,
        default=0.8,
        help="Fraction of pinned validators required to agree (default 0.8)",
    )

    # policy
    policy_p = sub.add_parser("policy", help="Sign and read policy documents (plan D16)")
    policy_sub = policy_p.add_subparsers(dest="policy_command", metavar="<subcommand>")
    policy_sign_p = policy_sub.add_parser(
        "sign", help="Sign a policy document with an Ed25519 admin key (the non-browser path)"
    )
    policy_sign_p.add_argument("document", type=Path, help="A bare PolicyDocument, as JSON")
    policy_sign_p.add_argument(
        "--key", dest="key_path", type=Path, required=True, help="Ed25519 seed file, hex, 0600"
    )
    policy_sign_p.add_argument(
        "--out", type=Path, default=None, help="Where to write the signed policy (default: stdout)"
    )
    policy_show_p = policy_sub.add_parser(
        "show", help="Render a policy document (signed or bare) in words"
    )
    policy_show_p.add_argument("document", type=Path, help="A PolicyDocument or SignedPolicy JSON")
    policy_show_p.add_argument(
        "--json", dest="as_json", action="store_true", help="Structured output"
    )

    # demo
    demo_p = sub.add_parser(
        "demo", help="Run the five scenarios end to end and write pages to open"
    )
    demo_p.add_argument(
        "--out", type=Path, default=None, help="Output folder (default: ./merkl-demo)"
    )
    demo_p.add_argument(
        "--xrpl-testnet",
        action="store_true",
        help="Also run against XRPL testnet (or set MERKL_XRPL_TESTNET=1)",
    )
    demo_p.add_argument("--no-node", action="store_true", help="Skip the JavaScript verifier")

    args = parser.parse_args()

    if args.command == "verify":
        from merkl.cli.verify import verify_command as verify_file

        raise SystemExit(
            verify_file(
                args.file,
                as_json=args.as_json,
                show_all=args.all,
                require_complete=args.require_complete,
                policy=args.policy,
                admin_key=args.admin_key,
                proof=args.proof,
                evidence=args.evidence,
                pcr=args.pcr,
                validator=args.validator,
                quorum=args.quorum,
                now=args.now,
                max_age=args.max_age,
            )
        )
    elif args.command == "receipt":
        from merkl.cli.receipt import receipt_show_command

        if args.receipt_command != "show":
            receipt_p.print_help()
            return
        raise SystemExit(
            receipt_show_command(
                args.ref,
                store=args.store,
                endpoint=args.endpoint,
                api_key=args.api_key,
                show_leaves=args.leaves,
                as_json=args.as_json,
            )
        )
    elif args.command in ("approve", "reject"):
        from merkl.cli.approve import approve_command

        raise SystemExit(
            approve_command(
                args.challenge,
                action=args.command,
                approver=args.approver,
                key_path=args.key_path,
                socket_path=args.socket_path,
                host=args.host,
                port=args.port,
                as_json=args.as_json,
                bearer_token=args.relay_token,
            )
        )
    elif args.command == "reconcile":
        from merkl.cli.reconcile import reconcile_command

        raise SystemExit(
            reconcile_command(
                args.treasury,
                history=args.history,
                store=args.store,
                endpoint=args.endpoint,
                api_key=args.api_key,
                as_json=args.as_json,
            )
        )
    elif args.command == "signer":
        if args.signer_command == "serve":
            from merkl.cli.signer import serve_command

            raise SystemExit(
                serve_command(
                    policy_path=args.policy,
                    home=args.home,
                    socket_path=args.socket,
                    host=args.host,
                    port=args.port,
                    blocklist=tuple(args.blocklist),
                    rail_endpoint=args.rail_endpoint,
                )
            )
        if args.signer_command == "token":
            from merkl.cli.signer import token_command

            if args.token_command not in ("add", "revoke", "list"):
                token_p.print_help()
                return
            raise SystemExit(
                token_command(args.token_command, getattr(args, "id", None), home=args.home)
            )
        signer_p.print_help()
    elif args.command == "policy":
        from merkl.cli.policy import show_command, sign_command

        if args.policy_command == "sign":
            raise SystemExit(sign_command(args.document, key_path=args.key_path, out=args.out))
        if args.policy_command == "show":
            raise SystemExit(show_command(args.document, as_json=args.as_json))
        policy_p.print_help()
    elif args.command == "treasury":
        from merkl.cli.treasury import enrol_command, init_command, verify_command

        if args.treasury_command == "init":
            from merkl.core.rail import NETWORK_XRPL_MAINNET, NETWORK_XRPL_TESTNET

            if args.xrpl_testnet == args.xrpl_mainnet:
                print("choose exactly one of --xrpl-testnet and --xrpl-mainnet", file=sys.stderr)
                raise SystemExit(2)
            raise SystemExit(
                init_command(
                    home=args.home,
                    agents=args.agents,
                    wallet_file=args.wallet_file,
                    network=(NETWORK_XRPL_MAINNET if args.xrpl_mainnet else NETWORK_XRPL_TESTNET),
                    trust=tuple(args.trust),
                    enrol=args.enrol,
                    notary=args.notary,
                    confirm=args.confirm,
                    agent_dir=args.agent_dir,
                    bundle_to_notary=args.bundle_to_notary,
                )
            )
        if args.treasury_command == "enrol":
            raise SystemExit(
                enrol_command(
                    home=args.home,
                    enrol=args.enrol,
                    notary=args.notary,
                    agent_dir=args.agent_dir,
                    bundle_to_notary=args.bundle_to_notary,
                )
            )
        if args.treasury_command == "verify":
            raise SystemExit(verify_command(args.address))
        treasury_p.print_help()
    elif args.command == "xrpl":
        from merkl.cli.xrpl_unl import pin_unl_command

        if args.xrpl_command == "pin-unl":
            raise SystemExit(
                pin_unl_command(args.source, out=args.out, quorum_fraction=args.quorum_fraction)
            )
        xrpl_p.print_help()
    elif args.command == "demo":
        from merkl.cli.demo import demo_command

        raise SystemExit(demo_command(out=args.out, xrpl=args.xrpl_testnet, node=not args.no_node))
    elif args.command == "disclose":
        from merkl.cli.disclose import disclose

        disclose(
            args.action_id,
            evidence_dir=args.evidence_dir,
            receipt_dir=args.receipt_dir,
            endpoint=args.endpoint,
            api_key=args.api_key,
            out_dir=args.out,
            leaves=[n.strip() for n in args.leaves.split(",") if n.strip()]
            if args.leaves
            else None,
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
