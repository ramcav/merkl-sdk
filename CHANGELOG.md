# Changelog

All notable changes to `merkl-sdk`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut by pushing a `merkl-sdk-v<version>` tag; see
`.github/workflows/release-sdk.yml`.

## [Unreleased]

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
