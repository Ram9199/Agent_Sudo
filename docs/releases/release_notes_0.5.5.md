# Release Notes: Agent_Sudo v0.5.5

Patch release. A batch of first-run and pip-only-user fixes surfaced by a fresh-install audit, plus a review fix that PR #90 had merged without. The goal is that a brand-new user who runs `pipx install agent-sudo-mcp` and follows the docs succeeds from a clean machine, with no repository checkout. No breaking changes, no schema changes, no policy-behavior changes, no new runtime dependencies.

## First-run experience

- **Friendly input errors (#69).** `check`, `run`, `generic-check`, `generic-run`, `hermes-check`, and `codex-check` no longer dump a raw traceback (and the user's path) when given a missing file, invalid JSON, or an inline string instead of a file path. They now print a one-line error with a payload example and exit non-zero, and the positional file arguments carry `--help` descriptions with an example schema.
- **`doctor` path consistency and no CWD litter (#71).** `agent-sudo doctor` no longer creates a `.agent-sudo/` directory in the current working directory. It probes the single home state root (`~/.agent-sudo`) for both the audit-log and delegation-store writability checks, so it reports one consistent location instead of two different roots.

## pip-only users

- **No repo-relative examples in docs or setup output (#67).** Documented commands and the `agent-sudo setup` verify steps (hermes/openclaw) no longer reference `examples/*.json` files that a `pip`/`pipx` install does not have. Each is now self-contained — an inline payload written to a temp file, or `agent-sudo eval` — so every documented command works from a clean install with no repository checkout. The `demo` closing line now points at `agent-sudo eval`.
- **Improved `agent-sudo-mcp --help` (#72).** The `--audit-log`, `--delegations-file`, and `--pending-approvals-file` flags now have descriptions, and the server help carries a description and an epilog pointing at `agent-sudo eval` and `agent-sudo setup`.

## Correctness

- **Re-landed missed PR #90 review fixes (#95).** PR #90 was squash-merged without its review-fix commit; this restores it. The demo shell executor now reports `executed=False` (not `True`) when the host fails to *spawn* a process (`OSError`), matching the other failure paths instead of mislabeling a non-execution as executed. The Windows file-lock retry filter replaces magic numbers `(13, 33)` with named errno/winerror sets via an `_is_lock_busy()` helper (`13` duplicated `errno.EACCES`; `33` is the Windows `ERROR_LOCK_VIOLATION` winerror). Regression tests — whose absence let the original fix silently drop — are added.

## Testing

- **Test isolation (#84).** The MCP gateway tests no longer depend on the developer's ambient `~/.agent-sudo/config.json` workspace (or `AGENT_SUDO_WORKSPACE`), so they behave the same locally as on a clean CI runner.

## Compatibility

- No breaking changes.
- No schema changes (`delegations.json` and `audit.jsonl` formats unchanged).
- No policy-behavior changes (classifier/policy decisions are identical to v0.5.4).
- No new runtime dependencies.
- The only user-visible changes are docs, CLI help/error text, test isolation, and the `executed` flag on a (rare) demo-executor spawn failure.
