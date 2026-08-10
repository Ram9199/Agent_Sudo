# `agent-sudo inventory` — design (issue #101, Phase 1)

Date: 2026-06-12
Status: Implemented in this PR (Phase 1 MVP); Phase 2 planned below.

## Problem

Dogfooding across Codex, Claude Desktop, Gemini/Antigravity, and Hermes showed
the highest-friction failure mode is **install/version drift**: multiple copies
of Agent_Sudo accumulate (pip, pipx, pyenv, per-client venvs, editable
checkouts, old test venvs), each MCP client config pins a different one, and
nothing shows the whole picture. A client silently running a stale version
looks like a product bug. Validated on the dogfood machine at implementation
time: 4 distinct installs (0.5.4, 0.5.5, 0.5.6, plus a pyenv shim), with
Claude Desktop pinned to 0.5.5 and Gemini/Antigravity pinned to 0.5.4 while
0.5.6 was newest.

## Shape

New top-level command: `agent-sudo inventory` (`--json` for machine output).
Kept separate from `doctor` so doctor's readiness exit-code contract and
output are untouched. Exit code is always 0 — the report is informational
(a `--strict` mode is Phase 2).

## Hard constraints (Phase 1)

- **Read-only.** Never modifies, deletes, or uninstalls anything; the
  read-only property is pinned by a test that snapshots the filesystem before
  and after a run.
- **Never executes discovered binaries.** Versions come from package metadata
  (`agent_sudo_mcp-*.dist-info/METADATA`, falling back to parsing
  `agent_sudo/__init__.py`), not from running `agent-sudo --version`.
  Executing arbitrary executables found on disk is a code-execution risk for a
  security tool. An opt-in `--exec-probe` is deferred to Phase 2.
- **Bounded discovery.** Only known locations are scanned — no
  filesystem-wide crawl.

## Discovery sources

Installs (deduplicated by environment root, symlinks resolved):

1. **PATH** — each PATH dir checked for `agent-sudo` / `agent-sudo-mcp`;
   records rank, detects shadowing (same name resolving to two roots).
2. **pipx** — `$PIPX_HOME/venvs` and the default pipx venv locations.
3. **pyenv** — `$PYENV_ROOT/versions/*/bin`; the `shims` directory is
   recognized and labeled `PYENV-SHIM` (resolves at runtime) instead of being
   misreported as an unknown install.
4. **Running interpreter** — the package serving the current process.
5. **Client-config commands** — any venv a client config points at, even if
   not on PATH (this is how per-client venvs like `.venv-antigravity` are
   found).

Editable installs detected via `direct_url.json` (`dir_info.editable`).

Client configs (parse-only, fail-soft to a warning on malformed files):

| Client | Path(s) |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\...` (Windows), `~/.config/Claude/...` (Linux) |
| Claude Code | `~/.claude.json` |
| Codex | `~/.codex/config.toml` (`[mcp_servers.*]`; tomllib, line-based fallback on Python 3.10; commented-out entries ignored) |
| Gemini | `~/.gemini/settings.json`, `~/.gemini/config/mcp_config.json` |
| Antigravity | `~/.gemini/antigravity/mcp_config.json` |
| Hermes | `~/.hermes/mcp_config.json`, `~/.hermes/config/mcp_config.json` |

An entry counts as Agent_Sudo when the command basename is
`agent-sudo`/`agent-sudo-mcp` or the args invoke `agent_sudo.mcp_server`.

## Classification

- **ACTIVE** — referenced by a client config, or present on PATH.
- **STALE** — older than the newest discovered version *and* referenced by no
  client config.
- **VERSION DRIFT** — version differs from the newest discovered version
  (installs), or a config resolves to a non-newest install (configs).
- **DUPLICATE INSTALL** — more than one distinct install root exists.
- **UNKNOWN** — version/metadata undeterminable, or a config's command does
  not exist on disk.
- Auxiliary labels: `PATH-SHADOWED`, `PYENV-SHIM`, `EDITABLE`.

Every install and config line carries: exact path, version, how it was
discovered, statuses, and a recommendation. Recommendations only ever say
review / upgrade / re-point — never delete or uninstall.

## Risks and mitigations

1. **Code execution via discovered binaries** — eliminated: metadata-only.
2. **Malformed configs crash the report** — every parser wrapped; malformed
   files become warnings, the rest of the report still renders.
3. **Python 3.10 has no `tomllib`** — comment-aware line-based fallback for
   the Codex TOML shape, unit-tested directly.
4. **Platform path differences** — candidate paths parametrized by platform;
   home/PATH/environ injectable, so tests are hermetic.
5. **Misclassification** — conservative: STALE requires both older-version and
   unreferenced; wording never instructs destructive action.
6. **Privacy** — output is local-only; `$HOME` shown as `~`.

## Phase 2 (planned, not in this PR)

- Relative `--audit-log` / `--delegations-file` path warnings in configs (the
  known relative-default trap).
- Broken-registration deep checks (server name collisions, stale flags,
  missing state files).
- Orphaned-install aging (last-modified heuibristics) and an explicit orphan
  status.
- Migration helper: `inventory --fix-plan` printing the exact commands to
  upgrade/re-point (still never executing them).
- Opt-in `--exec-probe` to confirm metadata versions by running binaries.
- `--strict` exit code for CI use.
- Hermes deep integration (`hermes mcp list`) once a stable config contract
  exists.
