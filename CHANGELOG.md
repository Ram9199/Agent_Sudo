# Changelog

## v0.5.6

Security-correctness patch: external-content taint can no longer weaken approval strength. Also picks up a pending-approval store concurrency fix that landed after v0.5.5.

- **Taint monotonicity (#103, #104).** The classifier's `EXTERNAL_CONTENT` provenance branch returned SENSITIVE for any non-BLOCKED action, downgrading CRITICAL-policy actions (`send_email`, `money_transfer`, `external_post`, `credential_access`, `run_shell_command`, `delete_file`, `legal_or_employment_message`) from strong approval to normal approval. External content may raise risk but must never lower it: SAFE still escalates to SENSITIVE; SENSITIVE, CRITICAL, and BLOCKED keep their tier. Adds regression tests for all seven critical actions and a property test asserting the tainted classification is never lower than the untainted one for every default-policy action across both taint channels (provenance origin and source trust).
- **Pending approval store concurrency (#100).** Mutations of the pending-approval store are serialized, preventing concurrent approval flows from corrupting or losing pending entries. Adds concurrency regression tests.
- **Compatibility.** No breaking changes, no schema changes, no new runtime dependencies. Visible behavior change (intended, strictly tightening): actions whose policy tier is CRITICAL now require strong/passphrase approval when tagged with `EXTERNAL_CONTENT` provenance, and their audit records carry classification `CRITICAL` instead of `SENSITIVE` — relevant to anyone alerting on classification counts. Nothing previously blocked is allowed and nothing previously allowed is blocked.

## v0.5.5

First-run and pip-only-user fixes surfaced by a fresh-install audit, plus a re-landed review fix. No engine behavior, schema, policy, or dependency changes.

- **Friendly input errors (#69).** `check`, `run`, `generic-check`, `generic-run`, `hermes-check`, and `codex-check` no longer dump a raw traceback (and the user's path) when given a missing file, invalid JSON, or an inline string instead of a file path. They now print a one-line error with a payload example and exit non-zero, and the positional file arguments carry `--help` descriptions with an example schema.
- **`doctor` path consistency and no CWD litter (#71).** `agent-sudo doctor` no longer creates a `.agent-sudo/` directory in the current working directory. It probes the single home state root (`~/.agent-sudo`) for both the audit-log and delegation-store writability checks, so it reports one consistent location.
- **No repo-relative examples in docs or setup output (#67).** Documented commands and the `agent-sudo setup` verify steps (hermes/openclaw) no longer reference `examples/*.json` files that a `pip`/`pipx` install does not have. Each is now self-contained (an inline payload written to a temp file, or `agent-sudo eval`), so every documented command works from a clean install with no repository checkout. The `demo` closing line now points at `agent-sudo eval`.
- **Improved `agent-sudo-mcp --help` (#72).** `--audit-log`, `--delegations-file`, and `--pending-approvals-file` now have descriptions, and the server help carries a description and an epilog pointing at `agent-sudo eval` and `agent-sudo setup`.
- **Test isolation (#84).** The MCP gateway tests no longer depend on the developer's ambient `~/.agent-sudo/config.json` workspace (or `AGENT_SUDO_WORKSPACE`), so they behave the same locally as on a clean CI runner.
- **Re-landed missed PR #90 review fixes (#95).** PR #90 was squash-merged without its review-fix commit; this restores it: the demo shell executor reports `executed=False` (not `True`) when the host fails to *spawn* a process (`OSError`), and the Windows file-lock retry filter replaces magic numbers `(13, 33)` with named errno/winerror sets via an `_is_lock_busy()` helper. Adds the regression tests whose absence let the fix silently drop.
- **Compatibility.** No breaking changes, no schema changes, no policy-behavior changes, no new runtime dependencies. Docs, CLI help/error text, test isolation, and the `executed` flag on a (rare) demo-executor spawn failure are the only user-visible changes.

## v0.5.4

- **`agent-sudo eval` one-shot evaluator.** New `agent-sudo eval` runs the full deny → delegate → allow-once → deny-exhausted → audit-verified ladder in a single command and prints a PASS/FAIL report. It runs entirely in a temporary directory and never reads or writes the user's `~/.agent-sudo` state. Exits `0` only when all five steps pass (CI-safe); `--json` emits a machine-readable report and `--output-dir DIR` writes artifacts to a chosen location. This is the published "fastest path" referenced by the README and the 5-minute evaluator guide, which were previously broken on PyPI because the command did not ship.
- **Claude Code + Codex CLI setup paths.** `agent-sudo setup` adds a `claude-code` target (alongside `codex`, `claude-desktop`, `hermes`, and `openclaw`), closing the gap where the headline audience had no first-party setup path.
- **Interactive `setup` selector.** Running `agent-sudo setup` with no target presents an interactive picker; targets are also selectable by number or name. Bare invocations are guided rather than erroring out.
- **Generated MCP config pins absolute paths and approval flags.** Setup output now pins absolute `--audit-log`, `--delegations-file`, and `--pending-approvals-file` paths and the macOS approval flags, so a configured client's audit, delegation, and pending state land in predictable locations instead of relative defaults.
- **First-run onboarding friction removed.** A batch of onboarding fixes (demo Scenario 1 now correctly labeled `Sensitive Read (REQUIRE_APPROVAL)`, clearer first-run guidance, and related copy fixes) so the first commands a new user runs behave as documented.
- **CLI command reference.** Adds a CLI command reference doc and corrects the `audit review` flag documentation.
- **Compact gated wordmark.** Interactive commands print a compact one-line wordmark.
- **MCP registry description shortened.** `server.json` description trimmed to satisfy registry length limits.
- **Compatibility.** No breaking changes, no schema changes, no policy-behavior changes, no new runtime dependencies. New CLI surface (`eval`, `setup claude-code`, the `setup` selector) is additive.

## v0.5.3

- **README repositioning.** Agent_Sudo is framed as an authorization, delegation, provenance, and verifiable-audit engine for AI agents — MCP is the adapter, not the identity.
- **Public metadata aligned.** The PyPI summary and the MCP Registry `server.json` description carry the same authorization/delegation/provenance/verifiable-audit positioning, so package indexes and crawlers surface consistent framing.
- **Audit Explorer — `audit list` filters + origin column.** `agent-sudo audit list` gains `--since`, `--decision`, `--origin`, `--actor`, `--tool`, `--target`, and `--non-allow`, plus a provenance origin column. Read-only; `--json` output shape unchanged.
- **Audit Explorer — `audit trace <token_id>`.** Token-first delegation lifecycle inspection: resolves a token by full id or unique prefix, joins its store metadata with audit references, and reports observed consumes/denials and the causes denial reasons cite, with a raw-reason fallback. Read-only.
- **Compatibility.** No breaking changes, no schema changes, no policy-behavior changes, no new runtime dependencies.

## v0.5.2

- **Sensitive read/search hardening.** Blocks sensitive `read_file` and `search_files` targets more consistently, including macOS Keychains, Messages, Mail, Cookies, and Safari stores; browser cookie/login profile stores; gcloud and kube config directories; and common credential files such as `.netrc`, `.npmrc`, and `.pypirc`.
- **Git/GitHub mutation hardening.** Blocks mutating Git and GitHub CLI shell commands at the classifier and executor boundary, including `git push`, `git remote` mutations, mutating `gh issue`/`pr`/`release`/`repo`/`workflow`/`run` commands, and mutating `gh api` calls. Read-only Git/GitHub commands remain approval-gated rather than hard-denied.
- **Audit review command.** Adds `agent-sudo audit review`, which verifies the audit chain, summarizes recent decision counts, and lists non-ALLOW records for a configurable window such as `30m`, `24h`, or `7d`.
- **Delegation store visibility.** Keeps `agent-sudo delegate create` stdout as parseable token JSON while reporting the delegation file path on stderr. When the default `~/.agent-sudo/delegations.json` store is used, the CLI warns that integrations may read a different delegation store.
- **Delegation troubleshooting docs.** Adds Hermes delegation-store guidance using explicit `--delegations-file`, plus a troubleshooting checklist for "delegation created but authorization still denied" cases covering action, path, actor, expiry, use count, and delegation-file mismatches.
- **Compatibility.** No new runtime dependencies. Delegation token format is unchanged, and existing JSON stdout consumers of `agent-sudo delegate create` remain compatible.

## v0.5.1

- **Concurrency-safe one-use delegation consumption.** The delegation consume path (`DelegationStore.authorize(consume=True)`, plus `create`/`revoke`) now performs its entire read → check → increment → write under an exclusive POSIX advisory lock (`fcntl.flock`) and re-reads token state from disk inside the lock. This closes a race in which concurrent consumers could each observe `uses=0` and all be allowed, double-spending a `max_uses=1` token. `save()` now publishes atomically (temp file → `fsync` → `os.replace` → directory `fsync`) so a reader or crash never sees a partial delegations file.
- **Concurrency-safe audit append.** `AuditLogger._write_entry` now holds the same exclusive lock across read-last-hash → link → append → `fsync`, so concurrent appends can no longer read the same `previous_hash` and fork the SHA-256 hash chain. The chain stays linear and `verify-audit`-clean under parallel writes.
- **Fail-closed under lock contention and corruption.** If the lock cannot be acquired within the timeout, or the store is unreadable/corrupt, or the audit log has a torn tail, the gateway denies (delegation) or raises (audit) rather than falling open or silently continuing. No broad `except` masking is introduced; existing fail-closed behavior is preserved.
- **No format changes.** `delegations.json` and `audit.jsonl` are byte-for-byte identical to v0.5.0. The only new on-disk artifacts are sibling `*.lock` files used purely for lock state.
- **No new dependencies.** Standard library only (`fcntl`). Public signatures are unchanged — `lock_timeout` is a keyword-only argument with a default on `DelegationStore` and `AuditLogger`. POSIX-only (macOS/Linux), matching the supported runtimes.

## v0.5.0

- **Stabilizes the approval-helper opener test.** Replaces a brittle `assertNotIn("pwd", ...)` substring scan — which false-positived whenever the temp-dir path contained `pwd` — with a deterministic check that parses the AppleScript `do script` body and asserts it launches only the approval-helper invocation, preserving the original intent (the requested command is never executed by the opener). No production behavior change.
- **Replaces the PydanticAI example with a real, deterministic, offline end-to-end dogfood.** A `FunctionModel`-driven agent loop exercises the full path — agent → `PermissionGateway` → real temp-dir file I/O → scoped delegation → hash-chained audit → audit verification — across four scenarios (safe `USER_DIRECT` allow; sensitive write held at `REQUIRE_APPROVAL` then allowed via a delegation token; blocked exfiltration denied; audit chain verified). The LLM is a deterministic test double (no key, no network); the gateway/delegation/audit path and file I/O are real. Adds a `pydantic-ai` `examples` optional extra (never a runtime dependency) and a dedicated CI job; the example test skips cleanly when the extra is absent.

- **Positioning: clarifies engine vs. demo executor.** Documents Agent_Sudo as an authorization/approval/delegation/audit **engine** whose primary integration is embedding the library in your agent; the MCP server is a distribution channel and reference demo. The MCP `write_file` (scoped to `/tmp/agent-sudo-demo`) and `run_shell_command` (narrow allowlist) tool descriptions now state plainly that they are **demo executors**, not a turnkey way to mediate a client's real file/shell tools. README "Choose Your Path", the Claude Desktop guide, and the security model are updated accordingly. No behavior change — labeling and docs only.
- **Adds `agent-sudo verify-routing`**, a read-only command that reports observed evidence of whether actions are flowing through Agent_Sudo: configuration state, observed gateway activity (audit record count, last record, decision histogram, hash-chain integrity), a best-effort scan of the client MCP config for `agent-sudo` and other bypass-capable servers, and the standing trust-boundary limits. It performs no probing, execution, or telemetry, and deliberately makes no aggregate "you are protected" claim — it can only report observed signals, not certify routing completeness.
- **Security hardening: contradictory provenance is reconciled, not trusted.** When a request asserts a `source_trust` higher than its `source` / `origin_type` evidence supports (e.g. `source="webpage"` or `origin_type="EXTERNAL_CONTENT"` paired with `source_trust="USER_DIRECT"`), the gateway now downgrades the trust to the most restrictive level the evidence supports (`EXTERNAL_CONTENT`/`UNKNOWN`) instead of honoring the inflated claim, and records an `inconsistent_provenance` reason on the decision and audit entry. **Impact:** such requests are escalated to `REQUIRE_APPROVAL` rather than allowed. Internally *consistent* provenance — including an explicit `USER_DIRECT` whose `source`/`origin_type` agree — is honored exactly as before. A consistently-forged `USER_DIRECT` remains a known limitation pending host attestation. See [`docs/architecture/security_model.md`](docs/architecture/security_model.md) (Default Trust Posture).
- **Security hardening (behavior change): missing provenance now fails closed.** A request that does not assert a trust level — no `source_trust`, no `provenance` — is treated as `UNKNOWN` (untrusted) instead of `USER_DIRECT`. The change is applied at the MCP JSON-RPC boundary (`tool_call_from_jsonrpc`), the `ActionRequest.from_dict` path, and the `ActionRequest` constructor default. **Impact:** a SAFE action (e.g. `read_file`) arriving without provenance is now escalated to `REQUIRE_APPROVAL` rather than allowed silently. Clients/integrations that speak for the operator must attest provenance explicitly (`source_trust="USER_DIRECT"`); explicit trust is honored exactly as before. Self-attested `USER_DIRECT` remains believed — host attestation / nonce binding is tracked separately. See [`docs/architecture/security_model.md`](docs/architecture/security_model.md) (Default Trust Posture).

## v0.4.3

- Capitalizes the verification namespace in `README.md` and aligns version metadata to resolve case-sensitive publisher check errors during official registry submission.

## v0.4.2

- Adds the official MCP Registry ownership verification marker to `README.md` and aligns version metadata in `server.json` to enable official registry publication.

## v0.4.1

- Adds `agent-sudo audit list`, a human-readable view of the audit log. Renders each record as a table (time, decision, actor, action, target, reason) so users can review what an agent did without parsing raw JSONL or writing code. Supports `--limit N` (default 20; `0` for all) and `--json`, defaults to the MCP server log at `.agent-sudo/mcp-audit.jsonl`, and handles both gateway-decision records and approval lifecycle events. Complements the existing integrity-only `verify-audit`.
- Adds `agent-sudo workspace set <path>` and `agent-sudo workspace show` so Claude Desktop users can persist the fixed workspace once in `~/.agent-sudo/config.json` and omit `--workspace` from the MCP server config.
- Fixes `agent-sudo doctor` for installed package users by running the contributor-only personal-data scan only when the source-tree scanner exists.
- Updates Claude Desktop onboarding docs and README setup guidance to make workspace persistence, audit verification, and native-tool bypass boundaries explicit.

## v0.4.0

First stable public release of the `agent-sudo` local permission gateway for AI agent tool execution.

- Consolidates release candidate iterations (rc1 through rc14) into the first stable production-ready release.
- Features robust security boundaries, including:
  - Deep-scanning of shell command arguments to block path traversal, nested subshells, symlinks, and utility bypasses targeting protected configurations.
  - PBKDF2-HMAC-SHA256 passphrase-based confirmation gating for sensitive and critical actions.
  - Tamper-resistant, cryptographically secured SHA-256 hash-chained JSONL audit logs.
  - Scoped, TTL-limited, and use-quota restricted temporary delegation tokens.
- Introduces native macOS user notifications and apple-script based auto-opening Terminal approval-helper utilities.
- Implements standard stdio Model Context Protocol (MCP) server integration (`agent-sudo-mcp`) out of the box with Claude Desktop and Cursor.
- Includes a complete python packaging structure with zero external runtime dependencies.

## v0.4.0-rc14

Release candidate addressing critical shell command policy bypass vulnerabilities.

- Hardens `is_blocked_shell_target` in `agent_sudo/classifier.py` and `agent_sudo/executors.py` by implementing comprehensive substring inspections for protected configuration paths and files (e.g. `.agent-sudo`, `.ssh`, `.agent-runtime`, `.env`, `auth.json`, `policy.yaml`, etc.).
- Adds deep token scanning to check all flattened command arguments for symlinks pointing to protected configuration paths, preventing obfuscation-based bypasses.
- Introduces robust regression tests covering path traversal variations (`$HOME`, relative `../`, no-space redirections `>`), copy/move/link utilities (`mv`, `cp`, `ln`, `rsync`, `tar`, `tee`, `dd`, `cat`), logical chained commands (`&&`, `;`), nested subshells (`bash -c`), and symlinks.

## v0.4.0-rc13

Release candidate introducing portable audit verifier helpers.

- Implements stable PolicyDecision and AuditRecord schemas.
- Adds canonical hash-chain verification semantics.
- Introduces `agent-sudo verify-audit` command-line utility to cryptographically validate audit trails and detect tamper attempts.
- Publishes lightweight `agent_sudo.spec_helpers` module for third-party runtime integrations.

## v0.4.0-rc12

Release candidate polishing the guided terminal helper auto-open UX for Claude Desktop approval workflows.

- Cleans and clears the terminal screen immediately upon auto-open to suppress login shell warnings, powerlevel10k details, and startup noise.
- Sanitizes and truncates target details to command/file basenames (e.g. `python3` instead of `/usr/bin/python3`) to reduce shell/path leakage and secrets exposure.
- Implements a 3-second auto-close countdown on successful approval or denial when a single pending request is resolved.
- Ensures keep-open behavior (blocking on a "Press Enter to exit..." prompt) on onboarding states, multiple requests, wrong passphrases, watch mode, or unexpected execution failures.
- Polishes overall operator UX and visual presentation for auto-opened helper sessions.

## v0.4.0-rc11

Release candidate introducing guided terminal helper workflow for pending approvals.

- Added `agent-sudo approval-helper` CLI command to guide the user interactively through approvals or denials with onboarding tips and interactive `[y/N]` prompts.
- Added continuous watching support via `--watch` flag for `approval-helper`.
- Added optional macOS Terminal.app auto-opening window support to streamline developer and Claude Desktop testing workflows.
- Wired `--open-approval-terminal` configuration flag to MCP server (`agent-sudo-mcp`) and CLI evaluation paths.
- Enabled environment variable support via `AGENT_SUDO_OPEN_APPROVAL_TERMINAL=1`.
- Built secure AppleScript Terminal opening execution (safely using python's `sys.executable` and `shlex.quote` without passing secrets, sensitive command targets, or passphrases).
- Ensured non-blocking opener behavior (opener warning logged to stderr on failure).
- Maintained exact approval validation, `shell=False` protections, and auto-approval security boundaries.

## v0.4.0-rc10

Release candidate introducing optional native macOS approval notifications.

- Added optional native macOS desktop notification support for pending approval requests.
- Added `--notify` CLI flag to both `agent-sudo-mcp` and `agent-sudo run / generic-run` commands.
- Enabled environment variable `AGENT_SUDO_NOTIFY=1` to toggle notifications.
- Sanitized and truncated notification payloads (reducing path disclosures and command arguments) to prevent secrets leakage.
- Ensured non-blocking notification behavior; failures do not disrupt the approval creation or MCP tool execution.
- Validated Claude Desktop end-to-end approval UX flow.
- Avoided the use of `shell=True` to prevent shell injection vectors.

## v0.4.0-rc9

Release candidate adding configurable workspace root support.

- Added CLI flags `--workspace` to both `agent-sudo context` and `agent-sudo-mcp` tools.
- Added environment variable support via `AGENT_SUDO_WORKSPACE`.
- Added config file fallback loading workspace paths from `~/.agent-sudo/config.json`.
- Introduced `configured_workspace` and `effective_workspace` fields to the runtime context.
- Prevents unanchored root execution reports for MCP clients (like Claude Desktop) when a valid workspace is configured.
- Maintained exact approval mechanics and policy boundaries for all workspace contexts.

## v0.4.0-rc8

Release candidate focusing on post-upgrade verification privacy and hygiene fixes.

- Redacted absolute paths from the `passphrase_reset` audit event to avoid recording raw personal user directories.
- Excluded the `.agent-sudo/` runtime state directory and build artifacts from the personal-data hygiene checks.
- Prevented `agent-sudo doctor` and post-upgrade verification from failing on local runtime audit log files.
- Preserved all local runtime state and audit log hash chains intact.

## v0.4.0-rc7

Release candidate introducing workspace discovery and runtime context for MCP clients.

- Added runtime context discovery utility to detect cwd, repo root, git branch, root execution, and workspace presence.
- Added `agent-sudo context` CLI command to output workspace context as JSON.
- Added `get_runtime_context` MCP tool to return the same structured context to MCP clients.
- Classifies context retrieval as `SAFE` (read-only, no approval required).
- Logs warnings to `stderr` when running from the filesystem root or when no git repository/workspace is detected.

## v0.4.0-rc6

Release candidate focused on improving CLI approval failure visibility.

- Failed `agent-sudo approve` now prints clear errors to `stderr` explaining the failure reason.
- Wrong passphrase no longer prints misleading pending approval JSON to `stdout`.
- Expired approval failure is clearly reported to the user.
- Successful approvals still print the updated `APPROVED` JSON to `stdout` and exit `0`.
- No changes to underlying approval security semantics.

## v0.4.0-rc5

Release candidate focused on secure passphrase reset flow.

- Implemented safe reset flow on `agent-sudo init-approval`: warns user, revokes active delegation tokens, and cancels active pending approvals (marking them `DENIED` with passphrase reset reason).
- Added CLI option overrides (`--config`, `--pending-approvals-file`, `--delegations-file`, `--audit-log`, and `--force`) for `init-approval` subcommand.
- Logged a chained `passphrase_reset` event to the audit log on successful reset.

## v0.4.0-rc4

Release candidate focused on approval lifecycle correctness.

- Fixed a bug where stale resolved approvals (`USED`, `EXPIRED`, `DENIED`) in the pending approvals JSON store incorrectly matched future identical requests and blocked them from executing.
- Ensured that future identical tool executions create a fresh pending approval request with a new unique UUID.
- Preserved single-use approval semantics, audit logging history, and local passphrase validation.
- Maintained all existing security boundaries, including `BLOCKED` policy enforcement and shell wrapper validation rules.

## v0.4.0-rc3

Release candidate focused on improving `upgrade-local` reliability with generated files.

- Added automatic cleaning of known generated untracked artifacts (like `agent_sudo.egg-info/`, `__pycache__/`, `.pytest_cache/`, `build/`, `dist/`, `.DS_Store`) during upgrade.
- Reduced friction for non-technical users upgrading editable installs by preventing build/test artifacts from blocking the upgrade.
- Bounded artifact cleanup strictly to known paths inside the repository root.
- Ensured unknown untracked files and tracked modified files continue to safely block upgrades by default.
- Maintained explicit requirement for `--allow-dirty` to ignore blocking user modifications.
- Kept configuration data, pending approvals, delegations, and audit logs under `~/.agent-sudo` completely untouched and preserved.

## v0.4.0-rc2

Release candidate focused on MCP approval lifecycle reliability and Claude Desktop usability.

- Changed pending approval TTL defaults to 120 seconds
- Added bounded TTL configuration through `AGENT_SUDO_APPROVAL_TTL_SECONDS` and `agent-sudo-mcp --approval-ttl-seconds`
- Added structured MCP approval metadata with approval ID, expiry, risk, action summary, and approval command
- Added `agent-sudo pending` for active pending approval review
- Added short-index approval support with `agent-sudo approve 1`
- Preserved exact-request matching, single-use approvals, audit logging, BLOCKED policy behavior, `.env` protections, and shell policy enforcement

## v0.2.0-beta

Beta release for the real MCP enforcement path.

- Added `agent-sudo-mcp` stdio MCP server
- Exposed MCP tools for `read_file`, `write_file`, and `run_shell_command`
- Routed MCP tool calls through `MCPGateway` and `PermissionGateway`
- Made shell execution `CRITICAL` by default
- Added path policy checks for demo writes and protected local paths
- Added approval lockout after repeated failed critical approvals
- Added MCP server setup and real-world validation docs
- Added subprocess integration tests for MCP initialize, tool listing, allowed reads, denied shell, and audit logging

## v0.1.0

Initial MVP release.

- Local permission gateway for agent tool requests
- YAML-backed policy engine
- Safe executor boundary before tool execution
- Agent adapters and universal tool-call schema
- Tamper-resistant JSONL audit logs
- Prompt-injection tripwire primitives (best-effort signal, not a defense)
- Approval hardening with local passphrase hash
- Scoped delegation tokens
- Request provenance model
- Setup and doctor commands
