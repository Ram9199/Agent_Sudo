# Agent_Sudo Command Reference

A complete map of the Agent_Sudo command surface, so you can understand what each
command does without reading source. Two executables ship with the package:

- **`agent-sudo`** — the CLI for setup, approvals, delegation, and audit.
- **`agent-sudo-mcp`** — the stdio MCP server an agent client (Claude Code, Codex
  CLI, Claude Desktop) actually connects to. This is the live enforcement point;
  the `agent-sudo` CLI manages and inspects the state around it.

> All examples are illustrative. `agent-sudo --version` and `agent-sudo <cmd> --help`
> are the source of truth for flags on your installed version. Nothing here changes
> behavior.

## Command categories at a glance

| Category | Commands |
| :--- | :--- |
| **Onboarding** | `setup`, `demo`, `doctor`, `init-approval`, `workspace`, `context` |
| **Operational** (live use) | `agent-sudo-mcp`, `pending`, `approve`, `deny`, `approval-helper`, `delegate` |
| **Audit / investigation** | `audit list`, `audit review`, `audit trace`, `verify-audit`, `verify-routing` |
| **Troubleshooting** | `doctor`, `context`, `verify-routing`, `inventory`, `topology` |
| **Administrative** | `init-approval`, `workspace set`, `delegate revoke`, `upgrade-local` |
| **Integration / dev** | `check`, `run`, `generic-check`, `generic-run`, `hermes-check`, `codex-check` |

Some commands appear in more than one category (e.g. `doctor` is both onboarding
and troubleshooting); they are listed under their primary use.

## Typical user workflow

1. **Install & verify** — `pipx install agent-sudo-mcp`, then `agent-sudo doctor`.
2. **Generate client config** — `agent-sudo setup` (interactive) or
   `agent-sudo setup <client>`.
3. **(Optional) enable interactive approvals** — `agent-sudo init-approval`.
4. **Connect** your MCP client; it launches `agent-sudo-mcp`.
5. **Operate** — when a sensitive action is pending: `agent-sudo pending` →
   `agent-sudo approve <id>`; for unattended access, `agent-sudo delegate create`.
6. **Investigate** — `agent-sudo audit list <log>`, `audit trace <token>`,
   `verify-audit <log>`.

---

## Onboarding

### `setup`
- **Purpose:** print a pasteable MCP config for a client runtime.
- **Example:** `agent-sudo setup` (interactive picker) or `agent-sudo setup codex`.
- **When to use:** first-time wiring of Claude Code / Codex CLI / Claude Desktop.
- **Common mistakes:** running it in CI with no target — it lists targets and exits
  non-zero rather than prompting; name the target explicitly in scripts.

### `eval`
- **Purpose:** the one-shot first-value demonstration — runs blocked → delegated →
  allowed-once → denied → audit-verified and prints a PASS/FAIL ladder plus the
  audit-log path.
- **Example:** `agent-sudo eval` · `agent-sudo eval --json` · `agent-sudo eval --output-dir ./eval-out`
- **When to use:** immediately after install to confirm the whole boundary works; it's
  the recommended first command and is CI-safe (exit 0 on pass, non-zero on fail).
- **Common mistakes:** expecting it to touch your real `~/.agent-sudo` — it runs in a
  temporary directory by default (use `--output-dir` for a stable location). The printed
  `Next:` command inspects that same audit log.

### `demo`
- **Purpose:** run a built-in, offline demo of allow/deny/audit decisions.
- **Example:** `agent-sudo demo`
- **When to use:** a quick look at individual decisions; for the full value loop use
  `agent-sudo eval`.
- **Common mistakes:** treating it as a config check — it uses a temporary audit log,
  not your real one.

### `doctor`
- **Purpose:** report local readiness (Python version, policy, writable audit/
  delegation stores, approval config). Also WARNs when the **running install is
  stale** (an older copy is resolving ahead of a newer one on the machine) or
  when an **editable install has drifted** from its registered source — so a
  shell silently running an out-of-date copy is caught here, not in production.
  It also WARNs when **multiple active installs** are detected (more than one
  Agent_Sudo resolving on PATH or referenced by client configs), pointing you
  to `agent-sudo inventory` to pick one canonical install.
- **Example:** `agent-sudo doctor`
- **When to use:** right after install, or when something isn't working.
- **Common mistakes:** expecting it to validate your MCP client config — it checks the
  local Agent_Sudo install, not the client wiring (use `verify-routing` for that).
- **Note:** the staleness/drift checks are **WARN-only** — they never fail the
  exit code or change anything; run `agent-sudo inventory` for the full
  install map and `--version` to see which copy is running.

### `--version`
- **Purpose:** print the running version **and which copy is running it** —
  install type (editable / pinned wheel / source checkout), the source path,
  and the Python executable. A bare version number can't tell you whether the
  code you're editing is the code that's enforcing; this can.
- **Example:**
  ```
  agent-sudo --version
  agent-sudo v0.5.6
    install:  editable  (source: /Volumes/Storage/Agent_Sudo)
    python:   ~/.pyenv/versions/3.11.14/bin/python  (3.11.14)
  ```
- **When to use:** first check when a client seems to run stale code. The first
  line stays a bare `agent-sudo vX.Y.Z` so scripts can still parse it.
- **See also:** `inventory` for the full multi-install picture across the machine.

### `inventory`
- **Purpose:** read-only report of every Agent_Sudo install it can find (PATH,
  pipx, pyenv, venvs referenced by client configs), the MCP client configs that
  point at them (Claude Desktop, Claude Code, Codex, Gemini, Antigravity,
  Hermes), and how they relate: version drift, duplicate installs, stale
  copies, PATH shadowing, editable installs, configs pointing at missing
  binaries.
- **Example:** `agent-sudo inventory` (human report) or `agent-sudo inventory --json`
- **When to use:** when a client seems to run an old version, when you have
  installed Agent_Sudo more than one way, or before upgrading.
- **Common mistakes:** expecting it to fix anything — it never modifies,
  deletes, or uninstalls; every line ends in a recommendation you apply
  yourself. It also reads metadata instead of executing the binaries it finds,
  so a corrupted install shows as `UNKNOWN` rather than being run.

### `topology`
- **Purpose:** answer "what Agent_Sudo instances are guarding me right now, and
  what is **not** routed through Agent_Sudo?" Four sections: **CLI surfaces**
  (the `agent-sudo` your shell resolves), **MCP clients** (Claude Desktop,
  Gemini, Antigravity… with config path, command, version, and the audit log
  each writes to), **audit destinations** (which clients share which log), and
  **not routed** (MCP tooling present on the machine but not wired through
  Agent_Sudo — Smithery is the motivating example).
- **Example:** `agent-sudo topology` (human view) or `agent-sudo topology --json`
- **When to use:** when you can't tell which copy a terminal vs an IDE is using,
  or whether a separate MCP tool is bypassing the gateway.
- **Common mistakes:** treating "not routed" as an error — it is informational;
  a tool running outside Agent_Sudo is fine if that is intentional. Like
  `inventory`, it is **read-only**: no auto-fix, no cleanup. It is a regrouping
  of `inventory` data plus a presence check — run `inventory` for install-level
  drift/duplicate detail.

### `init-approval`
- **Purpose:** create (or reset) the local passphrase used to approve **critical**
  actions.
- **Example:** `agent-sudo init-approval`
- **When to use:** only if you want interactive human approval; the delegation flow
  does not need it.
- **Common mistakes:** re-running it to "fix" something — a reset **revokes all
  delegations and cancels pending approvals** (audit log is preserved).

### `workspace`  (`set` / `show`)
- **Purpose:** persist the project directory MCP clients should treat as the workspace.
- **Example:** `agent-sudo workspace set /abs/path/to/project` · `agent-sudo workspace show`
- **When to use:** with GUI clients (e.g. Claude Desktop) that launch the server from
  `/`, so context detection still resolves your project.
- **Common mistakes:** passing a relative path; use an absolute directory that exists.

### `context`
- **Purpose:** print the detected runtime workspace context as JSON.
- **Example:** `agent-sudo context --workspace /abs/path/to/project`
- **When to use:** to confirm what workspace the server will resolve.
- **Common mistakes:** confusing it with `workspace show` — `context` *detects/resolves*
  (cwd, env, persisted config); `workspace show` reports only the *persisted* value.

---

## Operational (live use)

### `agent-sudo-mcp`  (separate executable)
- **Purpose:** the stdio MCP server your agent client connects to; the live point where
  tool calls are gated, classified, and logged.
- **Example:** configured by your client; manually:
  `agent-sudo-mcp --audit-log ~/.agent-sudo/mcp-audit.jsonl --delegations-file ~/.agent-sudo/delegations.json --workspace /abs/project`
- **When to use:** always, indirectly — it runs whenever your MCP client is active.
- **Common mistakes:** omitting `--delegations-file` (delegations are then ignored) or
  leaving `--audit-log` relative (the log lands somewhere `audit list` won't read). See
  [MCP Server Setup](integrations/mcp_server_setup.md).

### `pending`
- **Purpose:** list active pending approval requests.
- **Example:** `agent-sudo pending`
- **When to use:** when the client reports `approval_required` and you need the id.
- **Common mistakes:** none significant. (Note: `agent-sudo approvals list` does the same
  thing — see [Overlaps](#overlapping--redundant-commands).)

### `approve` / `deny`
- **Purpose:** approve or deny a pending request by id.
- **Example:** `agent-sudo approve <approval_id>` · `agent-sudo deny <approval_id>`
- **When to use:** to release (or reject) a gated action.
- **Common mistakes:** trying to approve a **critical** action without having run
  `init-approval` (the passphrase is required); letting the request expire (default TTL
  120s) before approving.

### `approval-helper`
- **Purpose:** a guided terminal flow for handling pending requests.
- **Example:** `agent-sudo approval-helper`
- **When to use:** for an interactive approve/deny loop; the macOS
  `--open-approval-terminal` flag launches this automatically.
- **Common mistakes:** invoking with `--auto-opened` by hand — that's the minimal
  auto-close mode meant for the auto-spawned window.

### `delegate`  (`create` / `list` / `revoke`)
- **Purpose:** issue, list, and revoke scoped, self-expiring delegation tokens.
- **Example:**
  `agent-sudo delegate create --actor codex --allow-action run_shell_command --allow-path pwd --ttl-seconds 300 --max-uses 1 --critical --reason "demo"`
- **When to use:** to grant narrow unattended authority instead of approving each action.
- **Common mistakes:** writing the token to a different `--delegations-file` than the MCP
  server reads — they must match, or the token is ignored (`delegate create` warns when
  it falls back to the default store).

---

## Audit / investigation

### `audit list`
- **Purpose:** show recent decisions as a filterable table (with a provenance origin column).
- **Example:** `agent-sudo audit list` · `agent-sudo audit list ~/.agent-sudo/mcp-audit.jsonl --since 24h --non-allow`
- **When to use:** to review what the agent did and how each call was decided.
- **Common mistakes:** none. The command defaults to `~/.agent-sudo/mcp-audit.jsonl` (falling back to a project-local `.agent-sudo/mcp-audit.jsonl` if present in the current working directory).

### `audit review`
- **Purpose:** verify the chain, summarize recent decision counts, and list non-ALLOW rows
  for a window.
- **Example:** `agent-sudo audit review` · `agent-sudo audit review --since 24h`
- **When to use:** a quick "what needs attention recently" pass.
- **Common mistakes:** the flag is `--since` (e.g. `30m`, `24h`, `7d`), not `--window`.

### `audit trace`
- **Purpose:** trace one delegation token's lifecycle (scope, uses, expiry) across the log.
- **Example:** `agent-sudo audit trace <token_id>` · `agent-sudo audit trace <token_id> ~/.agent-sudo/mcp-audit.jsonl`
- **When to use:** to investigate how a specific delegation was used or denied.
- **Common mistakes:** expecting exact causal counts — store-state and log-observed
  quantities are reported separately and not claimed as definitive.

### `verify-audit`
- **Purpose:** verify the SHA-256 hash chain of an audit log (tamper detection).
- **Example:** `agent-sudo verify-audit` · `agent-sudo verify-audit ~/.agent-sudo/mcp-audit.jsonl`
- **When to use:** to prove the log hasn't been edited.
- **Common mistakes:** confusing it with `verify-routing` (below) — different question.

### `verify-routing`
- **Purpose:** report observed evidence of whether actions are flowing *through*
  Agent_Sudo (config state, audit activity, decision histogram, hash-chain integrity,
  best-effort client wiring).
- **Example:** `agent-sudo verify-routing`
- **When to use:** to sanity-check that your client is actually routed through the engine.
- **Common mistakes:** reading it as a guarantee — it reports observed signals and
  explicitly **cannot** certify complete protection. (It defaults to checking both the
  current directory and `~/.agent-sudo/mcp-audit.jsonl`.)

---

## Troubleshooting

`doctor`, `context`, and `verify-routing` (documented above) are the troubleshooting
trio: **`doctor`** for local install health, **`context`** for workspace resolution, and
**`verify-routing`** for "is my client actually protected?".

---

## Administrative

`init-approval` (passphrase lifecycle), `workspace set` (persisted workspace),
`delegate revoke` (pull a token), and **`upgrade-local`** below.

### `upgrade-local`
- **Purpose:** safely upgrade a local source-checkout install of Agent_Sudo.
- **Example:** `agent-sudo upgrade-local --check` (report only) · `agent-sudo upgrade-local`
- **When to use:** maintaining a `pip install -e .` checkout; **not** needed for `pipx`
  installs (use `pipx upgrade agent-sudo-mcp`).
- **Common mistakes:** running with local edits — it cleans generated artifacts unless you
  pass `--allow-dirty`.

---

## Integration / dev (single-tool-call evaluation)

These commands evaluate a **single tool-call JSON file** through the policy engine. They
are for embedding/testing the engine, not day-to-day operation. The argument is a path to
a JSON file you create (there is no inline-string form). Run `agent-sudo <command> --help`
to see the expected schema with a copy-pasteable example.

| Command | Input | Behavior |
| :--- | :--- | :--- |
| `check` | universal `ActionRequest` JSON | classify + decide, **dry-run** (no execution) |
| `run` | universal `ActionRequest` JSON | evaluate **with** approvals + audit logging |
| `generic-check` | universal tool-call JSON | normalize → classify, dry-run |
| `generic-run` | universal tool-call JSON | normalize → evaluate (`--dry-run` available) |
| `hermes-check` | Hermes native tool-call JSON | normalize → classify, dry-run |
| `codex-check` | Codex native tool-call JSON | normalize → classify, dry-run |

- **Example** (self-contained — works from any directory, no repo checkout):

  ```bash
  cat > /tmp/agent-sudo-tool-call.json <<'EOF'
  {"actor": "agent-a", "agent_type": "generic", "source": "user",
   "source_trust": "USER_DIRECT", "tool": "unknown_tool", "action": "inspect",
   "target": "/home/user/project", "payload_summary": "Inspect example project"}
  EOF
  agent-sudo generic-check /tmp/agent-sudo-tool-call.json
  ```
- **When to use:** wiring the engine into a runtime/adapter and verifying classification.
- **Common mistakes:** expecting these to honor delegations — the `*-check` variants are
  dry-run classifiers and do not consult a delegation store; live enforcement happens in
  `agent-sudo-mcp`.

---

## Discoverability notes

### Hidden options
- `workspace set --config` and `workspace show --config` are hidden (`argparse.SUPPRESS`)
  — internal test hooks, not for general use. No hidden *commands* exist; everything is
  listed in `agent-sudo --help`.

### Poorly documented (before this reference)
- `check`, `hermes-check`, `codex-check` had little user-facing documentation and an
  undocumented input schema (mitigated by the `--help` schema examples and the table above).
- `context` vs `workspace show` distinction was not stated anywhere.

### Overlapping / redundant commands
- **`pending` ≡ `approvals list`** — both list pending approval requests. `pending` is the
  documented shorthand; `approvals list` is redundant.
- **`check` / `generic-check` / `hermes-check` / `codex-check`** overlap — same operation,
  different input adapter. Likewise **`run` / `generic-run`**.
- **`verify-audit` vs `audit review`** — `audit review` also verifies the chain, so the two
  overlap on integrity checking (`audit review` adds summary + non-ALLOW rows).
- **`verify-audit` vs `verify-routing`** — confusable names, different questions (log
  integrity vs. routing evidence).

### Obsolete
- None confirmed obsolete. `approvals list` is the strongest consolidation candidate
  (fully covered by `pending`). Any change there is out of scope for this reference, which
  documents current behavior only.
