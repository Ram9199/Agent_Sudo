# Evaluate Agent_Sudo in 5 Minutes

This is the primary first-time evaluator path for Agent_Sudo (v0.5.x).

You do not need to understand the internal architecture first. You only need to see this loop work:

```text
blocked
↓
delegated
↓
allowed once
↓
blocked again
↓
audit verified
```

## Fastest path: `agent-sudo eval`

**Recommended (via pipx):**
```bash
pipx install agent-sudo-mcp
agent-sudo eval
```

**Alternative (via virtual environment):**
```bash
python3 -m venv venv && source venv/bin/activate
pip install agent-sudo-mcp
agent-sudo eval
```

`agent-sudo eval` runs the entire loop in one shot — in a temporary directory, with no changes to your `~/.agent-sudo` state — and prints a PASS/FAIL ladder plus the audit-log path:

```text
Agent_Sudo Evaluation

[1/5] Blocked unsafe request ........ PASS
[2/5] Created delegation ............ PASS
[3/5] Delegated request allowed ..... PASS
[4/5] Token exhausted, denied again . PASS
[5/5] Audit chain verified .......... PASS

Result: PASS
Audit log: /tmp/agent-sudo-eval-.../audit.jsonl
Next: agent-sudo audit list /tmp/agent-sudo-eval-.../audit.jsonl
```

It exits `0` when all five steps pass and non-zero otherwise (so it is safe in CI). `--json` emits a machine-readable report; `--output-dir DIR` writes the artifacts to a location you choose. Inspect the recorded decisions with the printed `Next:` command, or verify the chain with `agent-sudo verify-audit <audit log>`.

That is the whole evaluation. The manual, step-by-step walkthrough below is optional — it shows the same loop driven explicitly through the MCP server, for readers who want to see each request.

## What You Will Prove

- `agent-sudo-mcp` receives a critical shell request.
- The request is blocked before execution.
- A one-use delegation allows the exact same request once.
- The same request is blocked again after the delegation is consumed.
- The audit log shows the decisions and verifies cleanly.
- `verify-routing` reports the currently configured routing and audit signals.

## 0. Install or Use a Checkout

For a published install:

**Option 1: Recommended (via pipx)**
```bash
pipx install agent-sudo-mcp
agent-sudo --version
```

**Option 2: Alternative (via virtual environment)**
```bash
python3 -m venv venv && source venv/bin/activate
pip install agent-sudo-mcp
agent-sudo --version
```

For a source checkout:

```bash
python3 -m pip install -e .
python3 -m agent_sudo.gateway --version
```

`agent-sudo --version` prints the installed version (e.g. `agent-sudo v0.5.x`) followed by a provenance block — install type (editable / pinned wheel / source checkout), source path, and the Python running it. The version should match the [PyPI badge](https://pypi.org/project/agent-sudo-mcp/) in the README, and the source path should be the install you expect to be using.

If `agent-sudo --version` shows an older version than the one you just installed — or an `install:`/`python:` line pointing at a copy you didn't expect — your shell is resolving a stale `agent-sudo` ahead of this install. Use the `python3 -m agent_sudo.gateway ...` fallback commands below, or reinstall Agent_Sudo in your active environment. For the full picture across every install on the machine, run `agent-sudo inventory`.

> The `agent-sudo-mcp` MCP server used in the steps below is installed by `pipx install agent-sudo-mcp`, `pip install agent-sudo-mcp`, and `pip install -e .`, so the evaluation runs the same way from a published install or a source checkout.

## 1. Prepare Temporary Evaluation State

Use `/tmp` so the evaluation does not create audit or delegation files in your project checkout:

```bash
rm -rf /tmp/agent-sudo-eval
mkdir -p /tmp/agent-sudo-eval

export AGENT_SUDO_AUDIT=/tmp/agent-sudo-eval/audit.jsonl
export AGENT_SUDO_DELEGATIONS=/tmp/agent-sudo-eval/delegations.json
```

## 2. Block a Critical MCP Request

Send one `run_shell_command` request for `pwd` through the MCP server:

```bash
python3 - <<'PY'
import json
import os
import subprocess

process = subprocess.Popen(
    [
        "agent-sudo-mcp",
        "--audit-log",
        os.environ["AGENT_SUDO_AUDIT"],
        "--delegations-file",
        os.environ["AGENT_SUDO_DELEGATIONS"],
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

def request(message):
    process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline().decode())

request({
    "jsonrpc": "2.0",
    "id": "init",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "agent-sudo-eval", "version": "0"},
    },
})

response = request({
    "jsonrpc": "2.0",
    "id": "pwd-1",
    "method": "tools/call",
    "actor": "codex",
    "params": {
        "name": "run_shell_command",
        "arguments": {"command": "pwd"},
    },
})

content = response["result"]["structuredContent"]
print("pwd-1", content["approval_decision"], content["execution_result"]["executed"])

process.stdin.close()
process.wait(timeout=2)
PY
```

Expected output:

```text
pwd-1 REQUIRE_STRONG_APPROVAL False
```

Meaning: the critical shell request reached Agent_Sudo and did not execute.

## 3. Delegate Exactly One Use

Create a delegation for one actor, one action, one target, and one use:

```bash
agent-sudo delegate create \
  --actor codex \
  --allow-action run_shell_command \
  --allow-path pwd \
  --ttl-seconds 300 \
  --max-uses 1 \
  --critical \
  --reason "5-minute evaluator pwd demo" \
  --delegations-file "$AGENT_SUDO_DELEGATIONS"
```

Source-checkout fallback:

```bash
python3 -m agent_sudo.gateway delegate create \
  --actor codex \
  --allow-action run_shell_command \
  --allow-path pwd \
  --ttl-seconds 300 \
  --max-uses 1 \
  --critical \
  --reason "5-minute evaluator pwd demo" \
  --delegations-file "$AGENT_SUDO_DELEGATIONS"
```

## 4. Allow Once, Then Block Again

Run the same MCP request twice:

```bash
python3 - <<'PY'
import json
import os
import subprocess

process = subprocess.Popen(
    [
        "agent-sudo-mcp",
        "--audit-log",
        os.environ["AGENT_SUDO_AUDIT"],
        "--delegations-file",
        os.environ["AGENT_SUDO_DELEGATIONS"],
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

def request(message):
    process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline().decode())

request({
    "jsonrpc": "2.0",
    "id": "init",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "agent-sudo-eval", "version": "0"},
    },
})

for request_id in ["pwd-2", "pwd-3"]:
    response = request({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "actor": "codex",
        "params": {
            "name": "run_shell_command",
            "arguments": {"command": "pwd"},
        },
    })
    content = response["result"]["structuredContent"]
    execution = content["execution_result"]
    print(
        request_id,
        content["approval_decision"],
        content["approval_method"],
        execution["executed"],
        execution["reason"],
    )

process.stdin.close()
process.wait(timeout=2)
PY
```

Expected output:

```text
pwd-2 ALLOW DELEGATION True executed
pwd-3 DENY DELEGATION False delegation token <token_id> mismatched: token exhausted
```

Meaning: the scoped token allowed exactly one matching request, then stopped working.

## 5. Inspect and Verify the Audit Trail

List the observed decisions from this evaluation:

```bash
agent-sudo audit list --limit 5 "$AGENT_SUDO_AUDIT"
```

Source-checkout fallback:

```bash
python3 -m agent_sudo.gateway audit list --limit 5 "$AGENT_SUDO_AUDIT"
```

Look for the stable `run_shell_command` / `pwd` sequence:

```text
REQUIRE_STRONG_APPROVAL
ALLOW
DENY
```

The table may also include auxiliary MCP approval rows. Those are not the activation proof; the proof is the `pwd` request being blocked, allowed once by delegation, then blocked again.

Verify audit integrity:

```bash
agent-sudo verify-audit "$AGENT_SUDO_AUDIT"
```

Source-checkout fallback:

```bash
python3 -m agent_sudo.gateway verify-audit "$AGENT_SUDO_AUDIT"
```

Expected output:

```text
audit log verified
```

## 6. Check Routing Evidence

Run the read-only routing report:

```bash
agent-sudo verify-routing
```

Source-checkout fallback:

```bash
python3 -m agent_sudo.gateway verify-routing
```

This reports configured/default routing evidence: configuration state, audit record count, last observed decision, decision histogram, hash-chain integrity, and best-effort MCP client wiring. It does not certify that every client tool is protected.

Note: this command reads the configured/default audit location, not necessarily the temporary `/tmp/agent-sudo-eval/audit.jsonl` file used above. For the evaluation proof, rely on the explicit `audit list "$AGENT_SUDO_AUDIT"` and `verify-audit "$AGENT_SUDO_AUDIT"` commands.

## Evaluation Success Criteria

You reached meaningful value when you can answer yes to all five:

- Did the first shell request get blocked before execution?
- Did the one-use delegation allow the exact same request once?
- Did the repeated request get blocked after delegation exhaustion?
- Did `audit list` show the decisions?
- Did `verify-audit` report `audit log verified`?

## Where Evaluators May Abandon

| Point | Severity | Likely cause | Documentation fix |
| :--- | :--- | :--- | :--- |
| Install command | High | `pipx` is missing or PATH is not refreshed | Keep source-checkout and `python3 -m ...` fallbacks next to every command that matters. |
| Version check | High | Shell resolves an older installed `agent-sudo` before the checkout | Tell evaluators to compare `agent-sudo --version` with `python3 -m agent_sudo.gateway --version` and use the checkout fallback if needed. |
| Choosing a path | High | README offers demo, quickstart, MCP setup, framework examples, and architecture before value | Make this guide the single primary CTA and move other paths below first value. |
| MCP client setup | High | Claude Desktop or another MCP client adds external config and restart friction | Do not require a real client for first value; use the documented subprocess MCP request first. |
| Passphrase setup | Medium | User is not ready to create local approval state during evaluation | Use delegation for the first evaluation path; keep passphrase setup in client setup docs. |
| Long Python snippets | Medium | Copy/paste fatigue or fear that the demo is implementation work | Label snippets as an MCP client simulator and show the expected one-line output immediately after each. |
| Delegation command | Medium | The user does not know why `--allow-path pwd` is the target | State that this grants only actor `codex` one use of `run_shell_command` for target `pwd`. |
| Exhaustion output | Low | Error text includes a generated token id and may not exactly match | Show the stable parts: `DENY`, `DELEGATION`, `False`, and `token exhausted`. |
| Audit list | Medium | Empty or stale log from the wrong path | Use explicit `/tmp/agent-sudo-eval/audit.jsonl` and pass it to every audit command. |
| Verify-routing | Low | The command reports limits instead of saying protected | Say upfront that it reports observed signals and cannot certify complete protection. |
| Trust boundary section | Medium | User reads limitations before seeing value and assumes nothing works | Put trust boundaries after the 5-minute proof in the README. |
