# Security & Threat Model

This document outlines the security boundaries, threat mitigation strategies, and design limitations of `Agent_Sudo`.

---

## 1. Authorization and Responsibility Boundaries

`Agent_Sudo` is a **local authorization, delegation, provenance, and verifiable-audit engine for AI agents**. It intercepts and authorizes tool actions requested by an AI agent before they are executed.

> [!IMPORTANT]
> - **Not the action owner**: `Agent_Sudo` does not execute downstream actions itself. The operator and concrete tool provider (e.g. your shell executor or file writer) remain responsible for the safe handling of the action.
> - **Policy and Auditing only**: `Agent_Sudo` provides authorization, interactive user approval, scoped delegation, transparency, and logging. It acts as a safety gate, not a sandbox or containment chamber.
> - **The shipped MCP server is a reference**: its `write_file` (scoped to `/tmp/agent-sudo-demo`) and `run_shell_command` (narrow allowlist) tools are **demo executors** that showcase gating. The engine is designed to be embedded in an agent/runtime that owns execution; to gate real tools, integrate the library rather than relying on the demo executors.

---

## 2. Threat Mitigation Profile

### What Agent_Sudo Enforces:
- **Excessive Agency / Accidental Executions**: Requires explicit human consent before agents run commands or mutate critical files.
- **Untrusted-Origin Actions**: Actions whose provenance is external content (e.g. instructions hidden in read files or web pages) are upgraded to require human validation based on *where the instruction came from*, independent of its wording.
- **Insecure Tools / Over-permissioning**: Normalizes and filters raw tool calls into structured, checked actions (e.g. classifying writes to source files as critical).
- **Log Tampering**: Implements append-only verification of local audit logs to detect post-hoc alterations by compromised agents.

### Best-Effort Signals (not enforcement boundaries):
- **Injection phrase detector**: Flags a small set of literal override strings (e.g. "ignore previous instructions") as a **tripwire signal**. It is trivially bypassed by paraphrasing or encoding and must **not** be relied on as prompt-injection protection — the real mitigation is the provenance-based escalation above.
- **Shell command screening**: Pattern-based scans for common bypass shapes (`../`, `$VAR` expansion, `bash -c`, copy/pipe utilities). Best-effort, not a complete shell parser; pair with OS-level containment for a real boundary.

### What Agent_Sudo Does NOT Protect Against:
- **Direct Tool Access (Bypasses)**: If the agent has access to alternate tools that do not route their operations through the `Agent_Sudo` gateway (e.g., a native tool with shell execution capability that doesn't use `Agent_Sudo`), `Agent_Sudo` cannot block or audit those actions.
- **Compromised CLI Environment**: If the local shell session or terminal is fully compromised, an attacker can directly approve pending actions or tamper with the local configuration files.
- **Control-plane mutation via ungoverned host tools**: An agent with a host-native shell (one that does not route through `Agent_Sudo`) can run `agent-sudo workspace set`, or edit config/delegation files, to *move* the enforcement boundary rather than cross it. `Agent_Sudo` cannot prevent this — the mitigation is to disable or route the agent's native shell. To make it detectable, workspace changes are recorded as `workspace_changed` audit events (old/new workspace, timestamp, CLI/local provenance), so a boundary change is visible to `agent-sudo verify-audit` even when made outside the gateway.
- **Passive Data Leaks (outside protected paths)**: Safe read paths (e.g., reading a standard document) are allowed automatically. If a document contains a API key that isn't in a protected config path, `Agent_Sudo` won't prevent the agent from reading and potentially exfiltrating it via normal allowed tools.

### Default Trust Posture (Fail Closed)

`Agent_Sudo` evaluates `source` / `source_trust` / `provenance.origin_type` on each request. The default posture is **fail closed**:

- **Missing provenance is untrusted.** A request that arrives without a trustworthy trust signal — no `source_trust`, no `provenance` — is treated as `UNKNOWN`, not `USER_DIRECT`. For a SAFE action this means it is escalated to `REQUIRE_APPROVAL` rather than allowed silently. This applies uniformly across the MCP JSON-RPC boundary, the `ActionRequest.from_dict` path, and the `ActionRequest` constructor default.
- **Contradictory provenance is reconciled, not trusted.** When an explicit `source_trust` claims *more* trust than its `source` / `origin_type` evidence supports (e.g. `source="webpage"` or `origin_type="EXTERNAL_CONTENT"` with `source_trust="USER_DIRECT"`), the claim is downgraded to the most restrictive level the evidence supports (`EXTERNAL_CONTENT`/`UNKNOWN`), an `inconsistent_provenance` reason is recorded on the decision and audit entry, and the action escalates to at least `REQUIRE_APPROVAL` (actions whose policy tier is `CRITICAL` retain `REQUIRE_STRONG_APPROVAL`). The check is **downgrade-only** — a caller may always self-restrict to a *lower* trust — and neutral/absent signals never trigger it.
- **Explicit, consistent trust is honored.** A caller that asserts `source_trust=USER_DIRECT` with agreeing `source`/`origin_type` (or attests provenance) is taken at its word and behaves exactly as before.

> **Known limitation — provenance is self-attested.** Trust is only as trustworthy as the component that stamps it. Today that component is the **host/runtime that constructs the tool call**; `Agent_Sudo` does not yet bind trust elevation to a host-issued credential. An adversarial agent that consistently forges `USER_DIRECT` provenance is still believed. Fail-closed defaults protect against an *honest-but-confused* caller that omits provenance — **not** against a *compromised* caller that lies about it. Closing this gap (host attestation / nonce binding) is tracked separately and intentionally out of scope for the fail-closed defaults. See [`docs/reports/provenance_trust_audit.md`](../reports/provenance_trust_audit.md).

---

## 3. Approvals and Delegation Lifecycle

### Approval Lifecycle
1. **Request**: The agent sends an `ActionRequest` via the MCP server or CLI wrapper.
2. **Classification**: The gateway classifies the action based on active policies:
   - `SAFE` -> Allowed immediately.
   - `SENSITIVE` -> Requires standard `REQUIRE_APPROVAL` (yes/no confirm).
   - `CRITICAL` -> Requires strong `REQUIRE_STRONG_APPROVAL` (passphrase confirm).
   - `BLOCKED` -> Rejected immediately.
3. **Pending Store**: In non-interactive contexts (like MCP), requests requiring approval are written to a temporary local pending file with a unique ID and a short TTL (default 120 seconds).
4. **Interactive Validation**: The operator reviews the request via `agent-sudo pending` and approves it (`agent-sudo approve <id>`).
5. **Consumption**: Once approved, the next matching request from the agent is permitted to execute, and the approval token is immediately marked `USED`.

### Delegation Lifecycle
Delegation allows users to issue temporary, scoped tokens for specific agents:
1. **Creation**: The user creates a token detailing an `actor`, `allow-action`, `allow-path`, and constraint parameters (maximum usage counts, specific Time-to-Live).
2. **Evaluation**: When a matching action is requested, the gateway checks the delegation store. If a valid, unexpired, and unexhausted token matches the actor, action, and target path, the request is allowed immediately.
3. **Usage tracking**: The token's usage count is incremented. Once the count or TTL expires, the token is treated as invalid.

---

## 4. Audit Log Guarantees

Every decision, execution result, and approval attempt is logged to a local JSONL file.

Each entry also carries a `run_context` block identifying the Agent_Sudo process that produced it — `version`, `install_type` (editable/pinned-wheel/source-checkout), `client` (the connected MCP client, e.g. claude-desktop/antigravity, or `cli`), `workspace`, and `pid`. The same block is attached to each pending-approval record and shown on the approval prompt and desktop notification, so the copy of Agent_Sudo that requested an approval is the copy named in the prompt and the audit trail. The field is additive (covered by the hash, ignored by older readers).

To prevent an agent from deleting or editing logs to cover its tracks, `Agent_Sudo` implements a **SHA-256 hash chain**:
- Each log entry contains an `entry_hash` and a `previous_hash`.
- The `entry_hash` is calculated by hashing the current log content concatenated with the `entry_hash` of the preceding record:
  `entry_hash = sha256(previous_hash + canonical_json(current_entry_without_hash))`
- Any insertion, deletion, or modification of historical log records will break the hash chain.
- The chain can be audited at any time using:
  ```bash
  agent-sudo verify-audit /path/to/mcp-audit.jsonl
  ```

---

## 5. Known Limitations

- **State File Isolation**: The configuration (`config.json`), delegation store (`delegations.json`), and pending approvals (`pending_approvals.json`) are stored in the user's home folder under `~/.agent-sudo/`. While protected, any tool running with the user's local permissions can read these files.
- **Process Identifiers**: Standard MCP tool calls do not carry authenticable operating system process IDs. The gateway relies on structural provenance tags to identify the calling `actor`.

---

## 6. Future Hardening Strategies

Planned enhancements for future releases of `Agent_Sudo` include:
- **File Locks**: Prevent concurrent processes from modifying policy, delegation, and approval states during evaluation.
- **Approval Nonce Binding**: Require the agent client to send a unique cryptographic nonce with its retry request to ensure the retry matches the approved ticket exactly.
- **Read-Root Allowlists**: Restrict all reads to explicitly designated workspace roots, blocking access to other filesystem paths entirely even for `SAFE` tools.
- **Policy Sealing**: Allow the policy file to be cryptographically signed by the user, refusing to run the gateway if the signature is invalid or modified.
- **Signed Delegation Tokens**: Issue cryptographic tokens that can be verified off-line, removing the need for a mutable local delegation store file.
