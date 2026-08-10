# Integrations

One local authorization and provenance engine. Any agent. Routed tool calls checked.

The integration pattern is the same for every runtime:

1. Convert the native tool call to the universal schema.
2. Convert the universal schema to `ActionRequest`.
3. Pass the request through `SafeToolExecutor`.
4. Execute only when the gateway returns `ALLOW`.

## Codex

```json
{
  "actor": "codex",
  "agent_type": "codex",
  "source": "user",
  "source_trust": "USER_DIRECT",
  "tool": "filesystem",
  "action": "edit_file",
  "target": "/home/user/example/project/README.md",
  "payload_summary": "Edit documentation",
  "payload_hash": "sha256:example-placeholder",
  "requested_at": "2026-01-01T00:00:00Z",
  "session_id": "session-codex-example"
}
```

## Hermes

```json
{
  "actor": "hermes",
  "agent_type": "hermes",
  "source": "user",
  "source_trust": "USER_DIRECT",
  "tool": "shell",
  "action": "run_shell_command",
  "target": "echo hello",
  "payload_summary": "Run harmless local command",
  "payload_hash": "sha256:example-placeholder",
  "requested_at": "2026-01-01T00:00:00Z",
  "session_id": "session-hermes-example"
}
```

Shell requests normalize to `run_shell_command`, which is `CRITICAL` under the default policy.

> [!NOTE]
> For details on experimental Hermes integration design and local Proof of Concept findings, see the [Hermes Integration Research Note](hermes-research.md).

## Claude Desktop

```json
{
  "actor": "claude-desktop",
  "agent_type": "claude_desktop",
  "source": "user",
  "source_trust": "USER_DIRECT",
  "tool": "filesystem",
  "action": "edit_file",
  "target": "/home/user/example/project/notes.md",
  "payload_summary": "Edit notes",
  "payload_hash": "sha256:example-placeholder",
  "requested_at": "2026-01-01T00:00:00Z",
  "session_id": "session-claude-example"
}
```

## OpenClaw

```json
{
  "actor": "openclaw",
  "agent_type": "openclaw",
  "source": "user",
  "source_trust": "USER_DIRECT",
  "tool": "browser",
  "action": "browser_click",
  "target": "button-1",
  "payload_summary": "Click a browser button",
  "payload_hash": "sha256:example-placeholder",
  "requested_at": "2026-01-01T00:00:00Z",
  "session_id": "session-openclaw-example"
}
```

## Generic Agent

First write a universal tool-call file (self-contained — no repo checkout needed):

```bash
cat > /tmp/agent-sudo-tool-call.json <<'EOF'
{"actor": "agent-a", "agent_type": "generic", "source": "user",
 "source_trust": "USER_DIRECT", "tool": "unknown_tool", "action": "inspect",
 "target": "/home/user/project", "payload_summary": "Inspect example project"}
EOF
```

Use `generic-check` to inspect it:

```bash
agent-sudo generic-check /tmp/agent-sudo-tool-call.json
```

Use `generic-run --dry-run` to evaluate without execution:

```bash
agent-sudo generic-run /tmp/agent-sudo-tool-call.json --dry-run
```

## MCP Tool Wrapper

MCP-style wrappers should build a universal request before invoking a tool:

```python
from agent_sudo.adapters.mcp import from_mcp_tool_call
from agent_sudo.executors import SafeToolExecutor

request = from_mcp_tool_call(tool_call)
result = safe_executor.dry_run(request)
```

For real execution, wrap the concrete tool executor behind `SafeToolExecutor`.
Do not call the underlying tool directly.
