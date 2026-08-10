# Release Checklist

Use this checklist before publishing `agent-sudo`.

## Required Checks

- [ ] Run personal-data scan: `python3 scripts/check_no_personal_data.py`
- [ ] Run tests: `python3 -m unittest discover -s tests`
- [ ] Review `README.md` for clarity and current commands
- [ ] Review `SECURITY.md` for disclosure guidance and limitations
- [ ] Confirm `LICENSE` exists and is Apache-2.0
- [ ] Check editable package install: `python3 -m pip install -e .`
- [ ] If system Python blocks editable install, verify in a virtual environment
- [ ] Run `agent-sudo doctor`
- [ ] Run the one-command proof (no repo files needed): `agent-sudo eval`
- [ ] Run a self-contained classifier check (verifies a pip-only install with no
  repo checkout):
  ```bash
  cat > /tmp/agent-sudo-tool-call.json <<'EOF'
  {"actor": "agent-a", "agent_type": "generic", "source": "user",
   "source_trust": "USER_DIRECT", "tool": "unknown_tool", "action": "inspect",
   "target": "/home/user/project", "payload_summary": "Inspect example project"}
  EOF
  agent-sudo generic-check /tmp/agent-sudo-tool-call.json
  ```

## Known Limitations

- `agent-sudo` cannot override an agent's system prompt.
- `agent-sudo` cannot protect tools the agent can still access directly.
- Enforcement requires routing tool execution through `agent-sudo`.
- Audit hash chains detect tampering but do not prevent local deletion or replacement.
- Setup commands are dry-run checklists and do not edit agent runtime config.
- The prompt-injection detector is a primitive phrase detector, not a full content-security system.
