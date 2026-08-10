# Agent Install Prompt

Copy and paste this prompt into a local agent:

```text
Install agent-sudo from this repository.

Do not disable existing safety controls.
Do not expose secrets, credentials, auth files, local config, audit logs, or personal data.
Do not print environment variables or credential files.

Before changing anything, run:
python3 scripts/check_no_personal_data.py
python3 -m unittest discover -s tests

Install locally using:
python3 -m pip install -e .

Run:
agent-sudo doctor
agent-sudo init-approval
agent-sudo eval   # one-command proof: blocked -> delegated -> allowed-once -> denied -> audit verified

Route dangerous tools through agent-sudo before execution.
Do not leave direct shell, browser, email, messaging, file-write, or credential tools available when they can be routed through agent-sudo instead.

Use dry-run verification before enabling execution.
Show the exact wrapper or proxy plan before editing any agent runtime config.
```
