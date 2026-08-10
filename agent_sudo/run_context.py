"""Process-wide run-context stamp (issue #109).

Answers "which copy of Agent_Sudo produced this?" for the three surfaces a user
sees at the trust boundary: approval prompts, desktop notifications, and audit
entries. Built from the :mod:`agent_sudo.self_identity` primitive plus the
connected MCP client and the active workspace.

The running install, the client that connected, and the workspace are constant
for a process, so they live as process-global state set once at startup
(``set_client`` at MCP ``initialize``; ``set_workspace`` when the server/CLI
resolves its workspace). ``current()`` is captured *by the acting process* — so
the value stored on an approval record is the requester's identity, which the
separate approval-helper process then displays verbatim rather than recomputing
its own.

Minimum fields only (version, install_type, client, workspace, pid); this does
not redesign the approval flow or the audit schema beyond adding this block.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from agent_sudo.self_identity import SelfIdentity, describe_running_install

_client: str = ""
_workspace: str = ""


def set_client(name: str | None) -> None:
    """Record the connected client (e.g. MCP ``clientInfo.name``)."""
    global _client
    _client = (name or "").strip()


def set_workspace(workspace: str | None) -> None:
    """Record the active workspace path."""
    global _workspace
    _workspace = (workspace or "").strip()


@lru_cache(maxsize=1)
def _identity() -> SelfIdentity:
    return describe_running_install()


def _default_client(origin: str) -> str:
    # When no MCP client announced itself, a CLI invocation is still meaningful.
    if origin in {"console-script", "python -m"}:
        return "cli"
    return "unknown"


def current() -> dict[str, Any]:
    """Build the run-context for the *current* process, right now."""
    identity = _identity()
    return {
        "version": identity.version,
        "install_type": identity.install_type,
        "client": _client or _default_client(identity.origin),
        "workspace": _workspace,
        "pid": os.getpid(),
    }


def format_stamp(ctx: dict[str, Any] | None) -> str:
    """One-line human stamp for prompts: which copy, which client, where."""
    if not ctx:
        return ""
    parts = [f"agent-sudo {ctx.get('version', '?')} ({ctx.get('install_type', '?')})"]
    client = str(ctx.get("client") or "")
    if client and client != "unknown":
        parts.append(f"client={client}")
    workspace = str(ctx.get("workspace") or "")
    if workspace:
        parts.append(f"ws={_tilde(workspace)}")
    pid = ctx.get("pid")
    if pid:
        parts.append(f"pid={pid}")
    return " · ".join(parts)


def format_notification_stamp(ctx: dict[str, Any] | None) -> str:
    """Compact stamp for the length-limited desktop notification body."""
    if not ctx:
        return ""
    return f"via agent-sudo {ctx.get('version', '?')} ({ctx.get('install_type', '?')})"


def _tilde(path: str) -> str:
    home = str(Path.home())
    return path.replace(home, "~", 1) if path.startswith(home) else path


def reset_for_tests() -> None:
    """Clear process-global state and the identity cache (test helper)."""
    global _client, _workspace
    _client = ""
    _workspace = ""
    _identity.cache_clear()
