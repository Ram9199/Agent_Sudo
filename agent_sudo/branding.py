"""Compact, gated Agent_Sudo wordmark for human-facing interactive commands.

Design constraints (deliberately minimal):
- One short line, no ASCII art, no multi-line logo, no animation.
- Shown only on an interactive TTY, never in CI / pipes / scripts / MCP server.
- No persistent "first run" tracking — gating is purely on the invocation.
- Optional dim styling, suppressed under NO_COLOR.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from agent_sudo import __version_label__

TAGLINE = "Authorization · Delegation · Provenance · Audit"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _env_set(name: str) -> bool:
    """True when an env var is present and not an explicit falsey value."""
    return os.environ.get(name) not in (None, "", "0", "false", "False")


def should_show_wordmark(stream: TextIO | None = None) -> bool:
    """Whether to print the wordmark for this invocation.

    Show only when the stream is an interactive TTY and we are not in CI (or an
    explicit opt-out). This keeps it off pipes, scripts, automation, and the
    MCP server. NO_COLOR does not suppress the wordmark — it only disables
    styling (see :func:`wordmark`).
    """
    stream = stream if stream is not None else sys.stderr
    if _env_set("CI") or _env_set("AGENT_SUDO_NO_BANNER"):
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def wordmark(*, color: bool | None = None) -> str:
    """The compact one-line wordmark, e.g.::

        Agent_Sudo vX.Y.Z · Authorization · Delegation · Provenance · Audit

    ``color`` forces styling on/off; when None, styling is applied unless
    NO_COLOR is set.
    """
    text = f"Agent_Sudo {__version_label__} · {TAGLINE}"
    use_color = (not _env_set("NO_COLOR")) if color is None else color
    if use_color:
        return f"{_DIM}{text}{_RESET}"
    return text


def print_wordmark(stream: TextIO | None = None) -> bool:
    """Print the wordmark to ``stream`` (stderr by default) if gating allows.

    Returns True if it was printed. Styling is gated on the stream being a TTY
    too, so a NO_COLOR-unset but redirected stream still gets plain text.
    """
    stream = stream if stream is not None else sys.stderr
    if not should_show_wordmark(stream):
        return False
    stream.write(wordmark() + "\n")
    stream.flush()
    return True
