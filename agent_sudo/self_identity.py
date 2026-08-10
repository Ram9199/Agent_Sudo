"""Self-identity of the *running* Agent_Sudo install (issue #108).

A permission tool must be able to say which copy of itself is guarding the
user. This module answers that for the **current process**: version, how it
was installed (editable / pinned wheel / source checkout), where its source
lives, which Python is running it, and how it was invoked.

It is the primitive consumed by ``--version`` (provenance block), the
run-context stamp on approvals/audit (#109), and ``doctor`` staleness
detection (#110). Detection of the editable source from a ``direct_url.json``
is shared with :mod:`agent_sudo.inventory` via :func:`parse_direct_url` so the
logic exists in exactly one place.

Strictly read-only: it inspects this interpreter's own metadata and never
executes anything.
"""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

DIST_NAME = "agent_sudo_mcp"
_CONSOLE_SCRIPTS = ("agent-sudo", "agent-sudo-mcp")


def parse_direct_url(text: str) -> tuple[bool, str]:
    """Parse a PEP 610 ``direct_url.json`` body.

    Returns ``(editable, source_path)``. ``editable`` is True only when the
    install was done with ``pip install -e``; ``source_path`` is the local
    path the install points at (``file://`` stripped), or "" when the URL is
    not a local path. Shared by :mod:`agent_sudo.inventory`.
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return False, ""
    if not isinstance(data, dict):
        return False, ""
    url = str(data.get("url", ""))
    source = url.removeprefix("file://") if url.startswith("file://") else ""
    editable = bool(data.get("dir_info", {}).get("editable")) if source else False
    return editable, source


@dataclass(frozen=True)
class SelfIdentity:
    version: str
    install_type: str  # "editable" | "pinned-wheel" | "source-checkout" | "unknown"
    source_path: str  # editable target or site-packages location of the package
    package_path: str  # the imported agent_sudo package directory
    python_executable: str
    python_prefix: str
    python_version: str
    origin: str  # "console-script" | "python -m" | "embedded"

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "install_type": self.install_type,
            "source_path": self.source_path,
            "package_path": self.package_path,
            "python_executable": self.python_executable,
            "python_prefix": self.python_prefix,
            "python_version": self.python_version,
            "origin": self.origin,
        }


def _read_direct_url() -> str | None:
    """Return the running distribution's ``direct_url.json`` text, if any.

    Name-based ``metadata.distribution(...)`` is unreliable: when a stale
    ``*.egg-info``/``*.dist-info`` shadows the real install on ``sys.path``
    (e.g. ``python -m agent_sudo.gateway`` from the repo root, where CWD is on
    the path), the lookup can return the stale entry, which has no
    ``direct_url.json`` — making an editable install look like a bare source
    checkout. So enumerate every distribution matching the name and return the
    first ``direct_url.json`` actually present.
    """
    try:
        from importlib import metadata

        dists = list(metadata.distributions())
    except Exception:
        return None
    canonical = DIST_NAME.replace("_", "-").lower()
    for dist in dists:
        try:
            name = str(dist.metadata["Name"] or "").replace("_", "-").lower()
        except Exception:
            continue
        if name != canonical:
            continue
        try:
            text = dist.read_text("direct_url.json")
        except Exception:
            text = None
        if text:
            return text
    return None


def _resolve_install(package_path: Path) -> tuple[str, str]:
    """Classify the running install. Returns ``(install_type, source_path)``."""
    direct_url = _read_direct_url()
    if direct_url is not None:
        editable, source = parse_direct_url(direct_url)
        if editable:
            return "editable", source or str(package_path.parent)
        # direct_url present but not editable: installed from a local path or
        # VCS pin, but materialised as a normal (copied) install — treat as a
        # pinned wheel for staleness purposes (it does not track its source).
        return "pinned-wheel", str(package_path)
    # No direct_url metadata.
    if _is_under_site_packages(package_path):
        return "pinned-wheel", str(package_path)
    # Imported straight from a checkout that was never installed.
    return "source-checkout", str(package_path.parent)


def _is_under_site_packages(package_path: Path) -> bool:
    return any(
        parent.name in {"site-packages", "dist-packages"}
        for parent in package_path.parents
    )


def _detect_origin(argv0: str) -> str:
    name = Path(argv0).name
    if name in _CONSOLE_SCRIPTS:
        return "console-script"
    if name in {"gateway.py", "__main__.py"} or name.startswith("__main__"):
        return "python -m"
    # Imported as a library (e.g. the in-process MCP server) rather than run
    # via a CLI entry point.
    return "embedded"


def describe_running_install(argv0: str | None = None) -> SelfIdentity:
    """Describe the Agent_Sudo install backing the current process."""
    import agent_sudo

    version = getattr(agent_sudo, "__version__", "") or "unknown"
    package_path = Path(agent_sudo.__file__).resolve().parent
    install_type, source_path = _resolve_install(package_path)
    return SelfIdentity(
        version=version,
        install_type=install_type,
        source_path=source_path,
        package_path=str(package_path),
        python_executable=sys.executable or "",
        python_prefix=sys.prefix,
        python_version=platform.python_version(),
        origin=_detect_origin(argv0 if argv0 is not None else (sys.argv[0] or "")),
    )


def format_version_block(identity: SelfIdentity, *, version_label: str) -> str:
    """Render the provenance block printed by ``agent-sudo --version``.

    The first line is kept byte-identical to the historical bare output
    (``agent-sudo <label>``) so scripts parsing the version still work; the
    provenance follows on indented lines.
    """
    home = str(Path.home())

    def tilde(path: str) -> str:
        return path.replace(home, "~", 1) if path and path.startswith(home) else path

    if identity.install_type == "editable":
        install_line = f"editable  (source: {tilde(identity.source_path)})"
    elif identity.install_type == "source-checkout":
        install_line = f"source checkout  ({tilde(identity.source_path)})"
    elif identity.install_type == "pinned-wheel":
        install_line = f"pinned wheel  ({tilde(identity.package_path)})"
    else:
        install_line = f"unknown  ({tilde(identity.package_path)})"

    # The human block answers one question: which copy is guarding you. It
    # deliberately omits `origin` (console-script / python -m / embedded) —
    # that's an invocation-mechanism detail useful to downstream consumers
    # (see to_dict()), not to a user reading `--version`.
    lines = [
        f"agent-sudo {version_label}",
        f"  install:  {install_line}",
        f"  python:   {tilde(identity.python_executable)}  ({identity.python_version})",
    ]
    return "\n".join(lines)
