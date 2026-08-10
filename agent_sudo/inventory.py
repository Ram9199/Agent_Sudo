"""Read-only install/config inventory for issue #101.

Discovers Agent_Sudo installations and the MCP client configurations that
reference them, then classifies what it found (ACTIVE / STALE / VERSION DRIFT
/ DUPLICATE INSTALL / UNKNOWN). Strictly read-only: it never executes
discovered binaries, never modifies or deletes anything, and bounds every
scan to known locations (no filesystem-wide crawl).

Versions are read from package metadata (``*.dist-info/METADATA`` or the
package ``__init__.py``) rather than by running ``agent-sudo --version`` —
executing arbitrary executables found on disk is a code-execution risk.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

EXECUTABLE_NAMES = ("agent-sudo", "agent-sudo-mcp")
_DIST_INFO_GLOB = "agent_sudo_mcp-*.dist-info"


@dataclass
class InstallRecord:
    root: str  # environment root (venv/prefix) identifying the install
    executable: str  # representative executable path ("" if none found)
    version: str  # "" when undetermined
    discovered_via: list[str] = field(default_factory=list)
    editable: bool = False
    editable_source: str = ""
    path_rank: int | None = None  # position of its bin dir on PATH, if any
    statuses: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "executable": self.executable,
            "version": self.version,
            "discovered_via": sorted(self.discovered_via),
            "editable": self.editable,
            "editable_source": self.editable_source,
            "path_rank": self.path_rank,
            "statuses": self.statuses,
            "recommendation": self.recommendation,
        }


@dataclass
class ConfigRecord:
    client: str
    config_path: str
    server_name: str
    command: str
    command_exists: bool
    install_root: str  # resolved install root ("" when unresolvable)
    version: str  # version of the resolved install
    audit_log: str = ""  # --audit-log path this client writes to ("" if unset)
    statuses: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "client": self.client,
            "config_path": self.config_path,
            "server_name": self.server_name,
            "command": self.command,
            "command_exists": self.command_exists,
            "install_root": self.install_root,
            "version": self.version,
            "audit_log": self.audit_log,
            "statuses": self.statuses,
            "recommendation": self.recommendation,
        }


@dataclass
class InventoryReport:
    installs: list[InstallRecord]
    configs: list[ConfigRecord]
    warnings: list[str]
    newest_version: str

    def to_dict(self) -> dict[str, object]:
        return {
            "newest_version": self.newest_version,
            "installs": [install.to_dict() for install in self.installs],
            "configs": [config.to_dict() for config in self.configs],
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def build_inventory(
    *,
    home: Path | None = None,
    path_env: str | None = None,
    platform: str | None = None,
    environ: dict[str, str] | None = None,
    include_running: bool = True,
) -> InventoryReport:
    """Collect installs and client configs. All inputs injectable for tests."""
    home = home or Path.home()
    environ = environ if environ is not None else dict(os.environ)
    path_env = path_env if path_env is not None else environ.get("PATH", "")
    platform = platform or sys.platform

    warnings: list[str] = []
    installs: dict[str, InstallRecord] = {}

    _discover_path_executables(installs, path_env)
    _discover_pipx(installs, home, environ)
    _discover_pyenv(installs, home, environ)
    if include_running:
        _discover_running_package(installs)

    configs = _discover_client_configs(home, platform, warnings)
    for config in configs:
        _attach_config_install(installs, config, source=f"config:{config.client}")

    pyenv_shims = str(Path(environ.get("PYENV_ROOT") or home / ".pyenv") / "shims")
    for install in installs.values():
        if install.root == pyenv_shims:
            install.statuses.append("PYENV-SHIM")
            continue
        _fill_metadata(install, warnings)

    report = InventoryReport(
        installs=sorted(installs.values(), key=lambda i: i.root),
        configs=configs,
        warnings=warnings,
        newest_version="",
    )
    _classify(report)
    return report


def _discover_path_executables(
    installs: dict[str, InstallRecord], path_env: str
) -> None:
    seen_roots_per_name: dict[str, list[str]] = {name: [] for name in EXECUTABLE_NAMES}
    for rank, raw_dir in enumerate(filter(None, path_env.split(os.pathsep))):
        bin_dir = Path(raw_dir)
        for name in EXECUTABLE_NAMES:
            exe = bin_dir / name
            if not exe.is_file() or not os.access(exe, os.X_OK):
                continue
            root = _install_root_for_executable(exe)
            record = _record_for(installs, root, executable=str(exe))
            record.discovered_via.append(f"PATH[{rank}]:{exe}")
            if record.path_rank is None or rank < record.path_rank:
                record.path_rank = rank
            seen_roots_per_name[name].append(root)
    # PATH shadowing: same executable name resolving to >1 install root.
    for name, roots in seen_roots_per_name.items():
        distinct = list(dict.fromkeys(roots))
        if len(distinct) > 1:
            for root in distinct[1:]:
                installs[root].statuses.append("PATH-SHADOWED")


def _discover_pipx(
    installs: dict[str, InstallRecord], home: Path, environ: dict[str, str]
) -> None:
    candidates = []
    if environ.get("PIPX_HOME"):
        candidates.append(Path(environ["PIPX_HOME"]) / "venvs")
    candidates.append(home / ".local" / "pipx" / "venvs")
    candidates.append(home / "Library" / "Application Support" / "pipx" / "venvs")
    for venvs in candidates:
        venv = venvs / "agent-sudo-mcp"
        if venv.is_dir():
            record = _record_for(installs, str(venv))
            record.discovered_via.append(f"pipx:{venv}")
            if not record.executable:
                exe = venv / "bin" / "agent-sudo"
                if exe.is_file():
                    record.executable = str(exe)


def _discover_pyenv(
    installs: dict[str, InstallRecord], home: Path, environ: dict[str, str]
) -> None:
    pyenv_root = Path(environ.get("PYENV_ROOT") or home / ".pyenv")
    versions = pyenv_root / "versions"
    if not versions.is_dir():
        return
    for version_dir in sorted(versions.iterdir()):
        bin_dir = version_dir / "bin"
        for name in EXECUTABLE_NAMES:
            exe = bin_dir / name
            if exe.is_file():
                record = _record_for(installs, str(version_dir), executable=str(exe))
                record.discovered_via.append(f"pyenv:{exe}")
                break


def _discover_running_package(installs: dict[str, InstallRecord]) -> None:
    try:
        import agent_sudo

        package_dir = Path(agent_sudo.__file__).resolve().parent
    except Exception:  # pragma: no cover - import always succeeds in-process
        return
    root = _install_root_for_site_packages(package_dir)
    record = _record_for(installs, root)
    record.discovered_via.append(f"running-interpreter:{sys.prefix}")


def _record_for(
    installs: dict[str, InstallRecord], root: str, *, executable: str = ""
) -> InstallRecord:
    record = installs.get(root)
    if record is None:
        record = InstallRecord(root=root, executable=executable, version="")
        installs[root] = record
    elif executable and not record.executable:
        record.executable = executable
    return record


def _install_root_for_executable(exe: Path) -> str:
    """Map an executable to its environment root, following symlinks."""
    try:
        resolved = exe.resolve()
    except OSError:
        resolved = exe
    # <root>/bin/agent-sudo (posix) or <root>/Scripts/agent-sudo (windows)
    parent = resolved.parent
    if parent.name in {"bin", "Scripts"}:
        return str(parent.parent)
    return str(parent)


def _install_root_for_site_packages(package_dir: Path) -> str:
    # .../<root>/lib/pythonX.Y/site-packages/agent_sudo -> <root>
    for ancestor in package_dir.parents:
        if ancestor.name in {"site-packages", "dist-packages"}:
            lib = ancestor.parent
            if lib.name.startswith("python") and lib.parent.name == "lib":
                return str(lib.parent.parent)
            return str(ancestor.parent)
    # Editable/source checkout: the package directory's parent is the root.
    return str(package_dir.parent)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def _fill_metadata(install: InstallRecord, warnings: list[str]) -> None:
    root = Path(install.root)
    dist_info = _find_dist_info(root)
    if dist_info is not None:
        version = _version_from_metadata(dist_info / "METADATA")
        if version:
            install.version = version
        editable_source = _editable_source(dist_info / "direct_url.json")
        if editable_source:
            install.editable = True
            install.editable_source = editable_source
        return
    # Source checkout / editable fallback: parse agent_sudo/__init__.py.
    for init in (
        root / "agent_sudo" / "__init__.py",
        *_site_packages_inits(root),
    ):
        version = _version_from_init(init)
        if version:
            install.version = version
            if init.parent.parent == root:
                install.editable = True
                install.editable_source = str(root)
            return
    warnings.append(f"could not determine version for install at {install.root}")


def _find_dist_info(root: Path) -> Path | None:
    lib = root / "lib"
    search_dirs: list[Path] = []
    if lib.is_dir():
        try:
            for python_dir in sorted(lib.iterdir()):
                site = python_dir / "site-packages"
                if site.is_dir():
                    search_dirs.append(site)
        except OSError:
            pass
    for site in search_dirs:
        try:
            matches = sorted(site.glob(_DIST_INFO_GLOB))
        except OSError:
            continue
        if matches:
            return matches[0]
    return None


def _site_packages_inits(root: Path) -> list[Path]:
    lib = root / "lib"
    if not lib.is_dir():
        return []
    inits = []
    try:
        for python_dir in sorted(lib.iterdir()):
            init = python_dir / "site-packages" / "agent_sudo" / "__init__.py"
            if init.is_file():
                inits.append(init)
    except OSError:
        pass
    return inits


def _version_from_metadata(metadata: Path) -> str:
    try:
        for line in metadata.read_text(encoding="utf-8").splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def _version_from_init(init: Path) -> str:
    try:
        text = init.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else ""


def _editable_source(direct_url: Path) -> str:
    # Shares the PEP 610 direct_url.json parsing with self_identity so the
    # editable-detection logic lives in exactly one place.
    from agent_sudo.self_identity import parse_direct_url

    try:
        text = direct_url.read_text(encoding="utf-8")
    except OSError:
        return ""
    editable, source = parse_direct_url(text)
    return source if editable else ""


# ---------------------------------------------------------------------------
# Client configs
# ---------------------------------------------------------------------------


def _client_config_candidates(home: Path, platform: str) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    if platform == "darwin":
        candidates.append(
            (
                "claude-desktop",
                home
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json",
            )
        )
    elif platform.startswith("win"):
        appdata = home / "AppData" / "Roaming"
        candidates.append(
            ("claude-desktop", appdata / "Claude" / "claude_desktop_config.json")
        )
    else:
        candidates.append(
            (
                "claude-desktop",
                home / ".config" / "Claude" / "claude_desktop_config.json",
            )
        )
    candidates.extend(
        [
            ("claude-code", home / ".claude.json"),
            ("codex", home / ".codex" / "config.toml"),
            ("gemini", home / ".gemini" / "settings.json"),
            ("gemini", home / ".gemini" / "config" / "mcp_config.json"),
            ("antigravity", home / ".gemini" / "antigravity" / "mcp_config.json"),
            ("hermes", home / ".hermes" / "mcp_config.json"),
            ("hermes", home / ".hermes" / "config" / "mcp_config.json"),
        ]
    )
    return candidates


def _discover_client_configs(
    home: Path, platform: str, warnings: list[str]
) -> list[ConfigRecord]:
    records: list[ConfigRecord] = []
    for client, config_path in _client_config_candidates(home, platform):
        if not config_path.is_file():
            continue
        try:
            if config_path.suffix == ".toml":
                entries = _mcp_entries_from_toml(config_path)
            else:
                entries = _mcp_entries_from_json(config_path)
        except (OSError, ValueError) as exc:
            warnings.append(f"could not parse {config_path}: {exc}")
            continue
        for server_name, command, args in entries:
            if not _is_agent_sudo_entry(command, args):
                continue
            command_path = Path(command).expanduser()
            records.append(
                ConfigRecord(
                    client=client,
                    config_path=str(config_path),
                    server_name=server_name,
                    command=command,
                    command_exists=command_path.is_file(),
                    install_root="",
                    version="",
                    audit_log=_audit_log_from_args(args),
                )
            )
    return records


def _audit_log_from_args(args: list[str]) -> str:
    """Return the --audit-log path from an MCP server's args, or ""."""
    for i, arg in enumerate(args):
        if arg == "--audit-log" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--audit-log="):
            return arg.split("=", 1)[1]
    return ""


def _mcp_entries_from_json(path: Path) -> list[tuple[str, str, list[str]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
    entries = []
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            command = str(spec.get("command", ""))
            args = [str(a) for a in spec.get("args", []) or []]
            entries.append((name, command, args))
    return entries


def _mcp_entries_from_toml(path: Path) -> list[tuple[str, str, list[str]]]:
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib

        data = tomllib.loads(text)
        servers = data.get("mcp_servers", {})
        entries = []
        if isinstance(servers, dict):
            for name, spec in servers.items():
                if not isinstance(spec, dict):
                    continue
                command = str(spec.get("command", ""))
                args = [str(a) for a in spec.get("args", []) or []]
                entries.append((name, command, args))
        return entries
    except ModuleNotFoundError:  # Python 3.10: no tomllib
        return _mcp_entries_from_toml_fallback(text)


def _mcp_entries_from_toml_fallback(text: str) -> list[tuple[str, str, list[str]]]:
    """Line-based [mcp_servers.<name>] section scanner for Python 3.10.

    Comment lines are skipped, matching tomllib's behaviour for the fields we
    read (a commented-out server entry is not an active registration).
    """
    entries: list[tuple[str, str, list[str]]] = []
    section: str | None = None
    command = ""
    args: list[str] = []

    def flush() -> None:
        if section is not None and command:
            entries.append((section, command, list(args)))

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        header = re.match(r"^\[mcp_servers\.([^\]]+)\]$", line)
        if header:
            flush()
            section = header.group(1).strip('"')
            command = ""
            args = []
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            section = None
            continue
        if section is None:
            continue
        key_match = re.match(r"^(\w+)\s*=\s*(.+)$", line)
        if not key_match:
            continue
        key, value = key_match.group(1), key_match.group(2).strip()
        if key == "command":
            command = value.strip('"')
        elif key == "args":
            args = re.findall(r'"([^"]*)"', value)
    flush()
    return entries


def _is_agent_sudo_entry(command: str, args: list[str]) -> bool:
    basename = Path(command).name
    if basename in EXECUTABLE_NAMES:
        return True
    joined = " ".join(args)
    return "agent_sudo.mcp_server" in joined or "agent_sudo_mcp" in joined


def _attach_config_install(
    installs: dict[str, InstallRecord], config: ConfigRecord, *, source: str
) -> None:
    command_path = Path(config.command).expanduser()
    if not config.command_exists:
        return
    if Path(config.command).name in EXECUTABLE_NAMES:
        root = _install_root_for_executable(command_path)
    else:
        # python -m agent_sudo.mcp_server style: root is the interpreter prefix.
        root = _install_root_for_executable(command_path)
    record = _record_for(installs, root, executable=str(command_path))
    record.discovered_via.append(f"{source}:{config.config_path}")
    config.install_root = root


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _version_key(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in version.split("."):
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def _classify(report: InventoryReport) -> None:
    versions = sorted(
        {i.version for i in report.installs if i.version}, key=_version_key
    )
    newest = versions[-1] if versions else ""
    report.newest_version = newest
    duplicate = len(report.installs) > 1
    referenced_roots = {c.install_root for c in report.configs if c.install_root}

    for install in report.installs:
        referenced = install.root in referenced_roots
        active = referenced or install.path_rank is not None
        shim = "PYENV-SHIM" in install.statuses
        if not install.version and not shim:
            install.statuses.append("UNKNOWN")
        if active:
            install.statuses.insert(0, "ACTIVE")
        if duplicate and not shim:
            install.statuses.append("DUPLICATE INSTALL")
        if install.version and newest and install.version != newest:
            install.statuses.append("VERSION DRIFT")
            if not referenced:
                install.statuses.append("STALE")
        if install.editable:
            install.statuses.append("EDITABLE")
        install.statuses = list(dict.fromkeys(install.statuses))
        install.recommendation = _install_recommendation(install, newest, referenced)

    for config in report.configs:
        if not config.command_exists:
            config.statuses.append("UNKNOWN")
            config.recommendation = (
                "configured command does not exist — re-run `agent-sudo setup "
                f"{config.client}` or update {config.config_path}"
            )
            continue
        install = next(
            (i for i in report.installs if i.root == config.install_root), None
        )
        config.version = install.version if install else ""
        if not config.version:
            config.statuses.append("UNKNOWN")
            config.recommendation = "could not determine the version this client runs"
        elif newest and config.version != newest:
            config.statuses.append("VERSION DRIFT")
            config.recommendation = (
                f"client runs {config.version} but {newest} is installed elsewhere — "
                "upgrade this install or re-point the config"
            )
        else:
            config.statuses.append("ACTIVE")
            config.recommendation = "up to date"


def _install_recommendation(
    install: InstallRecord, newest: str, referenced: bool
) -> str:
    if "PYENV-SHIM" in install.statuses:
        return (
            "pyenv shim — resolves to the active pyenv version at runtime; "
            "see the pyenv install entries for the actual versions"
        )
    if not install.version:
        return "version undetermined — verify this install manually"
    if "STALE" in install.statuses:
        return (
            f"older copy ({install.version} < {newest}) not referenced by any "
            "detected client config — review whether it is still needed"
        )
    if "VERSION DRIFT" in install.statuses:
        return f"upgrade to {newest} or re-point clients at the newest install"
    if install.editable:
        return f"editable install from {install.editable_source} — expected for development"
    if referenced:
        return "in use by a client config"
    if install.path_rank is not None:
        return "resolved via PATH"
    return "not referenced by PATH or any detected client config — review"


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_inventory(report: InventoryReport) -> str:
    lines: list[str] = []
    home = str(Path.home())

    def tilde(path: str) -> str:
        return path.replace(home, "~", 1) if path.startswith(home) else path

    lines.append("Agent_Sudo inventory (read-only)")
    lines.append("")
    lines.append(f"Installs found: {len(report.installs)}")
    for install in report.installs:
        status = ", ".join(install.statuses) or "OK"
        lines.append(f"  [{status}]")
        lines.append(f"    root:    {tilde(install.root)}")
        if install.executable:
            lines.append(f"    exe:     {tilde(install.executable)}")
        lines.append(f"    version: {install.version or 'unknown'}")
        for via in sorted(install.discovered_via):
            lines.append(f"    via:     {tilde(via)}")
        lines.append(f"    action:  {install.recommendation}")
    lines.append("")
    lines.append(f"Client configs referencing agent-sudo: {len(report.configs)}")
    for config in report.configs:
        status = ", ".join(config.statuses) or "OK"
        lines.append(f"  [{status}] {config.client} ({config.server_name})")
        lines.append(f"    config:  {tilde(config.config_path)}")
        lines.append(f"    command: {tilde(config.command)}")
        lines.append(f"    version: {config.version or 'unknown'}")
        lines.append(f"    action:  {config.recommendation}")
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in report.warnings:
            lines.append(f"  - {tilde(warning)}")
    if report.newest_version:
        lines.append("")
        lines.append(f"Newest installed version: {report.newest_version}")
    return "\n".join(lines)
