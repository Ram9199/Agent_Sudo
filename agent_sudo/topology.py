"""Read-only topology view (issue #112).

Answers two questions a confused user actually asks:
  * "What Agent_Sudo instances are guarding me right now?" — the CLI surfaces
    (shells), the MCP clients routed through Agent_Sudo, and the audit logs
    they write to.
  * "What is NOT routed through Agent_Sudo?" — MCP tooling present on the
    machine that does not go through the gateway (Smithery is the motivating
    example).

It is a regrouping of :func:`agent_sudo.inventory.build_inventory` output plus a
small presence probe for known unrouted tools. Strictly read-only: no execution
of discovered binaries, no auto-fix, no cleanup. Not a topology graph, not a
process monitor.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from agent_sudo.inventory import InstallRecord, InventoryReport, build_inventory

# Known MCP tooling that does NOT route through Agent_Sudo. Kept deliberately
# small and concrete (no generic framework). Each entry: a display name, the
# executables to look for on PATH, and filesystem paths whose presence indicates
# the tool is installed.
_KNOWN_UNROUTED_TOOLS = [
    {
        "name": "smithery",
        "binaries": ["smithery"],
        "paths": ["~/Library/Application Support/smithery"],
    },
]


@dataclass
class CLISurface:
    executable: str
    install_root: str
    version: str
    editable_source: str
    is_shim: bool  # True only when nothing but a shim is on PATH (no resolved target)
    via_shim: bool = False  # the resolved install is reached through a pyenv shim

    def to_dict(self) -> dict[str, object]:
        return {
            "executable": self.executable,
            "install_root": self.install_root,
            "version": self.version,
            "editable_source": self.editable_source,
            "is_shim": self.is_shim,
            "via_shim": self.via_shim,
        }


@dataclass
class MCPClientEntry:
    client: str
    config_path: str
    command: str
    install_root: str
    editable_source: str
    version: str
    audit_log: str

    def to_dict(self) -> dict[str, object]:
        return {
            "client": self.client,
            "config_path": self.config_path,
            "command": self.command,
            "install_root": self.install_root,
            "editable_source": self.editable_source,
            "version": self.version,
            "audit_log": self.audit_log,
        }


@dataclass
class NotRoutedTool:
    name: str
    found: list[str]

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "found": self.found}


@dataclass
class TopologyReport:
    newest_version: str
    cli_surfaces: list[CLISurface]
    mcp_clients: list[MCPClientEntry]
    audit_destinations: dict[str, list[str]]  # audit log path -> client names
    not_routed: list[NotRoutedTool]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "newest_version": self.newest_version,
            "cli_surfaces": [c.to_dict() for c in self.cli_surfaces],
            "mcp_clients": [m.to_dict() for m in self.mcp_clients],
            "audit_destinations": self.audit_destinations,
            "not_routed": [n.to_dict() for n in self.not_routed],
            "warnings": self.warnings,
        }


def build_topology(
    *,
    report: InventoryReport | None = None,
    home: Path | None = None,
    unrouted_tools: list[dict] | None = None,
) -> TopologyReport:
    """Assemble the topology from inventory data plus an unrouted-tool probe."""
    if report is None:
        report = build_inventory()
    home = home or Path.home()
    tools = unrouted_tools if unrouted_tools is not None else _KNOWN_UNROUTED_TOOLS

    editable_by_root = {
        i.root: i.editable_source for i in report.installs if i.editable_source
    }

    # 1. CLI surfaces: installs resolvable on PATH, nearest first. A pyenv shim
    # only *resolves to* a version install, so collapse it: when a real install
    # is on PATH, drop the standalone shim entry and mark the pyenv-version
    # install it resolves to as via_shim — avoiding a misleading second CLI row.
    # Only when nothing but a shim is on PATH do we show the shim itself.
    path_installs = sorted(
        (i for i in report.installs if i.path_rank is not None),
        key=lambda i: i.path_rank if i.path_rank is not None else 0,
    )
    shim_present = any("PYENV-SHIM" in i.statuses for i in path_installs)
    real_installs = [i for i in path_installs if "PYENV-SHIM" not in i.statuses]

    def _surface(
        install: InstallRecord, *, is_shim: bool, via_shim: bool
    ) -> CLISurface:
        return CLISurface(
            executable=Path(install.executable).name
            if install.executable
            else "agent-sudo",
            install_root=install.root,
            version=install.version,
            editable_source=install.editable_source,
            is_shim=is_shim,
            via_shim=via_shim,
        )

    if real_installs:
        cli_surfaces = [
            _surface(
                install,
                is_shim=False,
                via_shim=shim_present and "/.pyenv/versions/" in install.root,
            )
            for install in real_installs
        ]
    else:
        # Only a shim resolves on PATH (no version install on PATH to collapse into).
        cli_surfaces = [
            _surface(install, is_shim=True, via_shim=False)
            for install in path_installs
            if "PYENV-SHIM" in install.statuses
        ]

    # 2. MCP clients routed through Agent_Sudo (from client configs).
    mcp_clients = [
        MCPClientEntry(
            client=config.client,
            config_path=config.config_path,
            command=config.command,
            install_root=config.install_root,
            editable_source=editable_by_root.get(config.install_root, ""),
            version=config.version,
            audit_log=config.audit_log,
        )
        for config in report.configs
    ]

    # 3. Audit destinations: which clients write to each audit log.
    audit_destinations: dict[str, list[str]] = {}
    for config in report.configs:
        if config.audit_log:
            audit_destinations.setdefault(config.audit_log, []).append(config.client)

    # 4. Not routed: known MCP tooling present but not an Agent_Sudo client.
    routed_names = {c.client for c in report.configs}
    not_routed = _detect_unrouted(tools, home, routed_names)

    return TopologyReport(
        newest_version=report.newest_version,
        cli_surfaces=cli_surfaces,
        mcp_clients=mcp_clients,
        audit_destinations=audit_destinations,
        not_routed=not_routed,
        warnings=list(report.warnings),
    )


def _detect_unrouted(
    tools: list[dict], home: Path, routed_names: set[str]
) -> list[NotRoutedTool]:
    detected: list[NotRoutedTool] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name or name in routed_names:
            continue
        found: list[str] = []
        for binary in tool.get("binaries", []):
            path = shutil.which(binary)
            if path:
                found.append(path)
        for raw in tool.get("paths", []):
            expanded = (
                Path(raw.replace("~", str(home), 1))
                if raw.startswith("~")
                else Path(raw)
            )
            if expanded.exists():
                found.append(str(expanded))
        if found:
            detected.append(NotRoutedTool(name=name, found=found))
    return detected


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_topology(report: TopologyReport) -> str:
    home = str(Path.home())

    def tilde(path: str) -> str:
        return path.replace(home, "~", 1) if path and path.startswith(home) else path

    def editable_note(source: str) -> str:
        return f"   (editable: {tilde(source)})" if source else ""

    lines = ["Agent_Sudo topology (read-only)"]
    if report.newest_version:
        lines.append(f"Newest version on this machine: {report.newest_version}")
    lines.append("")

    lines.append("1. CLI surfaces (your shell / terminal)")
    if not report.cli_surfaces:
        lines.append("   (no agent-sudo found on PATH)")
    for surface in report.cli_surfaces:
        if surface.is_shim:
            lines.append(
                f"   {surface.executable}  →  {tilde(surface.install_root)}   "
                "(pyenv shim — resolves to the active pyenv version)"
            )
        else:
            version = surface.version or "unknown"
            shim_note = "   [resolved via pyenv shim]" if surface.via_shim else ""
            lines.append(
                f"   {surface.executable}  →  {tilde(surface.install_root)}   "
                f"v{version}{editable_note(surface.editable_source)}{shim_note}"
            )
    lines.append("")

    lines.append("2. MCP clients (routed through Agent_Sudo)")
    if not report.mcp_clients:
        lines.append("   (no client configs reference agent-sudo)")
    for client in report.mcp_clients:
        lines.append(f"   {client.client}   v{client.version or 'unknown'}")
        lines.append(f"     config:   {tilde(client.config_path)}")
        lines.append(
            f"     command:  {tilde(client.command)}{editable_note(client.editable_source)}"
        )
        lines.append(f"     audit:    {tilde(client.audit_log) or '(default)'}")
    lines.append("")

    lines.append("3. Audit destinations")
    if not report.audit_destinations:
        lines.append("   (none recorded in client configs)")
    for audit_log, clients in sorted(report.audit_destinations.items()):
        lines.append(f"   {tilde(audit_log)}   ←  {', '.join(sorted(clients))}")
    lines.append("")

    lines.append("4. Not routed through Agent_Sudo")
    if not report.not_routed:
        lines.append("   (no known unrouted MCP tooling detected)")
    for tool in report.not_routed:
        lines.append(
            f"   {tool.name}   present, NOT configured to route through Agent_Sudo"
        )
        lines.append(f"     found:    {', '.join(tilde(p) for p in tool.found)}")
    if report.not_routed:
        lines.append(
            "   These run without Agent_Sudo's approval/audit — expected only if intentional."
        )
    lines.append("")
    lines.append("Read-only. Run `agent-sudo inventory` for install-level detail.")
    return "\n".join(lines)
