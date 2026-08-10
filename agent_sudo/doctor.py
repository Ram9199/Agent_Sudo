from __future__ import annotations

import importlib.resources
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agent_sudo.approvals import CONFIG_PATH
from agent_sudo.delegations import (
    DelegationStore,
    default_delegations_path,
    is_broad_delegation,
)
from agent_sudo.inventory import InventoryReport, _version_key, build_inventory
from agent_sudo.self_identity import SelfIdentity, describe_running_install


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


def run_doctor(
    *,
    repo_root: Path | None = None,
    identity: SelfIdentity | None = None,
    inventory_report: InventoryReport | None = None,
) -> list[DoctorCheck]:
    # doctor reports user readiness only. Repository/contributor hygiene
    # (e.g. the personal-data scanner) is a CI concern run via
    # scripts/check_no_personal_data.py, not surfaced to evaluators here.
    #
    # All probes target the single home state root (~/.agent-sudo, where the
    # approval config and delegation store live) so doctor reports one
    # consistent location and never litters a .agent-sudo/ directory into the
    # current working directory. ``repo_root`` is accepted for backward
    # compatibility but no longer changes where state is probed.
    del repo_root
    state_root = default_delegations_path().parent
    return [
        _python_version_check(),
        _default_policy_check(),
        _approval_config_check(),
        _writable_file_check("audit log writable", state_root / "doctor-audit.jsonl"),
        _writable_file_check("delegation store writable", default_delegations_path()),
        _broad_delegations_check(),
        *_install_health_checks(identity, inventory_report),
    ]


def _install_health_checks(
    identity: SelfIdentity | None,
    inventory_report: InventoryReport | None,
) -> list[DoctorCheck]:
    """Detect a stale running install or an editable that drifted from its source.

    WARN-only (neither name is in the required set, so the exit code is never
    affected — issue #110 explicitly does not auto-fix). Reuses the
    :class:`SelfIdentity` primitive (#108) and the inventory classification
    (#101) rather than re-deriving versions.
    """
    if identity is None:
        identity = describe_running_install()
    if inventory_report is None:
        inventory_report = build_inventory()
    return [
        _staleness_check(identity, inventory_report),
        _runtime_source_check(identity),
        _duplicate_installs_check(inventory_report),
    ]


def _duplicate_installs_check(report: InventoryReport) -> DoctorCheck:
    name = "single active install"
    # Reuse inventory's classification (#101): an install is ACTIVE when a client
    # config references it or it resolves on PATH. A pyenv shim is ACTIVE too but
    # only *resolves to* a version install — counting both would double-count one
    # install, so PYENV-SHIM records are excluded. Distinct roots means a shim and
    # its target collapse to one, while two real installs (even same-version
    # editables at different source roots) stay distinct.
    roots = {
        install.root
        for install in report.installs
        if "ACTIVE" in install.statuses and "PYENV-SHIM" not in install.statuses
    }
    if len(roots) <= 1:
        detail = "one active install" if roots else "no active install detected"
        return DoctorCheck(name, True, detail)
    return DoctorCheck(
        name,
        False,
        "Multiple active Agent_Sudo installs detected. Run `agent-sudo inventory` "
        "to inspect and choose one canonical install.",
    )


def _staleness_check(identity: SelfIdentity, report: InventoryReport) -> DoctorCheck:
    name = "install up to date"
    running = identity.version
    newest = report.newest_version
    if not running or running == "unknown" or not newest:
        return DoctorCheck(name, True, "no newer install detected")
    if _version_key(running) >= _version_key(newest):
        return DoctorCheck(name, True, f"running the newest install found ({running})")
    # A newer copy exists elsewhere — name where, so the user can re-point/reinstall.
    newer = [i for i in report.installs if i.version == newest]
    location = _tilde(newer[0].root) if newer else "another install"
    return DoctorCheck(
        name,
        False,
        f"running {running} but {newest} is installed at {location}; "
        "your shell is resolving an older copy — run `agent-sudo inventory` "
        "and reinstall or re-point to the newest",
    )


def _runtime_source_check(identity: SelfIdentity) -> DoctorCheck:
    name = "runtime matches install source"
    if identity.install_type != "editable":
        return DoctorCheck(name, True, f"{identity.install_type} install")
    source = identity.source_path
    package = identity.package_path
    if source and _path_within(package, source):
        return DoctorCheck(name, True, f"editable source {_tilde(source)}")
    return DoctorCheck(
        name,
        False,
        f"editable install registered for {_tilde(source or '?')} but "
        f"code is running from {_tilde(package)}; the editable source "
        "moved or a stale copy is shadowing it — reinstall with `pip install -e`",
    )


def _tilde(path: str) -> str:
    """Collapse $HOME to ~ for install/source locations (never cwd-relative)."""
    home = str(Path.home())
    return path.replace(home, "~", 1) if path and path.startswith(home) else path


def _path_within(child: str, parent: str) -> bool:
    """True if ``child`` is ``parent`` or lives under it (string-safe, no I/O)."""
    try:
        child_path = Path(child).resolve()
        parent_path = Path(parent).resolve()
    except OSError:
        return False
    return child_path == parent_path or parent_path in child_path.parents


def doctor_exit_code(checks: list[DoctorCheck]) -> int:
    required = {
        "Python version OK",
        "default policy exists",
        "audit log writable",
        "delegation store writable",
    }
    failed_required = [
        check for check in checks if check.name in required and not check.ok
    ]
    return 1 if failed_required else 0


def format_doctor_checks(checks: list[DoctorCheck]) -> str:
    lines = []
    for check in checks:
        status = "OK" if check.ok else "WARN"
        if check.name in {
            "Python version OK",
            "default policy exists",
            "audit log writable",
            "delegation store writable",
        }:
            status = "OK" if check.ok else "FAIL"
        if check.name == "approval config exists" and not check.ok:
            lines.append(
                f"{status}: {check.name} - {check.detail}\n\n"
                "APPROVALS: NOT INITIALIZED\n\n"
                "Recommended:\n"
                "agent-sudo init-approval"
            )
        else:
            lines.append(f"{status}: {check.name} - {check.detail}")
    return "\n".join(lines)


def _python_version_check() -> DoctorCheck:
    ok = sys.version_info >= (3, 10)
    version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    return DoctorCheck("Python version OK", ok, f"running Python {version}")


def _default_policy_check() -> DoctorCheck:
    policy = importlib.resources.files("agent_sudo.config").joinpath(
        "default_policy.yaml"
    )
    exists = Path(str(policy)).exists()
    return DoctorCheck(
        "default policy exists", exists, "agent_sudo/config/default_policy.yaml"
    )


def _approval_config_check() -> DoctorCheck:
    exists = CONFIG_PATH.exists()
    detail = (
        _display_path(CONFIG_PATH)
        if exists
        else "not initialized: run agent-sudo init-approval"
    )
    return DoctorCheck("approval config exists", exists, detail)


def _broad_delegations_check() -> DoctorCheck:
    # Observability warning only (not in the required set, so it never fails the
    # exit code). A broad (path="*") token allows or blocks ALL matching actions
    # while active, and — once stale — can blanket-deny them; surface it so it is
    # not silently masking or breaking approvals.
    path = default_delegations_path()
    try:
        tokens = DelegationStore(path).list() if path.exists() else []
    except (OSError, ValueError) as exc:
        return DoctorCheck(
            "delegation scope", False, f"could not read delegation store: {exc}"
        )
    broad = [token for token in tokens if is_broad_delegation(token)]
    if not broad:
        return DoctorCheck(
            "delegation scope", True, "no broad (path=*) delegations present"
        )
    ids = ", ".join(token.token_id for token in broad)
    return DoctorCheck(
        "delegation scope",
        False,
        f"{len(broad)} broad (path=*) delegation(s) present: {ids}; "
        "these allow or block all matching actions — review with "
        "`agent-sudo delegate list`",
    )


def _writable_file_check(name: str, path: Path) -> DoctorCheck:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=path.name, dir=path.parent, delete=True
        ):
            pass
        return DoctorCheck(name, True, _display_path(path))
    except OSError as exc:
        return DoctorCheck(name, False, str(exc))


def _display_path(path: Path) -> str:
    resolved = path.expanduser()
    home = Path.home()
    try:
        return f"~/{resolved.relative_to(home)}"
    except ValueError:
        pass
    try:
        return str(resolved.relative_to(Path.cwd()))
    except ValueError:
        return str(resolved)
