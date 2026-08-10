from __future__ import annotations

import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from agent_sudo import __version_label__


WINDOWS_CONSOLE_SCRIPTS = ("agent-sudo.exe", "agent-sudo-mcp.exe")


def get_git_root() -> Path | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0:
            return Path(completed.stdout.strip())
    except OSError:
        pass
    return None


GENERATED_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
GENERATED_TOP_LEVEL_NAMES = {"build", "dist"}
GENERATED_FILE_NAMES = {".DS_Store"}


@dataclass(frozen=True)
class WorkingTreeStatus:
    generated_artifacts: list[str]
    user_changes: list[str]

    @property
    def is_dirty(self) -> bool:
        return bool(self.generated_artifacts or self.user_changes)

    @property
    def only_generated_artifacts(self) -> bool:
        return bool(self.generated_artifacts) and not self.user_changes


def is_working_tree_dirty(git_root: Path) -> bool:
    return get_working_tree_status(git_root).is_dirty


def get_working_tree_status(git_root: Path) -> WorkingTreeStatus:
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=git_root,
        capture_output=True,
        text=True,
        check=False,
    )
    generated: list[str] = []
    user_changes: list[str] = []
    for raw_line in completed.stdout.splitlines():
        if not raw_line:
            continue
        path = _status_path(raw_line)
        if raw_line.startswith("?? ") and is_generated_artifact(path):
            generated.append(path)
        else:
            user_changes.append(raw_line)
    return WorkingTreeStatus(generated, user_changes)


def is_generated_artifact(path: str) -> bool:
    normalized = path.rstrip("/")
    parts = Path(normalized).parts
    if not parts:
        return False
    if parts[-1] in GENERATED_FILE_NAMES:
        return True
    if any(part in GENERATED_DIR_NAMES for part in parts):
        return True
    if any(part.endswith(".egg-info") for part in parts):
        return True
    return parts[0] in GENERATED_TOP_LEVEL_NAMES


def clean_generated_artifacts(git_root: Path, artifacts: list[str]) -> None:
    for artifact in artifacts:
        target = _safe_repo_path(git_root, artifact)
        if target is None or not target.exists():
            continue
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()


def _status_path(raw_line: str) -> str:
    path = raw_line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.strip()


def _safe_repo_path(git_root: Path, relative_path: str) -> Path | None:
    try:
        root = git_root.resolve()
        target = (root / relative_path.rstrip("/")).resolve()
    except OSError:
        return None
    if target == root or root not in target.parents:
        return None
    return target


def version_key(tag: str) -> tuple[int, ...]:
    matches = re.findall(r"\d+", tag)
    return tuple(int(x) for x in matches)


def get_latest_git_tag(git_root: Path) -> str | None:
    completed = subprocess.run(
        ["git", "tag"],
        cwd=git_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    tags = [t.strip() for t in completed.stdout.splitlines() if t.strip()]
    if not tags:
        return None
    tags.sort(key=version_key)
    return tags[-1]


def _preremove_scripts_on_windows() -> list[tuple[Path, Path]]:
    """Move Agent_Sudo launchers out of pip's way on Windows.

    Windows does not allow pip to unlink the console launcher that started this
    process. It does allow the launcher to be renamed, after which pip can
    install its replacement at the original path.
    """
    if sys.platform != "win32":
        return []

    scripts_dir = Path(sys.executable).resolve().parent
    moved: list[tuple[Path, Path]] = []
    try:
        for script_name in WINDOWS_CONSOLE_SCRIPTS:
            original = scripts_dir / script_name
            if not original.is_file():
                continue
            backup = original.with_name(
                f".{original.stem}-upgrade-{uuid.uuid4().hex}.old.exe"
            )
            original.rename(backup)
            moved.append((original, backup))
    except OSError:
        _restore_preremoved_scripts(moved)
        raise
    return moved


def _restore_preremoved_scripts(moved: list[tuple[Path, Path]]) -> None:
    for original, backup in reversed(moved):
        if backup.exists() and not original.exists():
            try:
                backup.rename(original)
            except OSError:
                pass


def _remove_preremoved_scripts(moved: list[tuple[Path, Path]]) -> None:
    leftovers: list[Path] = []
    for _, backup in moved:
        try:
            backup.unlink(missing_ok=True)
        except OSError:
            # The launcher that invoked us can remain locked until this Python
            # process exits. A detached Python child removes that final backup.
            leftovers.append(backup)
    if not leftovers:
        return

    cleanup_code = (
        "import pathlib,sys,time; time.sleep(2); "
        "[(lambda p: p.unlink(missing_ok=True))(pathlib.Path(p)) for p in sys.argv[1:]]"
    )
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
        subprocess, "DETACHED_PROCESS", 0
    )
    try:
        subprocess.Popen(
            [sys.executable, "-c", cleanup_code, *map(str, leftovers)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
        )
    except OSError:
        pass


def handle_upgrade(*, check_only: bool = False, allow_dirty: bool = False) -> int:
    git_root = get_git_root()
    if not git_root:
        print("This installation is not inside a git repository.", file=sys.stderr)
        print(
            "\nTo upgrade agent-sudo manually, please run:\n  pip install --upgrade agent-sudo-mcp",
            file=sys.stderr,
        )
        return 1

    # Show warning about local state preservation
    print(
        "NOTE: Local state, audit logs, and delegations under ~/.agent-sudo will be preserved."
    )

    # Get current branch and commit
    branch_cmd = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=git_root,
        capture_output=True,
        text=True,
    )
    commit_cmd = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=git_root,
        capture_output=True,
        text=True,
    )
    current_branch = (
        branch_cmd.stdout.strip() if branch_cmd.returncode == 0 else "unknown"
    )
    current_commit = (
        commit_cmd.stdout.strip() if commit_cmd.returncode == 0 else "unknown"
    )

    print(f"Current installed version: {__version_label__}")
    print(f"Current Git branch: {current_branch}")
    print(f"Current Git commit: {current_commit}")

    # Fetch latest tags
    print("Fetching tags from origin...")
    fetch_cmd = subprocess.run(
        ["git", "fetch", "--tags"], cwd=git_root, capture_output=True, text=True
    )
    if fetch_cmd.returncode != 0:
        print("Warning: Failed to fetch tags from origin.", file=sys.stderr)

    latest_tag = get_latest_git_tag(git_root)
    if latest_tag:
        print(f"Latest available tag: {latest_tag}")
        is_newer = version_key(latest_tag) > version_key(__version_label__)
        print(f"Upgrade available: {'Yes' if is_newer else 'No'}")
    else:
        print("Latest available tag: unknown")
        is_newer = False

    if check_only:
        return 0

    # Verify working tree is clean unless allow_dirty is True. Untracked generated
    # build/cache artifacts are safe to remove because they can be recreated.
    if not allow_dirty:
        working_tree_status = get_working_tree_status(git_root)
        if working_tree_status.only_generated_artifacts:
            print("Found generated artifacts that can be safely removed:")
            for artifact in working_tree_status.generated_artifacts:
                print(f"- {artifact}")
            print("Cleaning generated artifacts...")
            clean_generated_artifacts(git_root, working_tree_status.generated_artifacts)
            print("Proceeding with upgrade...")
        elif working_tree_status.is_dirty:
            print("Error: Git working tree has uncommitted changes.", file=sys.stderr)
            if working_tree_status.generated_artifacts:
                print("\nGenerated artifacts detected:", file=sys.stderr)
                for artifact in working_tree_status.generated_artifacts:
                    print(f"- {artifact}", file=sys.stderr)
            if working_tree_status.user_changes:
                print("\nUser changes blocking upgrade:", file=sys.stderr)
                for change in working_tree_status.user_changes:
                    print(f"- {change}", file=sys.stderr)
            print("\nSuggested safe next steps:", file=sys.stderr)
            print("  git status --short", file=sys.stderr)
            print("  git stash push -u -m agent-sudo-upgrade-safety", file=sys.stderr)
            print("Then rerun: agent-sudo upgrade-local", file=sys.stderr)
            print(
                "Generated artifacts listed above can also be removed manually if you prefer.",
                file=sys.stderr,
            )
            print(
                "Pass --allow-dirty only if you understand the risk.", file=sys.stderr
            )
            return 1

    # Pull current branch
    print(f"Pulling latest changes on branch {current_branch}...")
    pull_cmd = subprocess.run(["git", "pull"], cwd=git_root)
    if pull_cmd.returncode != 0:
        print("Error: git pull failed.", file=sys.stderr)
        return 1

    # Reinstall. On Windows the active console launcher cannot be unlinked, so
    # move the Agent_Sudo stubs aside before pip's uninstall step.
    print("Reinstalling agent-sudo in editable mode...")
    try:
        moved_scripts = _preremove_scripts_on_windows()
    except OSError as exc:
        print(
            f"Error: Could not prepare Windows launchers for upgrade ({exc}).",
            file=sys.stderr,
        )
        return 1
    reinstall_cmd = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", "."], cwd=git_root
    )
    if reinstall_cmd.returncode != 0:
        _restore_preremoved_scripts(moved_scripts)
        print("Error: pip installation failed.", file=sys.stderr)
        return 1
    _remove_preremoved_scripts(moved_scripts)

    # Verify installation
    print("Verifying installation...")
    try:
        subprocess.run(["agent-sudo", "--version"], check=True)
        subprocess.run(["agent-sudo-mcp", "--version"], check=True)
        subprocess.run(["agent-sudo", "doctor"], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"Warning: Verification failed ({exc}).", file=sys.stderr)
        # Fallback to sys.executable verification
        try:
            subprocess.run(
                [sys.executable, "-m", "agent_sudo.gateway", "--version"], check=True
            )
            subprocess.run(
                [sys.executable, "-m", "agent_sudo.gateway", "doctor"], check=True
            )
        except subprocess.CalledProcessError:
            print("Error: Post-upgrade verification failed.", file=sys.stderr)
            return 1

    print("\nUpgrade completed successfully!")
    print(
        "\nReminder:\n  Restart Claude Desktop / Cursor / Hermes / OpenClaw after upgrading MCP server."
    )
    return 0
