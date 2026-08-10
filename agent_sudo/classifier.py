from __future__ import annotations

import shlex
from pathlib import Path

from agent_sudo.injection import detect_prompt_injection
from agent_sudo.models import ActionRequest, Classification, OriginType, TrustLevel
from agent_sudo.policy import Policy


BLOCKING_HINTS = {
    "bypass_policy",
    "disable_audit",
    "exfiltration",
    "secret_exfiltration",
    "token_exfiltration",
}

PROTECTED_WRITE_ACTIONS = {
    "write_file",
    "edit_file",
    "delete_file",
    "run_shell_command",
    "modify_auth",
    "create_cron",
}

PATH_WRITE_ACTIONS = {"write_file", "edit_file", "delete_file"}
FILE_WRITE_ACTIONS = {"write_file", "edit_file"}

DEMO_ALLOWED_ABSOLUTE_PREFIXES = {
    "/tmp",
}

CRITICAL_HINTS = {
    "credentials",
    "secrets",
    "auth",
    "money",
    "employment",
    "legal",
    "external_post",
    "email_send",
    "destructive",
}

SENSITIVE_HINTS = {
    "writes_local_file",
    "external_side_effect",
    "shell",
    "browser_action",
    "scheduled_task",
}

# Leading privilege/utility wrappers that prefix a real command without changing
# what it does. They shift the underlying command off argv[0], which would
# otherwise defeat the argv[0]-anchored destructive-command matchers below
# (e.g. `sudo rm -rf /`).
_COMMAND_WRAPPERS = {
    "sudo",
    "doas",
    "env",
    "command",
    "nice",
    "nohup",
    "time",
    "timeout",
    "stdbuf",
    "setsid",
    "ionice",
    "xargs",
}

# Wrapper options that consume the following token as their value, so the value
# is not mistaken for the wrapped command.
_WRAPPER_VALUE_FLAGS = {
    "-u",
    "-g",
    "-U",
    "-p",
    "-C",
    "-r",
    "-t",
    "-T",
    "-h",
    "-n",
    "-s",
    "-k",
    "-o",
}


class ActionClassifier:
    def __init__(self, policy: Policy):
        self.policy = policy

    def classify(self, request: ActionRequest) -> Classification:
        hints = {hint.strip().lower() for hint in request.risk_hints}
        if request.action == "prompt_injection_attempt" or detect_prompt_injection(
            _injection_scan_text(request)
        ):
            return Classification.BLOCKED
        if hints & BLOCKING_HINTS:
            return Classification.BLOCKED
        if request.action == "run_shell_command" and is_blocked_shell_target(
            request.target
        ):
            return Classification.BLOCKED
        if request.action in {"read_file", "search_files"} and is_blocked_read_target(
            request.target
        ):
            return Classification.BLOCKED
        if request.action == "get_runtime_context":
            return Classification.SAFE
        action_classification = self.policy.classification_for_action(request.action)
        if request.action in PATH_WRITE_ACTIONS and is_blocked_write_target(
            request.target
        ):
            return Classification.BLOCKED
        if request.action in FILE_WRITE_ACTIONS and is_critical_write_target(
            request.target
        ):
            if action_classification == Classification.BLOCKED:
                return Classification.BLOCKED
            return Classification.CRITICAL
        if request.action in PATH_WRITE_ACTIONS and is_forbidden_path_target(
            request.target
        ):
            return Classification.BLOCKED
        if request.action in {
            "write_file",
            "edit_file",
        } and not is_write_target_allowed(request.target):
            return Classification.BLOCKED
        if (
            is_protected_target(request.target)
            and request.action in PROTECTED_WRITE_ACTIONS
        ):
            if action_classification == Classification.BLOCKED:
                return Classification.BLOCKED
            return Classification.CRITICAL
        if (
            request.provenance.origin_type == OriginType.EXTERNAL_CONTENT
            and action_classification != Classification.BLOCKED
        ):
            # Taint must be monotonic: external-content origin escalates SAFE
            # to SENSITIVE but never weakens a stronger base classification.
            if action_classification == Classification.CRITICAL:
                return Classification.CRITICAL
            return Classification.SENSITIVE
        if request.source_trust in {TrustLevel.EXTERNAL_CONTENT, TrustLevel.UNKNOWN}:
            if action_classification == Classification.SAFE:
                return Classification.SENSITIVE
            return action_classification
        if hints & CRITICAL_HINTS:
            if action_classification == Classification.BLOCKED:
                return Classification.BLOCKED
            return Classification.CRITICAL
        if hints & SENSITIVE_HINTS:
            if action_classification in {
                Classification.BLOCKED,
                Classification.CRITICAL,
            }:
                return action_classification
            return Classification.SENSITIVE
        return action_classification


def is_protected_target(target: str) -> bool:
    expanded = str(Path(target).expanduser())
    normalized = expanded.replace("\\", "/")
    home = str(Path.home()).replace("\\", "/")

    if normalized == "pyproject.toml" or normalized.endswith("/pyproject.toml"):
        return True
    if normalized.endswith(".yaml") or normalized.endswith(".yml"):
        return True
    if normalized.endswith(".jsonl") and "audit" in normalized.lower():
        return True
    if "audit" in normalized.lower() and normalized.endswith(".log"):
        return True
    if (
        normalized.startswith("agent_sudo/config/")
        or "/agent_sudo/config/" in normalized
    ):
        return True
    if normalized.startswith("agent_sudo/") and normalized.endswith(".py"):
        return True
    if "/agent_sudo/" in normalized and normalized.endswith(".py"):
        return True
    if normalized.startswith(f"{home}/.agent-sudo/"):
        return True
    if normalized == f"{home}/.agent-runtime/auth.json":
        return True
    if normalized.startswith(f"{home}/.agent-runtime/"):
        return True
    return False


def is_forbidden_path_target(target: str) -> bool:
    normalized = _normalized_target(target)
    home = str(Path.home()).replace("\\", "/")

    if is_blocked_write_target(target):
        return True
    if normalized.startswith(f"{home}/.config/") or normalized == f"{home}/.config":
        return True
    return False


def is_blocked_write_target(target: str) -> bool:
    normalized = _normalized_target(target)
    lowered = normalized.lower()
    home = str(Path.home()).replace("\\", "/").lower()

    if lowered.startswith(f"{home}/.ssh/") or lowered == f"{home}/.ssh":
        return True
    if is_protected_target(target) and _looks_like_tamper_target(lowered):
        return True
    return _looks_like_credential_path(lowered)


def is_write_target_allowed(target: str) -> bool:
    import os
    import tempfile

    normalized = _normalized_target(target)
    path = Path(target).expanduser()
    if not path.is_absolute():
        return True

    try:
        resolved_path = str(path.resolve()).replace("\\", "/")
    except Exception:
        resolved_path = normalized

    # 1. Check default demo prefixes
    resolved_prefixes = []
    for prefix in DEMO_ALLOWED_ABSOLUTE_PREFIXES:
        try:
            resolved_prefixes.append(str(Path(prefix).resolve()).replace("\\", "/"))
        except Exception:
            resolved_prefixes.append(prefix)
    if any(
        resolved_path == prefix or resolved_path.startswith(prefix.rstrip("/") + "/")
        for prefix in resolved_prefixes
    ):
        return True

    # 2. Allow temp directory (e.g. /var/folders/ on macOS) for unit testing
    try:
        tmp_dir = str(Path(tempfile.gettempdir()).resolve()).replace("\\", "/")
        if resolved_path == tmp_dir or resolved_path.startswith(
            tmp_dir.rstrip("/") + "/"
        ):
            return True
    except Exception:
        pass

    # 3. Allow configured workspace if set
    ws = os.environ.get("AGENT_SUDO_WORKSPACE")
    if not ws:
        from agent_sudo.context import _load_config_workspace

        ws = _load_config_workspace()
    if ws:
        try:
            ws_resolved = str(Path(ws).expanduser().resolve()).replace("\\", "/")
            if resolved_path == ws_resolved or resolved_path.startswith(
                ws_resolved.rstrip("/") + "/"
            ):
                return True
        except Exception:
            pass

    return False


def is_critical_write_target(target: str) -> bool:
    normalized = _normalized_target(target)
    lowered = normalized.lower()
    name = Path(normalized).name.lower()

    if name.endswith((".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl")):
        return True
    if name in {".zshrc", ".bashrc"}:
        return True
    if _looks_like_launchd_plist(lowered):
        return True
    if _looks_like_cron_path(lowered):
        return True
    if _looks_like_systemd_unit(lowered):
        return True
    if _looks_like_mcp_config(lowered, name):
        return True
    if _looks_like_runtime_config(lowered, name):
        return True
    return is_protected_target(target)


def _normalized_target(target: str) -> str:
    return str(Path(target).expanduser()).replace("\\", "/")


def _looks_like_tamper_target(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in {"audit", "policy", "default_policy.yaml", "default_policy.yml"}
    )


def _looks_like_credential_path(lowered: str) -> bool:
    path_parts = {part for part in lowered.replace("\\", "/").split("/") if part}
    sensitive_names = {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "credentials",
        "secrets",
        "secret",
        "private_key",
        "id_rsa",
        "id_ed25519",
    }
    if path_parts & sensitive_names:
        return True
    return any(
        marker in lowered
        for marker in {
            "/auth/",
            "/credential/",
            "/credentials/",
            "/secret/",
            "/secrets/",
        }
    )


def _looks_like_launchd_plist(lowered: str) -> bool:
    return lowered.endswith(".plist") and any(
        marker in lowered
        for marker in {
            "/library/launchagents/",
            "/library/launchdaemons/",
            "/system/library/launchagents/",
            "/system/library/launchdaemons/",
        }
    )


def _looks_like_cron_path(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in {
            "/etc/crontab",
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/etc/cron.monthly/",
            "/etc/cron.weekly/",
            "/var/spool/cron/",
            "/var/cron/",
        }
    ) or lowered.endswith("/crontab")


def _looks_like_systemd_unit(lowered: str) -> bool:
    return "/systemd/" in lowered and lowered.endswith(
        (".service", ".timer", ".socket", ".mount", ".path", ".target")
    )


def _looks_like_mcp_config(lowered: str, name: str) -> bool:
    config_suffixes = (".json", ".jsonc", ".toml", ".yaml", ".yml")
    if name in {".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json"}:
        return True
    if "mcp" not in lowered or not name.endswith(config_suffixes):
        return False
    return any(
        marker in lowered
        for marker in {
            "/mcp/",
            "mcp_config",
            "mcp-config",
            "mcp.settings",
            "mcp_settings",
        }
    )


def _looks_like_runtime_config(lowered: str, name: str) -> bool:
    config_names = {
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
        "config.toml",
        "config.yaml",
        "config.yml",
        "settings.json",
    }
    if "/.agent-runtime/" in lowered or lowered.endswith("/.agent-runtime"):
        return True
    if name in config_names and any(
        marker in lowered for marker in {"runtime", "agent-runtime", ".codex", ".agent"}
    ):
        return True
    return False


def _strip_command_wrappers(parts: list[str]) -> list[str]:
    """Peel leading privilege/utility wrappers (sudo, env, nice, timeout, ...) so
    argv[0]-anchored matchers see the real command. Conservative: only peels a
    known wrapper set and never loosens matching (the result is always a suffix
    of ``parts``)."""
    i = 0
    n = len(parts)
    while i < n and parts[i] in _COMMAND_WRAPPERS:
        wrapper = parts[i]
        i += 1
        consumed_positional = False
        while i < n:
            token = parts[i]
            if token.startswith("-"):
                flag = token.split("=", 1)[0]
                i += 1
                if (
                    "=" not in token
                    and flag in _WRAPPER_VALUE_FLAGS
                    and i < n
                    and not parts[i].startswith("-")
                ):
                    i += 1
                continue
            if wrapper == "env" and "=" in token and not token.startswith("/"):
                i += 1  # VAR=value assignment before the command
                continue
            if wrapper == "timeout" and not consumed_positional:
                consumed_positional = True  # timeout's leading positional is a duration
                i += 1
                continue
            break
    return parts[i:]


def _is_path_like(token: str) -> bool:
    return (
        "/" in token
        or token.startswith(("~", "./", "../"))
        or (token.startswith(".") and token not in {".", ".."})
    )


def is_blocked_shell_target(command: str) -> bool:
    lowered = command.lower()
    parts = lowered.split()
    effective = _strip_command_wrappers(parts)
    if _looks_like_git_or_gh_mutation(command):
        return True
    if (
        effective
        and effective[0] == "rm"
        and any(
            "r" in flag and "f" in flag
            for flag in effective[1:]
            if flag.startswith("-")
        )
    ):
        return True
    if (
        effective
        and effective[0] == "chmod"
        and any(marker in lowered for marker in {".ssh", "auth", "credential"})
    ):
        return True
    # Credential-file reads via the shell must match read_file/search_files
    # handling: route path-like tokens through the shared credential-path helper.
    for token in parts:
        if _is_path_like(token) and _looks_like_credential_path(
            str(Path(token).expanduser()).replace("\\", "/").lower()
        ):
            return True
    if any(marker in lowered for marker in {"id_rsa", ".ssh/", "private_key"}):
        return True
    if "token" in lowered and any(
        marker in lowered for marker in {"http://", "https://", "curl", "wget"}
    ):
        return True

    # Block commands targeting protected configuration directories or system/agent credentials
    blocked_markers = {
        ".agent-sudo",
        ".agent-runtime",
        ".ssh",
        ".config",
        ".env",
        "pyproject.toml",
        "default_policy.yaml",
        "default_policy.yml",
        "auth.json",
        "mcp-audit.jsonl",
        "audit.jsonl",
        "audit.log",
        "agent_sudo/",
        "/library/keychains/",
        "/library/messages/",
        "/library/mail/",
        "/library/cookies/",
        "/library/safari/",
        "/library/containers/",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "/gcloud/",
        "/.kube/",
    }
    for marker in blocked_markers:
        if marker in lowered:
            return True
    if _looks_like_browser_profile_secret_command(lowered):
        return True

    # Check for symlinks pointing to protected/blocked targets
    if _has_protected_symlink(command, blocked_markers):
        return True

    return False


def _looks_like_git_or_gh_mutation(command: str) -> bool:
    try:
        argv = shlex.split(command)
    except ValueError:
        return False
    if not argv:
        return False
    command_name = Path(argv[0]).name
    if command_name == "git":
        return _looks_like_git_mutation(argv)
    if command_name == "gh":
        return _looks_like_gh_mutation(argv)
    return False


def _looks_like_git_mutation(argv: list[str]) -> bool:
    argv = _strip_git_global_options(argv)
    if len(argv) < 2:
        return False
    subcommand = argv[1]
    if subcommand == "push":
        return True
    if subcommand == "remote" and len(argv) >= 3:
        return argv[2] in {"add", "remove", "rename", "set-url", "set-head"}
    return False


def _strip_git_global_options(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    stripped = [argv[0]]
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if arg in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
            index += 2
            continue
        if arg.startswith("-C") and arg != "-C":
            index += 1
            continue
        if arg.startswith("-c") and arg != "-c":
            index += 1
            continue
        if arg.startswith("--git-dir=") or arg.startswith("--work-tree="):
            index += 1
            continue
        break
    stripped.extend(argv[index:])
    return stripped


def _looks_like_gh_mutation(argv: list[str]) -> bool:
    if len(argv) < 2:
        return False
    if argv[1] == "api":
        return _gh_api_uses_mutating_method(argv[2:])
    if argv[1] == "issue" and len(argv) >= 3:
        return argv[2] in {
            "close",
            "create",
            "delete",
            "develop",
            "edit",
            "lock",
            "reopen",
            "transfer",
            "unlock",
        }
    if argv[1] == "pr" and len(argv) >= 3:
        return argv[2] in {"close", "create", "edit", "merge", "reopen", "ready"}
    if argv[1] == "release" and len(argv) >= 3:
        return argv[2] in {"create", "delete", "edit", "upload"}
    if argv[1] == "repo" and len(argv) >= 3:
        return argv[2] in {"archive", "create", "delete", "edit", "fork", "rename"}
    if argv[1] == "workflow" and len(argv) >= 3:
        return argv[2] in {"disable", "enable", "run"}
    if argv[1] == "run":
        return True
    if argv[1] in {"auth", "config", "secret", "variable"}:
        return True
    return False


def _gh_api_uses_mutating_method(args: list[str]) -> bool:
    mutating_methods = {"POST", "PUT", "PATCH", "DELETE"}
    for index, arg in enumerate(args):
        upper = arg.upper()
        if arg in {"-f", "-F", "--raw-field"} or arg.startswith(("-f", "-F")):
            return True
        if arg.startswith("--raw-field="):
            return True
        if upper.startswith("-X") and upper[2:] in mutating_methods:
            return True
        if (
            arg == "-X"
            and index + 1 < len(args)
            and args[index + 1].upper() in mutating_methods
        ):
            return True
        if (
            arg.startswith("--method=")
            and arg.split("=", 1)[1].upper() in mutating_methods
        ):
            return True
        if (
            arg == "--method"
            and index + 1 < len(args)
            and args[index + 1].upper() in mutating_methods
        ):
            return True
    return False


def _has_protected_symlink(command: str, blocked_markers: set[str]) -> bool:
    delimiters = ["'", '"', "`", ";", "(", ")", "|", "&", ">", "<", "$", "=", ","]
    temp = command
    for d in delimiters:
        temp = temp.replace(d, " ")

    words = temp.split()
    for word in words:
        try:
            # Clean trailing punctuation but keep slashes for absolute paths
            cleaned = word.strip(".,:;?!")
            if not cleaned:
                continue
            path = Path(cleaned).expanduser()
            if path.is_symlink():
                resolved = str(path.resolve()).lower()
                for marker in blocked_markers:
                    if marker in resolved:
                        return True
        except Exception:
            pass
    return False


def is_blocked_read_target(target: str) -> bool:
    normalized = str(Path(target).expanduser()).replace("\\", "/")
    lowered = normalized.lower()
    name = Path(normalized).name.lower()
    home = str(Path.home()).replace("\\", "/").lower()

    # Paths:
    # ~/.ssh/**
    if lowered.startswith(f"{home}/.ssh/") or lowered == f"{home}/.ssh":
        return True
    # ~/.config/**
    if lowered.startswith(f"{home}/.config/") or lowered == f"{home}/.config":
        return True
    # ~/.agent-sudo/**
    if lowered.startswith(f"{home}/.agent-sudo/") or lowered == f"{home}/.agent-sudo":
        return True
    # ~/.agent-runtime/**
    if (
        lowered.startswith(f"{home}/.agent-runtime/")
        or lowered == f"{home}/.agent-runtime"
    ):
        return True
    # ~/.config/gcloud/** and ~/.kube/**
    if (
        lowered.startswith(f"{home}/.config/gcloud/")
        or lowered == f"{home}/.config/gcloud"
        or lowered.startswith(f"{home}/.kube/")
        or lowered == f"{home}/.kube"
    ):
        return True

    if _looks_like_macos_sensitive_read_path(normalized, lowered):
        return True

    # .env and .env.*
    if name == ".env" or name.startswith(".env."):
        return True
    if name in {".netrc", ".npmrc", ".pypirc"}:
        return True

    # Files containing: auth, token, credential, secret, private_key, config, api-key
    keywords = {
        "auth",
        "token",
        "credential",
        "secret",
        "private_key",
        "config",
        "api" + "_" + "key",
    }
    if any(kw in name or kw in lowered for kw in keywords):
        return True

    return False


def _looks_like_macos_sensitive_read_path(normalized: str, lowered: str) -> bool:
    home = str(Path.home()).replace("\\", "/").lower()
    macos_prefixes = {
        f"{home}/library/keychains",
        f"{home}/library/messages",
        f"{home}/library/mail",
        f"{home}/library/cookies",
        f"{home}/library/safari",
    }
    if any(
        lowered == prefix or lowered.startswith(prefix + "/")
        for prefix in macos_prefixes
    ):
        return True

    if _looks_like_browser_profile_secret_path(lowered, home):
        return True
    if _looks_like_browser_profile_path(lowered, home):
        return True

    if lowered.startswith(f"{home}/library/containers/") and any(
        marker in lowered
        for marker in {"mail", "notes", "com.apple.mail", "com.apple.notes"}
    ):
        return True

    return False


def _looks_like_browser_profile_secret_command(lowered: str) -> bool:
    home = str(Path.home()).replace("\\", "/").lower()
    return _looks_like_browser_profile_secret_path(lowered.replace("\\ ", " "), home)


def _looks_like_browser_profile_secret_path(lowered: str, home: str) -> bool:
    if not (
        lowered.endswith("/cookies")
        or lowered.endswith("/cookies.sqlite")
        or "/cookies/" in lowered
        or "/cookies.sqlite" in lowered
        or lowered.endswith("/login data")
        or "/login data" in lowered
    ):
        return False
    return _looks_like_browser_profile_path(lowered, home)


def _looks_like_browser_profile_path(lowered: str, home: str) -> bool:
    browser_prefixes = {
        f"{home}/library/application support/google/chrome/",
        f"{home}/library/application support/chromium/",
        f"{home}/library/application support/brave software/brave-browser/",
        f"{home}/library/application support/microsoft edge/",
        f"{home}/library/application support/arc/",
        f"{home}/library/application support/firefox/",
        f"{home}/library/application support/librewolf/",
        f"{home}/library/application support/vivaldi/",
        f"{home}/library/application support/opera software/",
        "~/library/application support/google/chrome/",
        "~/library/application support/chromium/",
        "~/library/application support/brave software/brave-browser/",
        "~/library/application support/microsoft edge/",
        "~/library/application support/arc/",
        "~/library/application support/firefox/",
        "~/library/application support/librewolf/",
        "~/library/application support/vivaldi/",
        "~/library/application support/opera software/",
    }
    return any(prefix in lowered for prefix in browser_prefixes)


def _injection_scan_text(request: ActionRequest) -> str:
    return " ".join(
        [
            request.source,
            request.tool,
            request.action,
            request.target,
            request.payload_summary,
        ]
    )
