from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_sudo._locking import DEFAULT_LOCK_TIMEOUT, file_lock
from agent_sudo.models import GatewayResult
from agent_sudo.spec_helpers import compute_entry_hash, verify_jsonl_file


class AuditLogger:
    def __init__(self, path: Path, *, lock_timeout: float = DEFAULT_LOCK_TIMEOUT):
        self.path = path
        self.lock_timeout = lock_timeout

    @property
    def _lock_path(self) -> Path:
        return Path(str(self.path) + ".lock")

    def record(self, result: GatewayResult) -> None:
        # Lazy import: pending_approvals imports this module at load time, so the
        # dependency only closes at call time (same pattern as run_context).
        from agent_sudo.pending_approvals import request_fingerprint_hash

        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": "gateway_decision",
            # Bind every decision to the exact request that produced it, so the
            # log alone proves what was authorized (and, for delegated allows,
            # that the grant was consumed for a specific request).
            "request_fingerprint": request_fingerprint_hash(result.request),
            **result.to_dict(),
        }
        self._write_entry(entry)

    def record_event(self, event_type: str, payload: dict[str, Any]) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            **payload,
        }
        self._write_entry(entry)

    def _write_entry(self, entry: dict[str, Any]) -> None:
        # Stamp which copy of Agent_Sudo wrote this entry (issue #109). Done at
        # the single write choke point so every record — decisions and approval
        # lifecycle events alike — names its producer. Additive: it is hashed
        # with the rest of the entry and ignored by older readers.
        if "run_context" not in entry:
            from agent_sudo.run_context import current as current_run_context

            entry["run_context"] = current_run_context()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Read last hash -> link -> append must be one atomic step, otherwise two
        # concurrent appends read the same previous_hash and fork the chain. The
        # lock (and full existing-chain verification in _last_entry_hash) keep
        # us fail-closed: on failure we raise rather than extend bad evidence.
        with file_lock(self._lock_path, self.lock_timeout):
            previous_hash = _last_entry_hash(self.path)
            entry["previous_hash"] = previous_hash
            entry["entry_hash"] = compute_entry_hash(previous_hash, entry)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())


def verify_audit_log(path: Path) -> tuple[bool, str]:
    result = verify_jsonl_file(path)
    if result.success:
        return True, "audit log verified"
    return False, str(result)


def verify_authorization_binding(
    entries: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Check that consumed authorizations are correctly bound to one request.

    Operates on raw audit entries (so a third party can run it against the log
    alone). It verifies two properties of the binding stamped by the engine:

      1. Integrity — each ``approval_used`` event's stamped ``request_fingerprint``
         equals the fingerprint recomputed from the embedded ``action_request``.
         A mismatch means the request or the stamp was altered after the fact.
      2. Single-consume — no approval id appears in more than one
         ``approval_used`` event. A repeat is a replay/double-consume.

    It also confirms every delegated ALLOW carries a ``request_fingerprint`` (so
    a delegated decision is always traceable to an exact request). Note this
    does NOT require a delegation token to map to a single fingerprint: a token
    is a *scoped* grant and may legitimately authorize several distinct requests
    within its scope up to ``max_uses`` — that is the documented difference
    between delegations (scoped) and approvals (exact-request).

    This does not check the hash chain; run :func:`verify_audit_log` for that.
    """
    from agent_sudo.pending_approvals import fingerprint_hash_from_dict

    problems: list[str] = []
    consumed_ids: dict[str, str] = {}
    used = 0
    delegated = 0
    for number, entry in enumerate(entries, start=1):
        event_type = str(entry.get("event_type", ""))
        if event_type == "approval_used":
            used += 1
            approval = entry.get("approval_request")
            approval = approval if isinstance(approval, dict) else {}
            approval_id = str(approval.get("approval_request_id", ""))
            stamped = entry.get("request_fingerprint")
            action_request = approval.get("action_request")
            if isinstance(action_request, dict) and isinstance(stamped, str):
                computed = fingerprint_hash_from_dict(action_request)
                if stamped != computed:
                    problems.append(
                        f"line {number}: approval_used fingerprint does not match "
                        f"its request (stamped {stamped[:12]}.., computed "
                        f"{computed[:12]}..)"
                    )
            elif stamped is None:
                problems.append(
                    f"line {number}: approval_used is not bound to a request "
                    "fingerprint"
                )
            if approval_id in consumed_ids:
                problems.append(
                    f"line {number}: approval {approval_id} consumed more than "
                    "once (replay/double-consume)"
                )
            else:
                consumed_ids[approval_id] = str(stamped or "")
        elif (
            event_type == "gateway_decision"
            and entry.get("decision") == "ALLOW"
            and entry.get("approval_method") == "DELEGATION"
        ):
            delegated += 1
            if not entry.get("request_fingerprint"):
                problems.append(
                    f"line {number}: delegated ALLOW is not bound to a request "
                    "fingerprint"
                )
    if problems:
        return False, "authorization binding check failed: " + "; ".join(problems)
    return (
        True,
        "authorization binding verified "
        f"({used} approval consumption(s), {delegated} delegated allow(s))",
    )


def read_audit_entries(path: Path) -> list[dict[str, Any]]:
    """Load audit JSONL records as a list of dicts (oldest first)."""
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def _entry_request(entry: dict[str, Any]) -> dict[str, Any]:
    """Resolve the action request inside an audit entry.

    Handles both ``gateway_decision`` records (which carry a ``request``) and
    approval lifecycle events (which carry an ``approval_request``).
    """
    request = entry.get("request")
    approval = entry.get("approval_request")
    if not isinstance(request, dict) and isinstance(approval, dict):
        request = approval.get("action_request")
    if not isinstance(request, dict):
        request = {}
    return request


def _entry_origin(entry: dict[str, Any]) -> str:
    """Origin type recorded in the entry's provenance (empty if absent)."""
    provenance = _entry_request(entry).get("provenance")
    if isinstance(provenance, dict):
        return str(provenance.get("origin_type", ""))
    return ""


def _audit_view(entry: dict[str, Any]) -> dict[str, str]:
    """Reduce a raw audit entry to the human-facing columns."""
    event_type = str(entry.get("event_type", "event"))

    request = _entry_request(entry)
    approval = entry.get("approval_request")

    if event_type == "gateway_decision":
        label = str(entry.get("decision", ""))
    else:
        label = event_type

    reason = entry.get("reason")
    if reason is None and isinstance(approval, dict):
        reason = approval.get("reason")

    return {
        "time": str(entry.get("timestamp", ""))[:19],
        "label": label,
        "origin": _entry_origin(entry),
        "actor": str(request.get("actor", "")),
        "action": str(request.get("action", "")),
        "target": str(request.get("target", "")),
        "reason": str(reason or ""),
    }


def filter_entries(
    entries: list[dict[str, Any]],
    *,
    decision: str | None = None,
    origin: str | None = None,
    actor: str | None = None,
    tool: str | None = None,
    target: str | None = None,
    non_allow: bool = False,
) -> list[dict[str, Any]]:
    """Return the subset of ``entries`` matching the given filters.

    ``decision`` and ``origin`` are exact matches (validated upstream against the
    known enum values). ``actor``/``tool``/``target`` are case-insensitive
    substring matches. ``non_allow`` drops every ``ALLOW`` decision. No filter
    argument means "keep everything", so an unfiltered call is a no-op.
    """
    selected: list[dict[str, Any]] = []
    for entry in entries:
        request = _entry_request(entry)
        entry_decision = str(entry.get("decision", ""))
        if non_allow and entry_decision == "ALLOW":
            continue
        if decision is not None and entry_decision != decision:
            continue
        if origin is not None and _entry_origin(entry) != origin:
            continue
        if (
            actor is not None
            and actor.lower() not in str(request.get("actor", "")).lower()
        ):
            continue
        if (
            tool is not None
            and tool.lower() not in str(request.get("tool", "")).lower()
        ):
            continue
        if (
            target is not None
            and target.lower() not in str(request.get("target", "")).lower()
        ):
            continue
        selected.append(entry)
    return selected


# (column header, width) pairs for the audit table.
_AUDIT_COLUMNS = [
    ("time", 19),
    ("decision", 17),
    ("origin", 16),
    ("actor", 12),
    ("action", 20),
    ("target", 22),
    ("reason", 44),
]


def format_audit_log(entries: list[dict[str, Any]], *, limit: int | None = None) -> str:
    """Render audit records as a readable table (newest at the bottom).

    Mirrors the style of ``format_pending_approvals``: a header row followed by
    clipped, space-separated columns. ``limit`` keeps only the most recent N
    records while preserving their original (1-based) record numbers.
    """
    if not entries:
        return "No audit records found."
    selected = entries if not limit or limit <= 0 else entries[-limit:]
    first_number = len(entries) - len(selected) + 1

    header = "  ".join(
        ["#".ljust(4)] + [name.ljust(width) for name, width in _AUDIT_COLUMNS]
    )
    rows = [header]
    for offset, entry in enumerate(selected):
        view = _audit_view(entry)
        cells = [str(first_number + offset).ljust(4)]
        for name, width in _AUDIT_COLUMNS:
            key = "label" if name == "decision" else name
            cells.append(_clip(view[key], width).ljust(width))
        rows.append("  ".join(cells).rstrip())
    return "\n".join(rows)


def audit_entries_since(
    entries: list[dict[str, Any]], since: timedelta
) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - since
    selected: list[dict[str, Any]] = []
    for entry in entries:
        timestamp = _parse_audit_timestamp(str(entry.get("timestamp", "")))
        if timestamp is not None and timestamp >= cutoff:
            selected.append(entry)
    return selected


def format_audit_review(entries: list[dict[str, Any]], *, since_label: str) -> str:
    counts = _decision_counts(entries)
    non_allow = [
        entry
        for entry in entries
        if str(entry.get("decision", entry.get("event_type", ""))) != "ALLOW"
    ]
    lines = [
        f"Audit review for last {since_label}",
        f"Records: {len(entries)}",
        "Decisions:",
    ]
    for decision in ("ALLOW", "REQUIRE_APPROVAL", "REQUIRE_STRONG_APPROVAL", "DENY"):
        lines.append(f"  {decision}: {counts.get(decision, 0)}")
    other_count = sum(
        count
        for decision, count in counts.items()
        if decision
        not in {"ALLOW", "REQUIRE_APPROVAL", "REQUIRE_STRONG_APPROVAL", "DENY"}
    )
    if other_count:
        lines.append(f"  OTHER: {other_count}")
    lines.append("")
    lines.append("Non-ALLOW records:")
    lines.append(format_audit_log(non_allow))
    return "\n".join(lines)


def parse_since_window(value: str) -> timedelta:
    raw = value.strip().lower()
    if not raw:
        raise ValueError("--since must not be empty")
    unit = raw[-1]
    amount = raw[:-1]
    if unit not in {"m", "h", "d"} or not amount.isdigit():
        raise ValueError("--since must use a duration like 30m, 24h, or 7d")
    number = int(amount)
    if number <= 0:
        raise ValueError("--since must be greater than zero")
    if unit == "m":
        return timedelta(minutes=number)
    if unit == "h":
        return timedelta(hours=number)
    return timedelta(days=number)


def _decision_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        label = str(entry.get("decision", entry.get("event_type", "UNKNOWN")))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _parse_audit_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _clip(value: str, width: int) -> str:
    return value if len(value) <= width else value[: max(0, width - 1)] + "."


GENESIS_HASH = "0" * 64


def _last_entry_hash(path: Path) -> str:
    """Return the final hash only when every existing entry verifies.

    Appending after a malformed or tampered entry would make the new record
    look correctly linked while preserving an invalid audit trail. Verify each
    existing link and digest before using the final hash as the next entry's
    predecessor, so writers fail closed until an operator investigates.
    """
    if not path.exists():
        return GENESIS_HASH
    last_hash = GENESIS_HASH
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError(
                    f"existing audit log line {line_number} is not a JSON object"
                )
            previous_hash = entry.get("previous_hash")
            if previous_hash != last_hash:
                raise ValueError(
                    f"existing audit log line {line_number} has a previous_hash mismatch"
                )
            value = entry.get("entry_hash")
            expected_hash = compute_entry_hash(last_hash, entry)
            if value != expected_hash:
                raise ValueError(
                    f"existing audit log line {line_number} has an entry_hash mismatch"
                )
            last_hash = value
    return last_hash
