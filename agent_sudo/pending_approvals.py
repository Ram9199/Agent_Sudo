from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from agent_sudo._locking import (
    DEFAULT_LOCK_TIMEOUT,
    file_lock,
    fsync_dir,
)
from agent_sudo.approvals import ApprovalProvider
from agent_sudo.audit import AuditLogger
from agent_sudo.models import (
    ActionRequest,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
    Classification,
    Decision,
)


PENDING_APPROVALS_PATH = Path.home() / ".agent-sudo" / "pending_approvals.json"
APPROVAL_TTL_ENV = "AGENT_SUDO_APPROVAL_TTL_SECONDS"
DEFAULT_APPROVAL_TTL_SECONDS = 120
MIN_APPROVAL_TTL_SECONDS = 30
MAX_APPROVAL_TTL_SECONDS = 600


class PendingApprovalStore:
    def __init__(
        self,
        path: Path = PENDING_APPROVALS_PATH,
        *,
        audit_logger: AuditLogger | None = None,
        ttl_seconds: int | None = None,
        now_func: Callable[[], datetime] | None = None,
        notify: bool | None = None,
        open_approval_terminal: bool | None = None,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ):
        self.path = path
        self.lock_timeout = lock_timeout
        self.audit_logger = audit_logger
        self.ttl_seconds = resolve_approval_ttl_seconds(ttl_seconds)
        self.now_func = now_func or (lambda: datetime.now(timezone.utc))
        self.notify = (
            notify
            if notify is not None
            else (os.environ.get("AGENT_SUDO_NOTIFY") == "1")
        )
        self.open_approval_terminal = (
            open_approval_terminal
            if open_approval_terminal is not None
            else (os.environ.get("AGENT_SUDO_OPEN_APPROVAL_TERMINAL") == "1")
        )

    @property
    def _lock_path(self) -> Path:
        return Path(str(self.path) + ".lock")

    def create(
        self,
        *,
        action_request: ActionRequest,
        classification: Classification,
        decision: Decision,
        required_approval_method: str,
        reason: str,
    ) -> ApprovalRequest:
        now = self._now()
        # Stamp which copy of Agent_Sudo requested this approval (issue #109) so
        # the prompt, notification, and audit trail all name the same process —
        # captured here, in the requesting process, then persisted on the record.
        from agent_sudo.run_context import current as current_run_context

        approval = ApprovalRequest(
            approval_request_id=str(uuid.uuid4()),
            action_request=action_request,
            classification=classification,
            decision=decision,
            required_approval_method=required_approval_method,
            created_at=_format_time(now),
            expires_at=_format_time(now + timedelta(seconds=self.ttl_seconds)),
            status=ApprovalStatus.PENDING,
            reason=reason,
            run_context=current_run_context(),
        )
        with file_lock(self._lock_path, self.lock_timeout):
            approvals = self._read()
            approvals.append(approval)
            self.save(approvals)
        self._record_state("approval_created", approval)

        if self.notify:
            try:
                import sys
                from agent_sudo.notifications import send_approval_notification

                send_approval_notification(approval)
            except Exception as exc:
                import sys

                sys.stderr.write(
                    f"Warning: failed to send desktop notification: {exc}\n"
                )

        if self.open_approval_terminal:
            try:
                import sys
                from agent_sudo.notifications import open_approval_terminal_window

                open_approval_terminal_window(self.path)
            except Exception as exc:
                import sys

                sys.stderr.write(f"Warning: failed to open approval terminal: {exc}\n")

        return approval

    def _read(self) -> list[ApprovalRequest]:
        """Pure read of the store file. No expiry side effects, no lock."""
        if not self.path.exists():
            return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("pending approvals file must contain a JSON list")
        return [ApprovalRequest.from_dict(item) for item in raw]

    @staticmethod
    def _find(
        approvals: list[ApprovalRequest], approval_request_id: str
    ) -> ApprovalRequest | None:
        for approval in approvals:
            if approval.approval_request_id == approval_request_id:
                return approval
        return None

    @staticmethod
    def _transition(
        approvals: list[ApprovalRequest],
        target: ApprovalRequest,
        status: ApprovalStatus,
        reason: str,
    ) -> tuple[ApprovalRequest, list[ApprovalRequest]]:
        new = replace(target, status=status, reason=reason)
        updated = [
            new if a.approval_request_id == target.approval_request_id else a
            for a in approvals
        ]
        return new, updated

    def list(self, *, update_expired: bool = True) -> list[ApprovalRequest]:
        # update_expired persists EXPIRED transitions via _expire_stale, which is
        # a write. Serialize it under the same file lock the mutators use so this
        # read path can never clobber a concurrent consume/deny/create (#99
        # follow-up: the previously unlocked expire-on-read could resurrect a
        # just-consumed approval). The locked mutators must NOT call this method
        # (they already hold the lock) — they expire in-place via
        # `self._expire_stale(self._read())`.
        if not update_expired:
            return self._read()
        with file_lock(self._lock_path, self.lock_timeout):
            return self._expire_stale(self._read())

    def save(self, approvals: list[ApprovalRequest]) -> None:
        # Atomic publish: write a temp file in the same directory, fsync it, then
        # os.replace over the target so a concurrent reader/crash never observes a
        # partial file. Byte-identical output to the previous write_text path.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _chmod_best_effort(self.path.parent, 0o700)
        data = (
            json.dumps(
                [approval.to_dict() for approval in approvals], indent=2, sort_keys=True
            )
            + "\n"
        )
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".pending-approvals-", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
            _chmod_best_effort(self.path, 0o600)
            fsync_dir(self.path.parent)
        except BaseException:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
            raise

    def find_matching(self, request: ActionRequest) -> ApprovalRequest | None:
        fingerprint = _request_fingerprint(request)
        matching = [
            approval
            for approval in self.list()
            if _request_fingerprint(approval.action_request) == fingerprint
            and approval.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
        ]
        return matching[-1] if matching else None

    def active_pending(self) -> list[ApprovalRequest]:
        return [
            approval
            for approval in self.list()
            if approval.status == ApprovalStatus.PENDING
        ]

    def approve(
        self,
        approval_request_id: str,
        *,
        approval_provider: ApprovalProvider,
    ) -> tuple[ApprovalRequest | None, ApprovalResult]:
        # The passphrase prompt (approve_critical) must NOT run while the file
        # lock is held — that would serialize every other store operation on
        # human input. So: resolve everything non-interactive under the lock
        # (phase 1), prompt with the lock released (phase 2), then re-acquire
        # and re-verify the approval is still PENDING before applying (phase 3).
        # The re-verify is what makes this safe: an approval consumed, denied, or
        # expired during the prompt is never clobbered back to APPROVED (#99).
        not_found = ApprovalResult(
            False, "APPROVAL_STORE", "approval request not found"
        )

        def _expire(
            approvals: list[ApprovalRequest], target: ApprovalRequest
        ) -> tuple[ApprovalRequest, ApprovalResult]:
            expired, updated = self._transition(
                approvals, target, ApprovalStatus.EXPIRED, "approval request expired"
            )
            self.save(updated)
            self._record_state("approval_expired", expired)
            return expired, ApprovalResult(
                False, "APPROVAL_STORE", "approval request expired"
            )

        # Phase 1 (locked): every outcome that needs no human input.
        pending_action: ActionRequest | None = None
        with file_lock(self._lock_path, self.lock_timeout):
            approvals = self._read()
            target = self._find(approvals, approval_request_id)
            if target is None:
                return None, not_found
            if target.status != ApprovalStatus.PENDING:
                return target, ApprovalResult(
                    False,
                    "APPROVAL_STORE",
                    f"approval request is {target.status.value}",
                )
            if self._is_expired(target):
                return _expire(approvals, target)
            if target.decision != Decision.REQUIRE_STRONG_APPROVAL:
                approved, updated = self._transition(
                    approvals,
                    target,
                    ApprovalStatus.APPROVED,
                    "approval request approved",
                )
                self.save(updated)
                self._record_state("approval_approved", approved)
                return approved, ApprovalResult(
                    True, "CLI_CONFIRM", "approval request approved"
                )
            pending_action = target.action_request

        # Phase 2 (lock released): interactive passphrase prompt.
        result = approval_provider.approve_critical(pending_action)
        if not result.approved or result.pending:
            with file_lock(self._lock_path, self.lock_timeout):
                target = self._find(self._read(), approval_request_id)
            if target is not None:
                self._record_attempt("approval_approve_failed", target, result)
            return target, result

        # Phase 3 (locked): re-verify still PENDING, then apply. Never clobber an
        # approval that was consumed/denied/expired while the prompt was open.
        with file_lock(self._lock_path, self.lock_timeout):
            approvals = self._read()
            target = self._find(approvals, approval_request_id)
            if target is None:
                return None, not_found
            if target.status != ApprovalStatus.PENDING:
                return target, ApprovalResult(
                    False,
                    "APPROVAL_STORE",
                    f"approval request is {target.status.value}",
                )
            if self._is_expired(target):
                return _expire(approvals, target)
            approved, updated = self._transition(
                approvals, target, ApprovalStatus.APPROVED, result.reason
            )
            self.save(updated)
        self._record_state("approval_approved", approved)
        return approved, result

    def deny(
        self, approval_request_id: str, *, reason: str = "approval request denied"
    ) -> ApprovalRequest | None:
        denied: ApprovalRequest | None = None
        # deny() has no interactive step, so the whole read-modify-write runs
        # under the lock (unlike approve(), which prompts for a passphrase).
        with file_lock(self._lock_path, self.lock_timeout):
            approvals = self._expire_stale(self._read())
            updated: list[ApprovalRequest] = []
            for approval in approvals:
                if approval.approval_request_id == approval_request_id:
                    approval = replace(
                        approval, status=ApprovalStatus.DENIED, reason=reason
                    )
                    denied = approval
                updated.append(approval)
            self.save(updated)
        if denied is not None:
            self._record_state("approval_denied", denied)
        return denied

    def consume_matching(self, request: ActionRequest) -> ApprovalRequest | None:
        # The entire read -> match -> mark-USED -> write must be atomic, or two
        # concurrent consumers each see the same APPROVED row and both succeed,
        # consuming a one-use approval more than once (issue #99). Mirrors the
        # delegation store's lock discipline.
        fingerprint = _request_fingerprint(request)
        consumed: ApprovalRequest | None = None
        expired_records: list[ApprovalRequest] = []
        with file_lock(self._lock_path, self.lock_timeout):
            approvals = self._expire_stale(self._read())
            updated: list[ApprovalRequest] = []
            for approval in approvals:
                if consumed is None and approval.status == ApprovalStatus.APPROVED:
                    if _request_fingerprint(approval.action_request) == fingerprint:
                        if self._is_expired(approval):
                            approval = replace(
                                approval,
                                status=ApprovalStatus.EXPIRED,
                                reason="approval request expired",
                            )
                            expired_records.append(approval)
                        else:
                            approval = replace(
                                approval,
                                status=ApprovalStatus.USED,
                                reason="approval request used",
                            )
                            consumed = approval
                updated.append(approval)
            if consumed is not None:
                self.save(updated)
        # Audit writes happen outside the pending lock; the audit logger takes its
        # own lock, and keeping them out shortens the critical section.
        for record in expired_records:
            self._record_state("approval_expired", record)
        if consumed is not None:
            # Bind the consumption to the exact request fingerprint so the audit
            # log alone proves which request consumed this approval.
            self._record_state(
                "approval_used",
                consumed,
                extra={"request_fingerprint": request_fingerprint_hash(request)},
            )
        return consumed

    def _expire_stale(self, approvals: list[ApprovalRequest]) -> list[ApprovalRequest]:
        changed = False
        updated: list[ApprovalRequest] = []
        for approval in approvals:
            if approval.status in {
                ApprovalStatus.PENDING,
                ApprovalStatus.APPROVED,
            } and self._is_expired(approval):
                approval = replace(
                    approval,
                    status=ApprovalStatus.EXPIRED,
                    reason="approval request expired",
                )
                changed = True
                self._record_state("approval_expired", approval)
            updated.append(approval)
        if changed:
            self.save(updated)
        return updated

    def _record_state(
        self,
        event_type: str,
        approval: ApprovalRequest,
        *,
        extra: dict[str, object] | None = None,
    ) -> None:
        if self.audit_logger is not None:
            payload: dict[str, object] = {"approval_request": approval.to_dict()}
            if extra:
                payload.update(extra)
            self.audit_logger.record_event(event_type, payload)

    def _record_attempt(
        self, event_type: str, approval: ApprovalRequest, result: ApprovalResult
    ) -> None:
        if self.audit_logger is not None:
            self.audit_logger.record_event(
                event_type,
                {
                    "approval_request": approval.to_dict(),
                    "approval_result": result.to_dict(),
                },
            )

    def _is_expired(self, approval: ApprovalRequest) -> bool:
        return _parse_time(approval.expires_at) <= self._now()

    def _now(self) -> datetime:
        value = self.now_func()
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def resolve_approval_ttl_seconds(value: int | str | None = None) -> int:
    raw_value: int | str | None = value
    if raw_value is None:
        raw_value = os.environ.get(APPROVAL_TTL_ENV)
    if raw_value is None or raw_value == "":
        ttl = DEFAULT_APPROVAL_TTL_SECONDS
    else:
        try:
            ttl = int(raw_value)
        except (TypeError, ValueError):
            ttl = DEFAULT_APPROVAL_TTL_SECONDS
    return min(MAX_APPROVAL_TTL_SECONDS, max(MIN_APPROVAL_TTL_SECONDS, ttl))


def resolve_approval_identifier(
    identifier: str, approvals: list[ApprovalRequest]
) -> str | None:
    if identifier.isdecimal():
        index = int(identifier)
        active = [
            approval
            for approval in approvals
            if approval.status == ApprovalStatus.PENDING
        ]
        if 1 <= index <= len(active):
            return active[index - 1].approval_request_id
    for approval in approvals:
        if approval.approval_request_id == identifier:
            return approval.approval_request_id
    return None


def format_pending_approvals(
    approvals: list[ApprovalRequest], *, now: datetime | None = None
) -> str:
    active = [
        approval for approval in approvals if approval.status == ApprovalStatus.PENDING
    ]
    if not active:
        return "No active pending approvals."
    actual_now = now or datetime.now(timezone.utc)
    if actual_now.tzinfo is None:
        actual_now = actual_now.replace(tzinfo=timezone.utc)
    rows = ["#  approval_id  action             actor       risk      age  expires"]
    for index, approval in enumerate(active, start=1):
        request = approval.action_request
        rows.append(
            "  ".join(
                [
                    str(index),
                    approval.approval_request_id,
                    _clip(request.action, 18),
                    _clip(request.actor, 10),
                    approval.classification.value,
                    _duration(
                        max(
                            0,
                            int(
                                (
                                    actual_now - _parse_time(approval.created_at)
                                ).total_seconds()
                            ),
                        )
                    ),
                    _duration(
                        max(
                            0,
                            int(
                                (
                                    _parse_time(approval.expires_at) - actual_now
                                ).total_seconds()
                            ),
                        )
                    ),
                ]
            )
        )
    return "\n".join(rows)


def expires_in_seconds(
    approval: ApprovalRequest, *, now: datetime | None = None
) -> int:
    actual_now = now or datetime.now(timezone.utc)
    if actual_now.tzinfo is None:
        actual_now = actual_now.replace(tzinfo=timezone.utc)
    return max(
        0,
        int(
            (
                _parse_time(approval.expires_at) - actual_now.astimezone(timezone.utc)
            ).total_seconds()
        ),
    )


def approval_command(approval_request_id: str) -> str:
    return f"agent-sudo approve {approval_request_id}"


def request_fingerprint(request: ActionRequest) -> str:
    return _request_fingerprint(request)


def _request_fingerprint(request: ActionRequest) -> str:
    return _fingerprint_string_from_dict(request.to_dict())


def _fingerprint_string_from_dict(data: dict) -> str:
    """Canonical fingerprint string for a serialized request dict.

    The per-call ``request_id`` / ``parent_request_id`` are zeroed so the
    fingerprint identifies the *request shape* (actor, source, tool, action,
    target, payload_summary, trust, session) rather than a single invocation.
    Two calls that differ only in those ids share a fingerprint; everything else
    (actor, session_id, target, ...) is part of it, which is what binds an
    approval to one actor + session.
    """
    data = dict(data)
    provenance = data.get("provenance")
    if isinstance(provenance, dict):
        provenance = dict(provenance)
        provenance["request_id"] = ""
        provenance["parent_request_id"] = ""
        data["provenance"] = provenance
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def request_fingerprint_hash(request: ActionRequest) -> str:
    """Stable SHA-256 of the canonical request fingerprint.

    Unlike :func:`request_fingerprint` (a JSON string used for in-process
    matching), this is a fixed-width hash suitable for stamping into audit
    records so a decision can be bound to — and re-verified against — the exact
    request that produced it, from the log alone.
    """
    return fingerprint_hash_from_dict(request.to_dict())


def fingerprint_hash_from_dict(data: dict) -> str:
    """Fingerprint hash computed directly from a serialized request dict.

    Used by the audit verifier to recompute the binding from a stored
    ``action_request`` without reconstructing an :class:`ActionRequest` (which
    would re-run trust reconciliation), so the check is a pure function of the
    bytes on disk.
    """
    return hashlib.sha256(
        _fingerprint_string_from_dict(data).encode("utf-8")
    ).hexdigest()


def _format_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except PermissionError:
        pass


def _clip(value: str, width: int) -> str:
    return value if len(value) <= width else value[: max(0, width - 1)] + "."


def _duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, remaining = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{remaining:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"
