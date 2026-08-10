"""Concurrency-safety regression tests for PendingApprovalStore.

Regression coverage for the falsification finding (issue #99): a single
one-use APPROVED pending approval could be consumed multiple times under
concurrent ``consume_matching`` calls, because the store performed an
unsynchronized read -> mark-USED -> write with no file lock or atomic save.

These mirror the delegation-store concurrency tests in
``tests/test_concurrency.py``. They are expected to FAIL against the
pre-fix store and PASS once the store adopts the same lock + atomic-write
discipline the delegation store already uses.
"""

from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from agent_sudo._locking import LockTimeout, file_lock
from agent_sudo.models import ActionRequest, ApprovalStatus, Classification, Decision
from agent_sudo.pending_approvals import PendingApprovalStore


def _request(target: str = "pwd", actor: str = "mcp-client") -> ActionRequest:
    return ActionRequest.from_dict(
        {
            "actor": actor,
            "source": "user",
            "source_trust": "USER_DIRECT",
            "tool": "shell",
            "action": "run_shell_command",
            "target": target,
            "payload_summary": "concurrency test",
        }
    )


def _approved_store(tmp: str, request: ActionRequest) -> PendingApprovalStore:
    """Create a store with a single approval forced to APPROVED on disk."""
    store = PendingApprovalStore(Path(tmp) / "pending.json")
    store.create(
        action_request=request,
        classification=Classification.CRITICAL,
        decision=Decision.REQUIRE_STRONG_APPROVAL,
        required_approval_method="passphrase",
        reason="concurrency test",
    )
    items = json.loads(Path(store.path).read_text())
    items[0]["status"] = "APPROVED"
    Path(store.path).write_text(json.dumps(items))
    return store


class ConcurrentConsumeMatchingTests(unittest.TestCase):
    def test_one_use_approval_consumed_exactly_once_under_parallel_attempts(
        self,
    ) -> None:
        n = 24
        with TemporaryDirectory() as tmp:
            request = _request()
            _approved_store(tmp, request)

            barrier = threading.Barrier(n)

            def attempt(_i: int):
                # Separate store object per thread over the same file, matching
                # the multi-process / multi-thread embedding the engine invites.
                store = PendingApprovalStore(Path(tmp) / "pending.json")
                barrier.wait()
                return store.consume_matching(request)

            with ThreadPoolExecutor(max_workers=n) as pool:
                results = list(pool.map(attempt, range(n)))

            consumed = [r for r in results if r is not None]
            self.assertEqual(
                len(consumed),
                1,
                f"expected exactly 1 successful consume, got {len(consumed)}",
            )

            # Store reflects exactly one USED approval, nothing left APPROVED.
            final = PendingApprovalStore(Path(tmp) / "pending.json").list(
                update_expired=False
            )
            used = [a for a in final if a.status == ApprovalStatus.USED]
            approved = [a for a in final if a.status == ApprovalStatus.APPROVED]
            self.assertEqual(len(used), 1)
            self.assertEqual(len(approved), 0)

    def test_concurrent_consume_never_raises_torn_read(self) -> None:
        """Concurrent readers must not observe a partially written store."""
        n = 16
        with TemporaryDirectory() as tmp:
            request = _request()
            _approved_store(tmp, request)

            barrier = threading.Barrier(n)
            errors: list[Exception] = []

            def attempt(_i: int):
                store = PendingApprovalStore(Path(tmp) / "pending.json")
                barrier.wait()
                try:
                    store.consume_matching(request)
                except Exception as exc:  # noqa: BLE001 - test asserts none occur
                    errors.append(exc)

            with ThreadPoolExecutor(max_workers=n) as pool:
                list(pool.map(attempt, range(n)))

            self.assertEqual(errors, [], f"torn reads/writes raised: {errors!r}")


class ExpireOnReadLockTests(unittest.TestCase):
    """The expire-on-read path (`list(update_expired=True)` -> `_expire_stale`
    -> save) is a writer and must run under the same file lock as the mutators.
    Before the follow-up fix it ran unlocked, so a reader holding a stale
    snapshot could write an approval back to APPROVED after a concurrent consume
    had marked it USED. This mirrors the delegation/audit lock-held tests:
    holding the lock externally must block the writing read path, not let it
    silently save underneath the lock.
    """

    def test_expire_on_read_is_serialized_under_the_file_lock(self) -> None:
        with TemporaryDirectory() as tmp:
            store = PendingApprovalStore(Path(tmp) / "pending.json", lock_timeout=0.2)
            # One expired PENDING entry, so _expire_stale would want to write.
            store.create(
                action_request=_request(),
                classification=Classification.CRITICAL,
                decision=Decision.REQUIRE_STRONG_APPROVAL,
                required_approval_method="passphrase",
                reason="stale",
            )
            items = json.loads(Path(store.path).read_text())
            items[0]["expires_at"] = "2000-01-01T00:00:00Z"
            Path(store.path).write_text(json.dumps(items))

            # Hold the lock externally; a writing read must contend and time out,
            # proving it acquires the lock rather than saving unsynchronized.
            with file_lock(store._lock_path, timeout=2.0):
                with self.assertRaises(LockTimeout):
                    store.list(update_expired=True)

            # A pure read (no write) is unaffected and never contends.
            with file_lock(store._lock_path, timeout=2.0):
                rows = store.list(update_expired=False)
            self.assertEqual(len(rows), 1)

    def test_concurrent_consume_with_stale_expiry_consumes_once(self) -> None:
        """Stress: consumers race readers that trigger expire-on-read saves; the
        target must be consumed at most once and never left APPROVED after use.
        """
        target = _request()
        for _ in range(40):
            with TemporaryDirectory() as tmp:
                store = PendingApprovalStore(Path(tmp) / "pending.json")
                store.create(
                    action_request=target,
                    classification=Classification.CRITICAL,
                    decision=Decision.REQUIRE_STRONG_APPROVAL,
                    required_approval_method="passphrase",
                    reason="target",
                )
                for i in range(20):
                    store.create(
                        action_request=_request(target=f"stale-{i}"),
                        classification=Classification.CRITICAL,
                        decision=Decision.REQUIRE_STRONG_APPROVAL,
                        required_approval_method="passphrase",
                        reason="stale",
                    )
                items = json.loads(Path(store.path).read_text())
                for it in items:
                    if it["action_request"]["target"] == "pwd":
                        it["status"] = "APPROVED"
                    else:
                        it["expires_at"] = "2000-01-01T00:00:00Z"
                Path(store.path).write_text(json.dumps(items))

                p = Path(tmp) / "pending.json"
                barrier = threading.Barrier(6)
                consumes: list = []

                def consumer():
                    barrier.wait()
                    consumes.append(PendingApprovalStore(p).consume_matching(target))

                def reader():
                    barrier.wait()
                    PendingApprovalStore(p).find_matching(target)

                threads = [threading.Thread(target=consumer) for _ in range(2)]
                threads += [threading.Thread(target=reader) for _ in range(4)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                succeeded = [c for c in consumes if c is not None]
                self.assertLessEqual(len(succeeded), 1)
                final = PendingApprovalStore(p).list(update_expired=False)
                row = [a for a in final if a.action_request.target == "pwd"][0]
                if succeeded:
                    self.assertEqual(row.status, ApprovalStatus.USED)


class ApproveLockDisciplineTests(unittest.TestCase):
    """approve() must not hold the file lock across the passphrase prompt, and
    must re-verify the approval is still PENDING before applying (so a consume
    or deny landing during the prompt is never clobbered)."""

    def _critical_pending(self, tmp: str):
        store = PendingApprovalStore(Path(tmp) / "pending.json")
        ap = store.create(
            action_request=_request(),
            classification=Classification.CRITICAL,
            decision=Decision.REQUIRE_STRONG_APPROVAL,
            required_approval_method="passphrase",
            reason="critical",
        )
        return store, ap

    def test_lock_is_released_during_passphrase_prompt(self) -> None:
        with TemporaryDirectory() as tmp:
            store, ap = self._critical_pending(tmp)
            observed = {}

            class _LockProbingProvider:
                def approve_critical(self, action_request):
                    # The lock must be free here; acquire it with a short timeout.
                    try:
                        with file_lock(store._lock_path, timeout=0.5):
                            observed["free"] = True
                    except LockTimeout:
                        observed["free"] = False
                    from agent_sudo.models import ApprovalResult

                    return ApprovalResult(True, "PASSPHRASE", "approved")

            target, result = store.approve(
                ap.approval_request_id, approval_provider=_LockProbingProvider()
            )
            self.assertTrue(observed.get("free"), "lock was held during the prompt")
            self.assertTrue(result.approved)
            self.assertEqual(target.status, ApprovalStatus.APPROVED)

    def test_reverify_does_not_clobber_state_changed_during_prompt(self) -> None:
        with TemporaryDirectory() as tmp:
            store, ap = self._critical_pending(tmp)

            class _RacingProvider:
                """Simulates a concurrent consume landing during the prompt by
                marking the pending row USED behind approve()'s back."""

                def approve_critical(self, action_request):
                    items = json.loads(Path(store.path).read_text())
                    for it in items:
                        if it["status"] == "PENDING":
                            it["status"] = "USED"
                    Path(store.path).write_text(json.dumps(items))
                    from agent_sudo.models import ApprovalResult

                    return ApprovalResult(True, "PASSPHRASE", "approved")

            target, result = store.approve(
                ap.approval_request_id, approval_provider=_RacingProvider()
            )

            # The approval must NOT be resurrected to APPROVED.
            final = store.list(update_expired=False)
            row = final[0]
            self.assertEqual(
                row.status,
                ApprovalStatus.USED,
                "approve() clobbered a state change made during the prompt",
            )
            self.assertEqual(target.status, ApprovalStatus.USED)


if __name__ == "__main__":
    unittest.main()
