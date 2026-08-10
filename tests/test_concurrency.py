"""Concurrency-safety tests for the file-backed stores (P1 hardening).

These exercise the advisory-lock + atomic-write changes in
``agent_sudo.delegations`` and ``agent_sudo.audit``:

1. Concurrent one-use delegation consumption -> exactly one ALLOW.
2. Concurrent audit appends -> linear, verifiable hash chain.
3. Lock timeout -> fail-closed denial / error, never ALLOW.
4. Corrupt delegation store -> deny, never allow.
5. Corrupt/torn audit tail -> explicit error, no false-valid chain.
6. Backward-compatible sequential one-use flow (allow once, then deny).

Threads (not processes) are sufficient: ``flock`` contends across separate
open file descriptions even within one process, which is exactly what both the
race and the lock-timeout test rely on.
"""

from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from agent_sudo._locking import file_lock
from agent_sudo.audit import AuditLogger, read_audit_entries, verify_audit_log
from agent_sudo.builders import AgentActionRequest
from agent_sudo.delegations import DelegationStore
from agent_sudo.models import Classification


def _matching_request(target: str, actor: str = "tester"):
    return AgentActionRequest.file_read(target, actor=actor, source="user")


class ConcurrentDelegationConsumptionTests(unittest.TestCase):
    def test_one_use_token_allows_exactly_once_under_parallel_attempts(self) -> None:
        n = 24
        with TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "a.txt")
            store = DelegationStore(Path(tmp) / "delegations.json")
            store.create(
                actor="tester",
                allowed_actions=["read_file"],
                allowed_paths=[target],
                ttl_seconds=3600,
                max_uses=1,
                reason="concurrency test",
            )

            barrier = threading.Barrier(n)
            request = _matching_request(target)

            def attempt(_i: int):
                barrier.wait()  # release all threads simultaneously
                return store.authorize(request, classification=Classification.SENSITIVE)

            with ThreadPoolExecutor(max_workers=n) as pool:
                results = list(pool.map(attempt, range(n)))

            allows = [r for r in results if r[0] is True]
            denies = [r for r in results if r[0] is not True]

            self.assertEqual(
                len(allows), 1, f"expected exactly 1 ALLOW, got {len(allows)}"
            )
            self.assertEqual(len(denies), n - 1)

            # Store reflects exactly one consumption.
            tokens = store.list()
            self.assertEqual(len(tokens), 1)
            self.assertEqual(tokens[0].uses, 1)


class ConcurrentAuditAppendTests(unittest.TestCase):
    def test_concurrent_appends_produce_linear_verifiable_chain(self) -> None:
        n = 50
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path)

            barrier = threading.Barrier(n)

            def append(i: int):
                barrier.wait()
                logger.record_event("concurrency_test", {"i": i})

            with ThreadPoolExecutor(max_workers=n) as pool:
                list(pool.map(append, range(n)))

            entries = read_audit_entries(path)
            self.assertEqual(len(entries), n, "row count must match attempts")

            ok, message = verify_audit_log(path)
            self.assertTrue(ok, f"hash chain must verify: {message}")

            # Linear chain: every previous_hash is unique and links forward.
            prev_hashes = [e["previous_hash"] for e in entries]
            entry_hashes = [e["entry_hash"] for e in entries]
            self.assertEqual(
                len(set(prev_hashes)), n, "forked chain: duplicate previous_hash"
            )
            self.assertEqual(prev_hashes[0], "0" * 64)
            for earlier, later in zip(entry_hashes, prev_hashes[1:]):
                self.assertEqual(earlier, later, "chain links must be contiguous")


class LockTimeoutTests(unittest.TestCase):
    def test_delegation_consume_denies_when_lock_held(self) -> None:
        with TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "a.txt")
            store = DelegationStore(Path(tmp) / "delegations.json", lock_timeout=0.2)
            store.create(
                actor="tester",
                allowed_actions=["read_file"],
                allowed_paths=[target],
                ttl_seconds=3600,
                max_uses=1,
                reason="lock timeout test",
            )
            request = _matching_request(target)

            # Hold the lock externally; the consume must time out and deny.
            with file_lock(store._lock_path, timeout=2.0):
                result, reason, _method = store.authorize(
                    request, classification=Classification.SENSITIVE
                )

            self.assertIs(result, False)
            self.assertIn("lock unavailable", reason)
            # Token must not have been consumed while denied.
            self.assertEqual(store.list()[0].uses, 0)

    def test_audit_append_raises_when_lock_held(self) -> None:
        from agent_sudo._locking import LockTimeout

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path, lock_timeout=0.2)
            with file_lock(logger._lock_path, timeout=2.0):
                with self.assertRaises(LockTimeout):
                    logger.record_event("blocked", {"x": 1})
            # Nothing was written.
            self.assertEqual(read_audit_entries(path), [])


class CorruptStoreTests(unittest.TestCase):
    def test_corrupt_delegation_store_denies_not_allows(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "delegations.json"
            path.write_text("{ this is not valid json", encoding="utf-8")
            store = DelegationStore(path)
            request = _matching_request(str(Path(tmp) / "a.txt"))

            result, reason, _method = store.authorize(
                request, classification=Classification.SENSITIVE
            )
            self.assertIs(result, False, "corrupt store must fail closed")
            self.assertIn("unreadable", reason)

    def test_corrupt_audit_tail_does_not_create_false_valid_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.record_event("first", {"i": 0})  # one valid, chained row

            # Simulate a torn/garbage final line from a crashed writer.
            with path.open("a", encoding="utf-8") as handle:
                handle.write('{"timestamp": "2026')

            with self.assertRaises(json.JSONDecodeError):
                logger.record_event("second", {"i": 1})

    def test_tampered_audit_entry_is_not_extended(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.record_event("first", {"i": 0})

            entries = read_audit_entries(path)
            entries[0]["event_type"] = "tampered"
            path.write_text(
                "\n".join(json.dumps(entry, sort_keys=True) for entry in entries)
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "entry_hash mismatch"):
                logger.record_event("second", {"i": 1})

            self.assertEqual(len(read_audit_entries(path)), 1)


class BackwardCompatSequentialTests(unittest.TestCase):
    def test_sequential_one_use_allows_then_denies(self) -> None:
        with TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "a.txt")
            store = DelegationStore(Path(tmp) / "delegations.json")
            store.create(
                actor="tester",
                allowed_actions=["read_file"],
                allowed_paths=[target],
                ttl_seconds=3600,
                max_uses=1,
                reason="sequential test",
            )
            request = _matching_request(target)

            first = store.authorize(request, classification=Classification.SENSITIVE)
            second = store.authorize(request, classification=Classification.SENSITIVE)

            self.assertIs(first[0], True)
            self.assertIs(second[0], False)
            self.assertIn("exhausted", second[1])


if __name__ == "__main__":
    unittest.main()
