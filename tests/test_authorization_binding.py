"""Behavioral acceptance tests for the Agent_Sudo wedge.

These prove the wedge with behavior, not packaging:

  1. Exact scoped authorization  — a token scoped to one target does not
     authorize a sibling target.
  2. Replay-after-consume        — a consumed (USED) approval cannot be replayed
     to authorize a second identical request.
  3. Cross-agent/session isolation (approvals) — an approval bound to actor X /
     session S only authorizes actor X / session S.
  4. Delegation session-scoping probe — characterizes whether a delegation token
     is reusable across sessions/actors, so the design boundary is explicit
     rather than assumed.

The fourth test is a *characterization* test: it asserts the engine's current
behavior so the boundary is documented and locked in. See its docstring for the
finding.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_sudo.approvals import ApprovalProvider
from agent_sudo.audit import (
    AuditLogger,
    read_audit_entries,
    verify_authorization_binding,
)
from agent_sudo.builders import AgentActionRequest
from agent_sudo.delegations import DelegationStore
from agent_sudo.gateway import PermissionGateway
from agent_sudo.models import (
    ActionRequest,
    ApprovalResult,
    ApprovalStatus,
    Decision,
    OriginType,
    Provenance,
)
from agent_sudo.pending_approvals import PendingApprovalStore
from agent_sudo.policy import load_default_policy


class _NoTty(ApprovalProvider):
    """Non-interactive: a SENSITIVE/CRITICAL action becomes a pending request
    rather than an inline TTY prompt (mirrors the MCP server)."""

    def __init__(self) -> None:
        super().__init__(stdin_is_tty=lambda: False)


class _AlwaysApprove(ApprovalProvider):
    """Stands in for a human granting a strong approval without a passphrase."""

    def approve_critical(self, request: ActionRequest) -> ApprovalResult:
        return ApprovalResult(True, "PASSPHRASE_CONFIRM", "approved")


def _session(session_id: str) -> Provenance:
    # USER_DIRECT origin keeps source_trust consistent with source="user" so the
    # request carries no inconsistency risk-hint; only session_id varies.
    return Provenance(origin_type=OriginType.USER_DIRECT, session_id=session_id)


class ExactScopedAuthorizationTests(unittest.TestCase):
    """Goal: exact scoped authorization."""

    def setUp(self) -> None:
        self.policy = load_default_policy()

    def test_scoped_token_rejects_sibling_target(self) -> None:
        # send_message is SENSITIVE. A token scoped to channel "alerts" must
        # authorize "alerts" and must NOT authorize the sibling channel "general".
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DelegationStore(Path(tmpdir) / "delegations.json")
            store.create(
                actor="codex",
                allowed_actions=["send_message"],
                allowed_paths=["alerts"],
                max_uses=5,
                reason="alerts channel only",
            )
            gateway = PermissionGateway(
                self.policy, approvals=_NoTty(), delegation_store=store
            )

            in_scope = gateway.evaluate(
                AgentActionRequest.send_message("alerts", actor="codex")
            )
            sibling = gateway.evaluate(
                AgentActionRequest.send_message("general", actor="codex")
            )

        # The in-scope request is allowed exactly by the delegation.
        self.assertEqual(in_scope.decision, Decision.ALLOW)
        self.assertEqual(in_scope.approval_method, "DELEGATION")

        # The sibling target is NOT authorized by the scoped token: it falls
        # through to the approval path, never to a delegated ALLOW.
        self.assertNotEqual(sibling.decision, Decision.ALLOW)
        self.assertNotEqual(sibling.approval_method, "DELEGATION")


class ReplayAfterConsumeTests(unittest.TestCase):
    """Goal: replay-after-consume rejection."""

    def setUp(self) -> None:
        self.policy = load_default_policy()

    def test_consumed_approval_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending.json")
            gateway = PermissionGateway(
                self.policy, approvals=_NoTty(), pending_approval_store=store
            )
            request = AgentActionRequest.send_message("alerts", actor="codex")

            # 1. First evaluation creates a pending approval (no inline grant).
            first = gateway.evaluate(request)
            self.assertEqual(first.decision, Decision.REQUIRE_APPROVAL)
            approval_id = store.active_pending()[0].approval_request_id

            # 2. A human approves it.
            _, approve_result = store.approve(
                approval_id, approval_provider=_AlwaysApprove()
            )
            self.assertTrue(approve_result.approved)

            # 3. The next identical request is allowed exactly once and consumes
            #    the approval (marks it USED).
            consumed = gateway.evaluate(request)
            self.assertEqual(consumed.decision, Decision.ALLOW)
            self.assertEqual(consumed.approval_method, "PENDING_APPROVAL")

            # 4. Replaying the identical request does NOT re-use the consumed
            #    approval: it falls back to a fresh pending request, never ALLOW.
            replayed = gateway.evaluate(request)
            statuses = {a.status for a in store.list()}

        self.assertNotEqual(replayed.decision, Decision.ALLOW)
        self.assertEqual(replayed.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ApprovalStatus.USED, statuses)


class CrossActorSessionIsolationTests(unittest.TestCase):
    """Goal: cross-agent/session isolation for approvals.

    An approval is bound to the exact request fingerprint, which includes the
    actor and the provenance session_id. A different actor or a different
    session produces a different fingerprint and therefore cannot consume it.
    """

    def setUp(self) -> None:
        self.policy = load_default_policy()

    def _gateway(self, store: PendingApprovalStore) -> PermissionGateway:
        return PermissionGateway(
            self.policy, approvals=_NoTty(), pending_approval_store=store
        )

    def test_approval_for_actor_session_x_isolated_from_y(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PendingApprovalStore(Path(tmpdir) / "pending.json")
            gateway = self._gateway(store)

            alice_s1 = AgentActionRequest.send_message(
                "alerts", actor="alice", provenance=_session("session-1")
            )

            # Create + approve an approval bound to alice / session-1.
            gateway.evaluate(alice_s1)
            approval_id = store.active_pending()[0].approval_request_id
            store.approve(approval_id, approval_provider=_AlwaysApprove())

            # A different ACTOR (same action/target/session) cannot consume it.
            bob_s1 = AgentActionRequest.send_message(
                "alerts", actor="bob", provenance=_session("session-1")
            )
            other_actor = gateway.evaluate(bob_s1)

            # A different SESSION (same actor/action/target) cannot consume it.
            alice_s2 = AgentActionRequest.send_message(
                "alerts", actor="alice", provenance=_session("session-2")
            )
            other_session = gateway.evaluate(alice_s2)

            # The exact actor + session still consumes it (control): proves the
            # approval was valid and only the precise fingerprint matched.
            exact = gateway.evaluate(alice_s1)

        self.assertNotEqual(other_actor.decision, Decision.ALLOW)
        self.assertNotEqual(other_session.decision, Decision.ALLOW)
        self.assertEqual(exact.decision, Decision.ALLOW)
        self.assertEqual(exact.approval_method, "PENDING_APPROVAL")


class DelegationSessionScopingProbeTests(unittest.TestCase):
    """Probe: is a delegation token isolated per session / per actor?

    FINDING (characterized below): a DelegationToken has no session field, and
    DelegationStore._evaluate matches on actor + action + path only. Therefore:

      * Cross-ACTOR isolation HOLDS — a token for actor X never authorizes
        actor Y.
      * Cross-SESSION isolation does NOT hold for delegations — the same token
        authorizes any session of the same actor. This is intentional: a
        delegation is a standing, scoped grant that deliberately outlives a
        single session. Session-level isolation is provided by the approval
        layer (see CrossActorSessionIsolationTests), not by delegations.

    This test locks in that boundary so a future change to the delegation match
    rule (e.g. adding session binding) is a conscious decision with a failing
    test, not a silent drift.
    """

    def setUp(self) -> None:
        self.policy = load_default_policy()

    def test_delegation_is_actor_scoped_but_cross_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DelegationStore(Path(tmpdir) / "delegations.json")
            store.create(
                actor="codex",
                allowed_actions=["send_message"],
                allowed_paths=["alerts"],
                max_uses=5,
                reason="standing grant for codex",
            )
            gateway = PermissionGateway(
                self.policy, approvals=_NoTty(), delegation_store=store
            )

            # Same actor, session A: allowed via delegation.
            session_a = gateway.evaluate(
                AgentActionRequest.send_message(
                    "alerts", actor="codex", provenance=_session("session-A")
                )
            )
            # Same actor, DIFFERENT session B: STILL allowed via the same token.
            # (Documented boundary: delegations are session-agnostic.)
            session_b = gateway.evaluate(
                AgentActionRequest.send_message(
                    "alerts", actor="codex", provenance=_session("session-B")
                )
            )
            # DIFFERENT actor: NOT authorized by the token (actor isolation).
            other_actor = gateway.evaluate(
                AgentActionRequest.send_message(
                    "alerts", actor="mallory", provenance=_session("session-A")
                )
            )

        # Cross-session reuse is the current, intentional behavior.
        self.assertEqual(
            session_a.decision,
            Decision.ALLOW,
            "delegation should authorize the issuing actor's session",
        )
        self.assertEqual(session_a.approval_method, "DELEGATION")
        self.assertEqual(
            session_b.decision,
            Decision.ALLOW,
            "delegations are cross-session by design: a different session of the "
            "same actor is still authorized by the same token",
        )
        self.assertEqual(session_b.approval_method, "DELEGATION")

        # Cross-actor isolation holds.
        self.assertNotEqual(
            other_actor.decision,
            Decision.ALLOW,
            "a delegation for one actor must never authorize a different actor",
        )
        self.assertNotEqual(other_actor.approval_method, "DELEGATION")


class AuditBindingTests(unittest.TestCase):
    """Goal: audit-verifiable authorization binding.

    Every gateway decision is stamped with the hash of the exact request, and
    each approval consumption records that hash, so the binding is provable from
    the log alone.
    """

    def setUp(self) -> None:
        self.policy = load_default_policy()

    def _run_replay_scenario(self, tmpdir: str) -> Path:
        audit_path = Path(tmpdir) / "audit.jsonl"
        audit = AuditLogger(audit_path)
        store = PendingApprovalStore(Path(tmpdir) / "pending.json", audit_logger=audit)
        gateway = PermissionGateway(
            self.policy,
            approvals=_NoTty(),
            audit_logger=audit,
            pending_approval_store=store,
        )
        request = AgentActionRequest.send_message("alerts", actor="codex")
        gateway.evaluate(request)  # create pending
        approval_id = store.active_pending()[0].approval_request_id
        store.approve(approval_id, approval_provider=_AlwaysApprove())
        gateway.evaluate(request)  # consume -> ALLOW
        gateway.evaluate(request)  # replay -> fresh pending, not allowed
        return audit_path

    def test_gateway_decisions_carry_request_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = read_audit_entries(self._run_replay_scenario(tmpdir))
        decisions = [e for e in entries if e.get("event_type") == "gateway_decision"]
        self.assertTrue(decisions)
        for entry in decisions:
            self.assertIn("request_fingerprint", entry)
            self.assertEqual(len(entry["request_fingerprint"]), 64)

    def test_clean_log_passes_binding_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = read_audit_entries(self._run_replay_scenario(tmpdir))
        ok, message = verify_authorization_binding(entries)
        self.assertTrue(ok, message)
        # Exactly one approval was consumed in the scenario.
        self.assertIn("1 approval consumption", message)

    def test_tampered_consumption_fingerprint_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = read_audit_entries(self._run_replay_scenario(tmpdir))
        # Forge the stamped fingerprint on the consumption event.
        for entry in entries:
            if entry.get("event_type") == "approval_used":
                entry["request_fingerprint"] = "0" * 64
        ok, message = verify_authorization_binding(entries)
        self.assertFalse(ok)
        self.assertIn("does not match", message)

    def test_double_consume_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            entries = read_audit_entries(self._run_replay_scenario(tmpdir))
        used = [e for e in entries if e.get("event_type") == "approval_used"]
        self.assertEqual(len(used), 1)
        # Replaying the same consumption event must be rejected.
        entries.append(dict(used[0]))
        ok, message = verify_authorization_binding(entries)
        self.assertFalse(ok)
        self.assertIn("consumed more than once", message)


if __name__ == "__main__":
    unittest.main()
