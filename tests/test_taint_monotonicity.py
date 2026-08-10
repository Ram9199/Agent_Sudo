"""Regression tests for issue #103: EXTERNAL_CONTENT taint must be monotonic.

External-content taint (provenance origin or source trust) may only raise a
request's classification, never lower it. Before the fix, the provenance
branch returned SENSITIVE for any non-BLOCKED action, downgrading
CRITICAL-policy actions from strong approval to normal approval.
"""

from __future__ import annotations

import unittest

from agent_sudo.classifier import ActionClassifier
from agent_sudo.models import (
    ActionRequest,
    Classification,
    OriginType,
    Provenance,
    TrustLevel,
)
from agent_sudo.policy import load_default_policy


TIER_ORDER = {
    Classification.SAFE: 0,
    Classification.SENSITIVE: 1,
    Classification.CRITICAL: 2,
    Classification.BLOCKED: 3,
}

# Targets chosen so no target-based rule (blocked read/write paths, protected
# targets, shell blocklist, injection scan) fires; only the action's policy
# tier and the taint channel under test decide the outcome.
NEUTRAL_TARGETS = {
    "run_shell_command": "echo hello",
    "send_email": "to:teammate@example.com",
    "money_transfer": "account:checking",
    "credential_access": "vault:item",
    "external_post": "https://example.com/post",
    "legal_or_employment_message": "to:teammate@example.com",
}
DEFAULT_TARGET = "notes.txt"


def _request(
    action: str,
    *,
    origin: OriginType = OriginType.USER_DIRECT,
    source_trust: TrustLevel = TrustLevel.USER_DIRECT,
) -> ActionRequest:
    return ActionRequest(
        actor="agent-a",
        source="user",
        tool="test",
        action=action,
        target=NEUTRAL_TARGETS.get(action, DEFAULT_TARGET),
        payload_summary=f"perform {action}",
        source_trust=source_trust,
        provenance=Provenance(origin_type=origin),
    )


class TaintMonotonicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_default_policy()
        self.classifier = ActionClassifier(self.policy)

    def test_external_content_origin_keeps_critical_actions_critical(self) -> None:
        for action in sorted(self.policy.critical_actions):
            with self.subTest(action=action):
                untainted = self.classifier.classify(_request(action))
                tainted = self.classifier.classify(
                    _request(action, origin=OriginType.EXTERNAL_CONTENT)
                )
                self.assertEqual(untainted, Classification.CRITICAL)
                self.assertEqual(tainted, Classification.CRITICAL)

    def test_external_content_origin_escalates_safe_to_sensitive(self) -> None:
        tainted = self.classifier.classify(
            _request("read_file", origin=OriginType.EXTERNAL_CONTENT)
        )
        self.assertEqual(tainted, Classification.SENSITIVE)

    def test_external_content_origin_keeps_sensitive_sensitive(self) -> None:
        tainted = self.classifier.classify(
            _request("write_file", origin=OriginType.EXTERNAL_CONTENT)
        )
        self.assertEqual(tainted, Classification.SENSITIVE)

    def test_external_content_origin_keeps_blocked_blocked(self) -> None:
        for action in sorted(self.policy.blocked_actions):
            with self.subTest(action=action):
                tainted = self.classifier.classify(
                    _request(action, origin=OriginType.EXTERNAL_CONTENT)
                )
                self.assertEqual(tainted, Classification.BLOCKED)

    def test_external_content_source_trust_matrix(self) -> None:
        # Guards the already-correct source_trust branch against regression.
        expectations = {
            "read_file": Classification.SENSITIVE,  # SAFE escalates
            "write_file": Classification.SENSITIVE,
            "run_shell_command": Classification.CRITICAL,
            "exfiltrate_secrets": Classification.BLOCKED,
        }
        for action, expected in expectations.items():
            with self.subTest(action=action):
                tainted = self.classifier.classify(
                    _request(action, source_trust=TrustLevel.EXTERNAL_CONTENT)
                )
                self.assertEqual(tainted, expected)

    def test_taint_never_lowers_classification_for_any_policy_action(self) -> None:
        all_actions = (
            self.policy.safe_actions
            | self.policy.sensitive_actions
            | self.policy.critical_actions
            | self.policy.blocked_actions
        )
        taints = [
            {"origin": OriginType.EXTERNAL_CONTENT},
            {"source_trust": TrustLevel.EXTERNAL_CONTENT},
            {
                "origin": OriginType.EXTERNAL_CONTENT,
                "source_trust": TrustLevel.EXTERNAL_CONTENT,
            },
        ]
        for action in sorted(all_actions):
            untainted = self.classifier.classify(_request(action))
            for taint in taints:
                with self.subTest(action=action, taint=taint):
                    tainted = self.classifier.classify(_request(action, **taint))
                    self.assertGreaterEqual(
                        TIER_ORDER[tainted],
                        TIER_ORDER[untainted],
                        f"{action}: taint lowered {untainted.value} to {tainted.value}",
                    )


if __name__ == "__main__":
    unittest.main()
