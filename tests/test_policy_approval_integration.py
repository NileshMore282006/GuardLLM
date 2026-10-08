"""
Unit and Integration Tests for AgentGuard v0.7 Policy and Approval Integration

Verifies:
- Approval records cryptographically bound to principal identity
- Normal users cannot approve high-risk actions (only operator/admin)
- Approval transfer rejection: User B cannot execute an approval owned by User A
- Policy-version binding: Approval created under Policy v1 cannot be approved or executed under Policy v2
- Argument mutation rejection: Mutating tool arguments fails binding verification
- Tool mutation rejection: Mutating tool name fails binding verification
- Replay prevention: Consumed approvals cannot be re-executed
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.approval_service import (
    ActionBindingMismatchError,
    approve_and_execute,
    create_approval_request,
    execute_with_approval_token,
)
from backend.services.approval_store import (
    ApprovalReplayError,
    ApprovalStatus,
    approval_store,
)
from backend.services.authorization_service import ForbiddenError
from backend.services.identity_service import Principal
from backend.services.policy_service import policy_service


class TestPolicyApprovalIntegration(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.user_a = Principal(
            principal_id="user-demo",
            principal_type="user",
            roles=("user",),
            tenant_id="default",
            active=True,
        )
        self.user_b = Principal(
            principal_id="service-demo",
            principal_type="service",
            roles=("user",),
            tenant_id="default",
            active=True,
        )
        self.operator = Principal(
            principal_id="operator-demo",
            principal_type="user",
            roles=("operator",),
            tenant_id="default",
            active=True,
        )
        self.admin = Principal(
            principal_id="admin-demo",
            principal_type="admin",
            roles=("admin",),
            tenant_id="default",
            active=True,
        )
        with policy_service._lock:
            policy_service._policies.clear()

    def tearDown(self):
        with policy_service._lock:
            policy_service._policies.clear()

    def test_user_cannot_approve_own_or_other_approvals(self):
        """Standard user principal is forbidden from approving requests."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "audit@example.com", "subject": "Notice", "body": "Audit report"},
            request_id="req-test-1",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")
        self.assertIsNotNone(record)

        # User A attempting to approve must fail with ForbiddenError
        with self.assertRaises(ForbiddenError):
            approve_and_execute(record.approval_id, approving_principal=self.user_a)

    def test_operator_or_admin_can_approve(self):
        """Operator or admin principal can approve high-risk tool request."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "audit@example.com", "subject": "Notice", "body": "Audit report"},
            request_id="req-test-1",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")

        outcome = approve_and_execute(record.approval_id, approving_principal=self.operator)
        self.assertEqual(outcome["decision"], "ALLOW")
        self.assertEqual(outcome["approval_status"], ApprovalStatus.CONSUMED.value)

    def test_approval_principal_binding_prevents_transfer(self):
        """Another non-admin principal cannot execute a token bound to User A."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "transfer@example.com", "subject": "Check", "body": "Transfer test"},
            request_id="req-test-transfer",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")

        # Admin approves the request
        approval_store.mark_approved(record.approval_id)

        # User B attempts to execute using User A's approval
        res = execute_with_approval_token(
            approval_id=record.approval_id,
            tool_name="send_email",
            arguments={"recipient": "transfer@example.com", "subject": "Check", "body": "Transfer test"},
            request_id="req-exec-transfer",
            executing_principal=self.user_b,
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["attack_type"], "approval_binding_mismatch_principal_mismatch")

    def test_policy_version_binding_invalidates_on_policy_update(self):
        """If a policy changes (version increments), approvals created under the old version are invalidated."""
        # 1. Create a policy v1 requiring approval
        pol = policy_service.create_policy(
            name="Email Policy",
            description="Require approval for email",
            action="REQUIRE_APPROVAL",
            principal_scope=["*"],
            tool_scope=["send_email"],
            risk_levels=["high"],
            priority=200,
            principal=self.admin,
        )
        self.assertEqual(pol.version, 1)

        # 2. Create approval under Policy v1
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "pol@example.com", "subject": "Sub", "body": "Body text"},
            request_id="req-test-pol",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")
        self.assertEqual(record.policy_id, pol.policy_id)
        self.assertEqual(record.policy_version, 1)

        # 3. Admin updates the policy (increments to version 2)
        policy_service.update_policy(
            policy_id=pol.policy_id,
            description="Updated policy requirements",
            priority=300,
            principal=self.admin,
        )

        # 4. Attempting to approve under old policy version must fail closed with policy_version_mismatch
        with self.assertRaises(ActionBindingMismatchError) as ctx:
            approve_and_execute(record.approval_id, approving_principal=self.admin)
        self.assertIn("Policy binding mismatch", str(ctx.exception))

    def test_argument_mutation_rejection(self):
        """Mutating arguments after approval fails binding verification."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "safe@example.com", "subject": "Safe", "body": "Safe content"},
            request_id="req-test-args",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")

        approval_store.mark_approved(record.approval_id)

        # Attacker attempts to change recipient in execution
        res = execute_with_approval_token(
            approval_id=record.approval_id,
            tool_name="send_email",
            arguments={"recipient": "attacker@evil.com", "subject": "Safe", "body": "Safe content"},
            request_id="req-exec-args",
            executing_principal=self.user_a,
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["attack_type"], "approval_binding_mismatch_argument_hash_mismatch")

    def test_tool_mutation_rejection(self):
        """Changing tool name after approval fails binding verification."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "safe@example.com", "subject": "Safe", "body": "Safe content"},
            request_id="req-test-tool",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")

        approval_store.mark_approved(record.approval_id)

        res = execute_with_approval_token(
            approval_id=record.approval_id,
            tool_name="delete_record",
            arguments={"recipient": "safe@example.com", "subject": "Safe", "body": "Safe content"},
            request_id="req-exec-tool",
            executing_principal=self.user_a,
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["attack_type"], "approval_binding_mismatch_tool_name_mismatch")

    def test_replay_prevention(self):
        """An approval cannot be executed more than once."""
        decision, record, reason = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "single@example.com", "subject": "Single", "body": "Once"},
            request_id="req-test-replay",
            principal=self.user_a,
        )
        self.assertEqual(decision, "PENDING_APPROVAL")

        # 1st execution succeeds
        outcome = approve_and_execute(record.approval_id, approving_principal=self.admin)
        self.assertEqual(outcome["decision"], "ALLOW")

        # 2nd execution attempt must raise ApprovalReplayError
        with self.assertRaises(ApprovalReplayError):
            approve_and_execute(record.approval_id, approving_principal=self.admin)


if __name__ == "__main__":
    unittest.main()
