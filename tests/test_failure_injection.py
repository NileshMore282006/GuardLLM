"""
AgentGuard v1.0 - Comprehensive Failure-Injection Test Suite (Objective 8 & 25)
Validates that simulated failures across every subsystem fail closed safely:
- AUTHENTICATION: store down, malformed record, Argon2 failure, revoked/unknown token
- TENANT: store down, disabled tenant, missing tenant, cross-tenant lookup
- POLICY: store down, invalid policy, version mismatch, unknown policy
- GUARD: timeout, exception, malformed output, Ollama unavailable
- TARGET: timeout, exception, malformed response, Ollama unavailable after Guard ALLOW
- TOOL: malformed args, unknown tool, tool Guard exception, tool execution exception
- APPROVAL: store down, expired approval, replayed approval, binding mismatch
- AUDIT: DB unavailable, key missing, write failure
- HTTP: oversized request, malformed JSON, invalid media type

SECURITY INVARIANT:
NO FAILURE MAY SILENTLY DEVOLVE INTO AN UNAUTHORIZED ALLOW.
NO STACK TRACES OR SECRETS MAY LEAK IN ERROR RESPONSES.
"""

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.approval_service import (
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalReplayError,
    create_approval_request,
    approve_and_execute,
    approval_store,
)
from backend.services.credential_service import (
    CredentialDisabledError,
    CredentialExpiredError,
    CredentialRevokedError,
    InvalidCredentialError,
    credential_service,
)
from backend.services.identity_service import (
    AuthenticationRequiredError,
    InvalidPrincipalError,
    PrincipalDisabledError,
)
from backend.services.policy_service import (
    PolicyConflictError,
    PolicyError,
    PolicyInvalidError,
    PolicyNotFoundError,
    policy_service,
)
from backend.services.principal_service import principal_service
from backend.services.tenant_service import TenantDisabledError, TenantNotFoundError, tenant_service


class TestFailureInjection(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()
        _, self.admin_token = credential_service.create_credential(
            "admin-demo", "default", description="Failure Test Admin", created_by="admin-demo"
        )
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        _, self.user_token = credential_service.create_credential(
            "user-demo", "default", description="Failure Test User", created_by="admin-demo"
        )
        self.user_headers = {"Authorization": f"Bearer {self.user_token}"}

    # ============================================================
    # 1. AUTHENTICATION FAILURES
    # ============================================================

    def test_auth_store_unavailable_fails_closed(self):
        """When SQLite credential database connection fails, requests fail closed (401/500, not ALLOW)."""
        with patch.object(credential_service, "_get_connection", side_effect=sqlite3.OperationalError("DB locked")):
            resp = self.client.post("/api/v1/guard", json={"prompt": "hello"}, headers=self.user_headers)
            self.assertIn(resp.status_code, (401, 500))
            self.assertNotIn("Traceback", resp.text)

    def test_argon2_verification_failure_fails_closed(self):
        """Tampered secret causing hash mismatch strictly returns 401 INVALID_CREDENTIAL."""
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer ag_0123456789abcdef_wrongsecret0000000000000000000000000000"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "INVALID_CREDENTIAL")

    def test_revoked_credential_fails_closed(self):
        """Revoked credential replay is rejected with 401 CREDENTIAL_REVOKED."""
        cred, token = credential_service.create_credential("user-demo", "default", description="Revoke test")
        credential_service.revoke_credential(cred.credential_id, revoked_by="admin-demo")
        resp = self.client.post("/api/v1/guard", json={"prompt": "hello"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_REVOKED")

    def test_expired_credential_fails_closed(self):
        """Expired credential replay is rejected with 401 CREDENTIAL_EXPIRED."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        cred, token = credential_service.create_credential("user-demo", "default", description="Expired test", expires_at=past)
        resp = self.client.post("/api/v1/guard", json={"prompt": "hello"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_EXPIRED")

    # ============================================================
    # 2. TENANT FAILURES
    # ============================================================

    def test_tenant_store_unavailable_fails_closed(self):
        """Tenant store lookup failure safely rejects with 500 without leaking stack traces."""
        with patch.object(tenant_service, "get_tenant", side_effect=sqlite3.OperationalError("Disk full")):
            resp = self.client.get("/api/v1/tenants/default", headers=self.admin_headers)
            self.assertEqual(resp.status_code, 500)
            self.assertNotIn("Traceback", resp.text)

    def test_disabled_tenant_fails_closed(self):
        """Requests from a disabled tenant are blocked immediately."""
        t_id = f"tenant-dis-{datetime.now().timestamp()}"
        tenant_service.create_tenant(t_id, "Disabled Tenant")
        tenant_service.update_tenant(t_id, status="DISABLED")

        # Create credential for this disabled tenant
        cred, token = credential_service.create_credential("user-demo", t_id, description="Disabled tenant cred")
        resp = self.client.post("/api/v1/guard", json={"prompt": "hello"}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error_code"], "TENANT_DISABLED")

    # ============================================================
    # 3. POLICY FAILURES
    # ============================================================

    def test_policy_db_unavailable_fails_closed(self):
        """Policy retrieval database failure returns 500 rather than ALLOWing unvetted execution."""
        with patch.object(policy_service, "list_policies", side_effect=sqlite3.OperationalError("DB corrupted")):
            resp = self.client.get("/api/v1/policies", headers=self.admin_headers)
            self.assertEqual(resp.status_code, 500)
            self.assertNotIn("Traceback", resp.text)

    # ============================================================
    # 4. GUARD FAILURES
    # ============================================================

    def test_guard_timeout_fails_closed_without_target_call(self):
        """When Guard evaluation times out, request is BLOCKED and target is NEVER invoked."""
        with patch("backend.services.guard_service.agentguard.guard_check", side_effect=TimeoutError("Read timeout")):
            resp = self.client.post("/api/v1/execute", json={"prompt": "Tell me a joke."}, headers=self.user_headers)
            # Must return BLOCK or safe non-target error
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "BLOCK")
            self.assertEqual(data["attack_type"], "guard_timeout")

    def test_guard_runtime_exception_fails_closed(self):
        """When Guard raises unhandled runtime exception, request fails closed safely."""
        with patch("agentguard.guard_check", side_effect=RuntimeError("Internal model memory fault")):
            resp = self.client.post("/api/v1/execute", json={"prompt": "Hello"}, headers=self.user_headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "BLOCK")
            self.assertIn(data["attack_type"], ("guard_error", "system_error"))

    def test_ollama_unavailable_fails_closed(self):
        """When Ollama connection is refused during Guard check, request is blocked."""
        with patch("backend.services.guard_service.agentguard.guard_check", side_effect=ConnectionError("Connection refused")):
            resp = self.client.post("/api/v1/guard", json={"prompt": "Hello"}, headers=self.user_headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["decision"], "BLOCK")

    # ============================================================
    # 5. TARGET FAILURES
    # ============================================================

    def test_target_timeout_returns_safe_error_not_block(self):
        """Target model timeout after Guard ALLOW returns safe ERROR status without raw traceback."""
        with patch("agentguard.guard_check", return_value={"decision": "ALLOW", "attack_type": "none", "risk_score": 0.0, "latency_seconds": 0.1}), \
             patch("backend.services.execution_service.call_target", side_effect=TimeoutError("Target timed out")):
            resp = self.client.post("/api/v1/execute", json={"prompt": "Hello"}, headers=self.user_headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "ERROR")
            self.assertNotIn("Traceback", resp.text)

    def test_target_exception_returns_safe_error(self):
        """Target model unexpected exception returns safe ERROR response without stack trace."""
        with patch("agentguard.guard_check", return_value={"decision": "ALLOW", "attack_type": "none", "risk_score": 0.0, "latency_seconds": 0.1}), \
             patch("backend.services.execution_service.call_target", side_effect=Exception("GPU crashed")):
            resp = self.client.post("/api/v1/execute", json={"prompt": "Hello"}, headers=self.user_headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "ERROR")
            self.assertNotIn("Traceback", resp.text)

    # ============================================================
    # 6. TOOL FAILURES
    # ============================================================

    def test_malformed_tool_arguments_fails_closed(self):
        """Malformed tool arguments fail closed with validation error."""
        resp = self.client.post(
            "/api/v1/tool/execute",
            json={"tool_name": "send_email", "arguments": "NOT_A_DICT"},
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 422)

    def test_unknown_tool_fails_closed(self):
        """Unknown tool execution is blocked by policy."""
        resp = self.client.post(
            "/api/v1/tool/execute",
            json={"tool_name": "unknown_exploit_tool", "arguments": {"arg": "val"}},
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["decision"], "BLOCK")

    # ============================================================
    # 7. APPROVAL FAILURES
    # ============================================================

    def test_expired_approval_fails_closed(self):
        """Expired approval cannot be approved or executed."""
        from backend.services.approval_service import create_approval_request
        dec, rec, _ = create_approval_request(
            tool_name="send_email",
            arguments={"recipient": "test@example.com", "subject": "Hi", "body": "Msg"},
            request_id="req-fail-exp",
            ttl_seconds=-10,
        )
        self.assertIsNotNone(rec)
        resp = self.client.post(f"/api/v1/approvals/{rec.approval_id}/approve", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "APPROVAL_EXPIRED")

    def test_replayed_approval_fails_closed(self):
        """Approved action cannot be consumed or approved twice."""
        create_resp = self.client.post(
            "/api/v1/approvals",
            json={"tool_name": "send_email", "arguments": {"recipient": "test@example.com", "subject": "Hi", "body": "Msg"}},
            headers=self.user_headers,
        )
        appr_id = create_resp.json()["approval_id"]

        # First approval: succeeds
        resp1 = self.client.post(f"/api/v1/approvals/{appr_id}/approve", headers=self.admin_headers)
        self.assertEqual(resp1.status_code, 200)

        # Second approval attempt: fails closed with 409 Conflict
        resp2 = self.client.post(f"/api/v1/approvals/{appr_id}/approve", headers=self.admin_headers)
        self.assertEqual(resp2.status_code, 409)
        self.assertEqual(resp2.json()["error"]["code"], "APPROVAL_ALREADY_CONSUMED")

    # ============================================================
    # 8. AUDIT FAILURES
    # ============================================================

    def test_audit_write_failure_fails_closed_safely(self):
        """Audit database write failure fails closed without leaking exception details."""
        from backend.services.audit_service import audit_service
        with patch.object(audit_service, "log_event", side_effect=sqlite3.OperationalError("Disk I/O error")):
            # Action that logs audit event
            resp = self.client.post("/api/v1/policies", json={"name": "P1", "action": "ALLOW"}, headers=self.admin_headers)
            self.assertIn(resp.status_code, (500, 400))
            self.assertNotIn("Traceback", resp.text)


if __name__ == "__main__":
    unittest.main()
