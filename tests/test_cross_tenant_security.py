"""
AgentGuard v0.8 - Cross-Tenant Security Tests
Validates strict tenant isolation across policies, approvals, audit logs,
credentials, and principals. Ensures no cross-tenant leakage or spoofing.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service
from backend.services.policy_service import policy_service
from backend.services.approval_store import approval_store
from backend.services.approval_service import generate_approval_id
from backend.services.audit_service import audit_service


class TestCrossTenantSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Create Tenant Alpha and Tenant Beta if not already present
        if not tenant_service.get_tenant("tenant-alpha"):
            tenant_service.create_tenant("tenant-alpha", name="Alpha Org", created_by="admin-demo")
        else:
            tenant_service.enable_tenant("tenant-alpha")

        if not tenant_service.get_tenant("tenant-beta"):
            tenant_service.create_tenant("tenant-beta", name="Beta Org", created_by="admin-demo")
        else:
            tenant_service.enable_tenant("tenant-beta")

        # Create Admin in Alpha
        if not principal_service.get_principal("admin-alpha"):
            principal_service.create_principal(
                "admin-alpha", principal_type="admin", tenant_id="tenant-alpha", roles=("admin",), created_by="admin-demo"
            )
        _, self.secret_alpha = credential_service.create_credential(
            "admin-alpha", "tenant-alpha", description="Alpha Admin", created_by="admin-demo"
        )
        self.headers_alpha = {"Authorization": f"Bearer {self.secret_alpha}"}

        # Create Admin in Beta
        if not principal_service.get_principal("admin-beta"):
            principal_service.create_principal(
                "admin-beta", principal_type="admin", tenant_id="tenant-beta", roles=("admin",), created_by="admin-demo"
            )
        _, self.secret_beta = credential_service.create_credential(
            "admin-beta", "tenant-beta", description="Beta Admin", created_by="admin-demo"
        )
        self.headers_beta = {"Authorization": f"Bearer {self.secret_beta}"}

        # Create Global Admin
        _, self.secret_global = credential_service.create_credential(
            "global-admin-demo", "default", description="Global Admin", created_by="global-admin-demo"
        )
        self.headers_global = {"Authorization": f"Bearer {self.secret_global}"}

    def test_cross_tenant_policy_read_isolation(self):
        """Tenant Alpha cannot read policies created by Tenant Beta."""
        # Beta creates a policy
        create_resp = self.client.post(
            "/api/v1/policies",
            json={
                "name": "Beta Private Policy",
                "action": "DENY",
                "rules": [{"tool_name": "send_email"}],
            },
            headers=self.headers_beta,
        )
        self.assertEqual(create_resp.status_code, 201)
        policy_id = create_resp.json()["policy_id"]

        # Alpha attempts to read Beta's policy
        alpha_read = self.client.get(f"/api/v1/policies/{policy_id}", headers=self.headers_alpha)
        # Must return 404 Not Found to prevent enumeration
        self.assertEqual(alpha_read.status_code, 404)

        # Alpha policy listing must not include Beta's policy
        alpha_list = self.client.get("/api/v1/policies", headers=self.headers_alpha)
        self.assertEqual(alpha_list.status_code, 200)
        p_ids = [p["policy_id"] for p in alpha_list.json()["policies"]]
        self.assertNotIn(policy_id, p_ids)

    def test_cross_tenant_policy_write_and_delete_isolation(self):
        """Tenant Alpha cannot update or delete policies created by Tenant Beta."""
        # Beta creates a policy
        create_resp = self.client.post(
            "/api/v1/policies",
            json={
                "name": "Beta Mutable Policy",
                "action": "DENY",
                "rules": [{"tool_name": "send_email"}],
            },
            headers=self.headers_beta,
        )
        policy_id = create_resp.json()["policy_id"]

        # Alpha attempts to update Beta's policy
        update_resp = self.client.put(
            f"/api/v1/policies/{policy_id}",
            json={"name": "Tampered Policy", "action": "ALLOW"},
            headers=self.headers_alpha,
        )
        self.assertEqual(update_resp.status_code, 404)

        # Alpha attempts to delete Beta's policy
        delete_resp = self.client.delete(f"/api/v1/policies/{policy_id}", headers=self.headers_alpha)
        self.assertEqual(delete_resp.status_code, 404)

        # Verify policy is unmodified in Beta
        beta_read = self.client.get(f"/api/v1/policies/{policy_id}", headers=self.headers_beta)
        self.assertEqual(beta_read.status_code, 200)
        self.assertEqual(beta_read.json()["name"], "Beta Mutable Policy")

    def test_cross_tenant_approval_isolation(self):
        """Tenant Alpha cannot view, approve, deny, or execute Tenant Beta approvals."""
        appr_id = generate_approval_id()
        # Create an approval record for Tenant Beta
        record = approval_store.create_approval(
            approval_id=appr_id,
            request_id="req-beta-1",
            tool_name="send_email",
            risk_level="high",
            reason="Beta needs email",
            arguments_summary="Send email to partner",
            arguments_hash="hash_beta_123",
            canonical_arguments={"to": "partner@example.com"},
            principal_id="admin-beta",
            policy_id="pol-beta",
            policy_version=1,
            tenant_id="tenant-beta",
        )

        # Alpha attempts to read the approval
        read_resp = self.client.get(f"/api/v1/approvals/{appr_id}", headers=self.headers_alpha)
        self.assertEqual(read_resp.status_code, 404)

        # Alpha attempts to approve it
        approve_resp = self.client.post(f"/api/v1/approvals/{appr_id}/approve", headers=self.headers_alpha)
        self.assertIn(approve_resp.status_code, (403, 404))

        # Alpha attempts to deny it
        deny_resp = self.client.post(f"/api/v1/approvals/{appr_id}/deny", headers=self.headers_alpha)
        self.assertIn(deny_resp.status_code, (403, 404))

    def test_cross_tenant_audit_isolation(self):
        """Tenant Alpha admin cannot view Tenant Beta audit logs, even if querying with ?tenant_id=tenant-beta."""
        # Log an event for Beta
        audit_service.log_event(
            action="beta_secret_operation",
            request_id="req-beta-audit-1",
            principal_id="admin-beta",
            tenant_id="tenant-beta",
            decision="ALLOW",
        )

        # Alpha attempts to query Beta's audit events
        resp = self.client.get("/api/v1/audit/events?tenant_id=tenant-beta", headers=self.headers_alpha)
        self.assertIn(resp.status_code, (200, 403))
        if resp.status_code == 200:
            events = resp.json()["events"]
            # Must only contain events for tenant-alpha, zero events for tenant-beta
            for ev in events:
                self.assertEqual(ev["tenant_id"], "tenant-alpha")

        # Global admin CAN query across tenants or query tenant-beta specifically
        global_resp = self.client.get("/api/v1/audit/events?tenant_id=tenant-beta", headers=self.headers_global)
        self.assertEqual(global_resp.status_code, 200)
        global_events = global_resp.json()["events"]
        beta_actions = [e["action"] for e in global_events if e["tenant_id"] == "tenant-beta"]
        self.assertIn("beta_secret_operation", beta_actions)

    def test_cross_tenant_credential_isolation(self):
        """Tenant Alpha admin cannot view, revoke, or rotate Tenant Beta credentials."""
        # Create a credential in Beta
        beta_cred, _ = credential_service.create_credential(
            principal_id="admin-beta",
            tenant_id="tenant-beta",
            description="Beta confidential key",
            created_by="admin-beta",
        )

        # Alpha attempts to inspect Beta's credential
        inspect_resp = self.client.get(f"/api/v1/credentials/{beta_cred.credential_id}", headers=self.headers_alpha)
        self.assertEqual(inspect_resp.status_code, 404)

        # Alpha attempts to revoke Beta's credential
        revoke_resp = self.client.post(f"/api/v1/credentials/{beta_cred.credential_id}/revoke", headers=self.headers_alpha)
        self.assertEqual(revoke_resp.status_code, 404)

        # Alpha attempts to rotate Beta's credential
        rotate_resp = self.client.post(f"/api/v1/credentials/{beta_cred.credential_id}/rotate", headers=self.headers_alpha)
        self.assertEqual(rotate_resp.status_code, 404)

    def test_header_spoofing_cannot_bypass_tenant_isolation(self):
        """Sending X-AgentGuard-Tenant header does NOT grant access to other tenants."""
        # Alpha sends request with X-AgentGuard-Tenant: tenant-beta
        spoofed_headers = {
            "Authorization": f"Bearer {self.secret_alpha}",
            "X-AgentGuard-Tenant": "tenant-beta",
        }
        resp = self.client.get("/api/v1/policies", headers=spoofed_headers)
        self.assertEqual(resp.status_code, 200)
        # Policies returned must still belong to tenant-alpha
        for p in resp.json()["policies"]:
            self.assertEqual(p["tenant_id"], "tenant-alpha")


if __name__ == "__main__":
    unittest.main()
