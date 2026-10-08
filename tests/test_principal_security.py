"""
AgentGuard v0.8 - Principal Security Tests
Validates principal lifecycle, RBAC enforcement, self-promotion prevention,
role escalation prevention, tenant reassignment protection, and final-admin safety handling.
"""

import secrets
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.principal_service import principal_service, PrincipalError
from backend.services.tenant_service import tenant_service
from backend.services.credential_service import credential_service
from backend.services.request_context import RequestSecurityContext


class TestPrincipalSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Create admin and user credentials for HTTP requests
        self.admin_cred, self.admin_secret = credential_service.create_credential(
            principal_id="admin-demo",
            tenant_id="default",
            description="Admin bearer",
            created_by="admin-demo",
        )
        self.user_cred, self.user_secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="User bearer",
            created_by="admin-demo",
        )

        self.admin_headers = {"Authorization": f"Bearer {self.admin_secret}"}
        self.user_headers = {"Authorization": f"Bearer {self.user_secret}"}

    def test_principal_retrieval_and_attributes(self):
        """Principals are properly retrieved with all metadata."""
        p = principal_service.get_principal("admin-demo")
        self.assertIsNotNone(p)
        self.assertEqual(p.principal_id, "admin-demo")
        self.assertEqual(p.tenant_id, "default")
        self.assertIn("admin", p.roles)
        self.assertEqual(p.status, "ACTIVE")

    def test_user_cannot_create_principal(self):
        """Non-admin callers cannot create principals."""
        resp = self.client.post(
            "/api/v1/principals",
            json={
                "principal_id": "malicious-admin",
                "principal_type": "user",
                "tenant_id": "default",
                "roles": ["admin"],
            },
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIsNone(principal_service.get_principal("malicious-admin"))

    def test_admin_can_create_principal_with_valid_roles(self):
        """Admin callers can create principals with validated roles."""
        pid = f"operator-alice-{secrets.token_hex(4)}"
        resp = self.client.post(
            "/api/v1/principals",
            json={
                "principal_id": pid,
                "principal_type": "user",
                "tenant_id": "default",
                "roles": ["operator"],
            },
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 201)
        p = principal_service.get_principal(pid)
        self.assertIsNotNone(p)
        self.assertIn("operator", p.roles)

    def test_arbitrary_or_unknown_roles_rejected(self):
        """Unknown or arbitrary role names fail validation."""
        resp = self.client.post(
            "/api/v1/principals",
            json={
                "principal_id": "super-user",
                "principal_type": "user",
                "tenant_id": "default",
                "roles": ["superadmin", "root"],
            },
            headers=self.admin_headers,
        )
        self.assertIn(resp.status_code, (400, 422))

    def test_user_cannot_promote_self(self):
        """User cannot escalate their own roles."""
        resp = self.client.put(
            "/api/v1/principals/user-demo",
            json={
                "roles": ["admin"],
            },
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 403)
        p = principal_service.get_principal("user-demo")
        self.assertEqual(p.roles, ("user",))

    def test_user_cannot_change_own_tenant(self):
        """User cannot reassign their tenant."""
        resp = self.client.put(
            "/api/v1/principals/user-demo",
            json={
                "tenant_id": "enterprise-tenant",
            },
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 403)
        p = principal_service.get_principal("user-demo")
        self.assertEqual(p.tenant_id, "default")

    def test_disabling_final_admin_fails_closed(self):
        """Cannot disable the final active admin principal."""
        # Disable other admin accounts so admin-demo is the only remaining active admin
        with principal_service._lock:
            conn = principal_service._get_connection()
            try:
                with conn:
                    conn.execute("UPDATE principals SET status = 'DISABLED' WHERE principal_id = 'global-admin-demo'")
            finally:
                conn.close()

        # Attempt to disable admin-demo via API must fail closed with 400
        resp = self.client.post("/api/v1/principals/admin-demo/disable", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("final active admin", resp.json()["detail"].lower())

        p = principal_service.get_principal("admin-demo")
        self.assertEqual(p.status, "ACTIVE")

        # Restore
        principal_service._seed_defaults()

    def test_principal_disable_and_enable_lifecycle(self):
        """Admin can disable and re-enable non-final principals."""
        pid = f"service-worker-{secrets.token_hex(4)}"
        # Create a test principal
        self.client.post(
            "/api/v1/principals",
            json={
                "principal_id": pid,
                "principal_type": "service",
                "tenant_id": "default",
                "roles": ["user"],
            },
            headers=self.admin_headers,
        )

        # Disable
        dis_resp = self.client.post(f"/api/v1/principals/{pid}/disable", headers=self.admin_headers)
        self.assertEqual(dis_resp.status_code, 200)
        self.assertEqual(dis_resp.json()["status"], "DISABLED")

        p = principal_service.get_principal(pid)
        self.assertEqual(p.status, "DISABLED")

        # Enable
        en_resp = self.client.post(f"/api/v1/principals/{pid}/enable", headers=self.admin_headers)
        self.assertEqual(en_resp.status_code, 200)
        self.assertEqual(en_resp.json()["status"], "ACTIVE")


if __name__ == "__main__":
    unittest.main()
