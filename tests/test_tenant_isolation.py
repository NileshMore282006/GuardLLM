"""
AgentGuard v0.8 - Tenant Isolation & Administration Tests
Validates tenant model, active/disabled states, global-admin vs tenant-admin privileges,
and tenant lifecycle operations.
"""

import secrets
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.tenant_service import tenant_service, TenantError
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service
from backend.services.request_context import RequestSecurityContext


class TestTenantIsolation(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Global admin credential (tenant=default, global_admin=True)
        _, self.global_admin_secret = credential_service.create_credential(
            principal_id="global-admin-demo",
            tenant_id="default",
            description="Global Admin bearer",
            created_by="global-admin-demo",
        )
        self.global_admin_headers = {"Authorization": f"Bearer {self.global_admin_secret}"}

        # Create Tenant Alpha and Tenant Beta if not already present
        if not tenant_service.get_tenant("tenant-alpha"):
            tenant_service.create_tenant(
                tenant_id="tenant-alpha",
                name="Alpha Corp",
                created_by="admin-demo",
            )
        else:
            tenant_service.enable_tenant("tenant-alpha")

        if not tenant_service.get_tenant("tenant-beta"):
            tenant_service.create_tenant(
                tenant_id="tenant-beta",
                name="Beta LLC",
                created_by="admin-demo",
            )
        else:
            tenant_service.enable_tenant("tenant-beta")

        # Create Tenant-Admin in Alpha (NOT global admin)
        if not principal_service.get_principal("alpha-admin"):
            principal_service.create_principal(
                principal_id="alpha-admin",
                principal_type="admin",
                tenant_id="tenant-alpha",
                roles=("admin",),
                created_by="admin-demo",
            )
        _, self.alpha_admin_secret = credential_service.create_credential(
            principal_id="alpha-admin",
            tenant_id="tenant-alpha",
            description="Alpha Admin bearer",
            created_by="admin-demo",
        )
        self.alpha_admin_headers = {"Authorization": f"Bearer {self.alpha_admin_secret}"}

        # Create Normal User in Alpha
        if not principal_service.get_principal("alpha-user"):
            principal_service.create_principal(
                principal_id="alpha-user",
                principal_type="user",
                tenant_id="tenant-alpha",
                roles=("user",),
                created_by="alpha-admin",
            )
        _, self.alpha_user_secret = credential_service.create_credential(
            principal_id="alpha-user",
            tenant_id="tenant-alpha",
            description="Alpha User bearer",
            created_by="alpha-admin",
        )
        self.alpha_user_headers = {"Authorization": f"Bearer {self.alpha_user_secret}"}

    def test_global_admin_can_create_and_list_tenants(self):
        """Global admin has authority to create, inspect, and list all tenants."""
        tid = f"tenant-gamma-{secrets.token_hex(4)}"
        resp = self.client.post(
            "/api/v1/tenants",
            json={"tenant_id": tid, "name": "Gamma Inc"},
            headers=self.global_admin_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["tenant_id"], tid)
        self.assertEqual(data["status"], "ACTIVE")

        list_resp = self.client.get("/api/v1/tenants", headers=self.global_admin_headers)
        self.assertEqual(list_resp.status_code, 200)
        tenants = [t["tenant_id"] for t in list_resp.json()["tenants"]]
        self.assertIn(tid, tenants)
        self.assertIn("tenant-alpha", tenants)

    def test_tenant_admin_cannot_access_cross_tenant_management(self):
        """Tenant admin cannot create tenants, list all tenants, or manage other tenants."""
        # Cannot create new tenants
        create_resp = self.client.post(
            "/api/v1/tenants",
            json={"tenant_id": "tenant-rogue", "name": "Rogue"},
            headers=self.alpha_admin_headers,
        )
        self.assertEqual(create_resp.status_code, 403)

        # Cannot inspect another tenant
        get_beta = self.client.get("/api/v1/tenants/tenant-beta", headers=self.alpha_admin_headers)
        self.assertIn(get_beta.status_code, (403, 404))

        # Cannot disable another tenant
        dis_beta = self.client.post("/api/v1/tenants/tenant-beta/disable", headers=self.alpha_admin_headers)
        self.assertEqual(dis_beta.status_code, 403)

    def test_disabled_tenant_blocks_all_requests(self):
        """When a tenant is DISABLED, requests from its principals are rejected with 403 TENANT_DISABLED."""
        # Disable tenant-alpha
        dis_resp = self.client.post("/api/v1/tenants/tenant-alpha/disable", headers=self.global_admin_headers)
        self.assertEqual(dis_resp.status_code, 200)
        self.assertEqual(dis_resp.json()["status"], "DISABLED")

        # Now any authenticated request with alpha credentials must fail closed
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers=self.alpha_user_headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error_code"], "TENANT_DISABLED")

        # Re-enable tenant-alpha to prevent polluting subsequent tests
        self.client.post("/api/v1/tenants/tenant-alpha/enable", headers=self.global_admin_headers)

    def test_re_enabling_tenant_restores_access(self):
        """Enabling a previously disabled tenant restores access for its valid credentials."""
        # Disable
        self.client.post("/api/v1/tenants/tenant-alpha/disable", headers=self.global_admin_headers)

        # Enable
        en_resp = self.client.post("/api/v1/tenants/tenant-alpha/enable", headers=self.global_admin_headers)
        self.assertEqual(en_resp.status_code, 200)
        self.assertEqual(en_resp.json()["status"], "ACTIVE")

        # Now requests succeed
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers=self.alpha_user_headers,
        )
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
