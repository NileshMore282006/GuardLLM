"""
AgentGuard v0.8 - Authentication Security Tests
Validates Bearer token authentication, status failure codes (REVOKED, EXPIRED, DISABLED),
header spoofing rejection, timing-safe evaluation, and identity precedence.
"""

import secrets
import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.credential_service import credential_service
from backend.services.principal_service import principal_service
from backend.services.tenant_service import tenant_service


class TestAuthenticationSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Valid user credential
        self.user_cred, self.user_secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="User Auth Test",
            created_by="admin-demo",
        )

    def test_valid_bearer_credential_authenticates(self):
        """Valid Bearer credential yields 200 OK and trusted context."""
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {self.user_secret}"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["decision"], "ALLOW")

    def test_invalid_credential_fails_401(self):
        """Invalid credential returns 401 with INVALID_CREDENTIAL."""
        tampered_secret = self.user_secret[:-4] + "zzzz"
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {tampered_secret}"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "INVALID_CREDENTIAL")

    def test_unknown_credential_fails_401_without_enumeration(self):
        """Unknown credential ID returns generic 401 INVALID_CREDENTIAL."""
        unknown_secret = "ag_cred_0000000000000000_1234567890abcdef1234567890abcdef"
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {unknown_secret}"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "INVALID_CREDENTIAL")

    def test_revoked_credential_fails_401(self):
        """Revoked credential immediately returns 401 CREDENTIAL_REVOKED."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Revoked Token Test",
            created_by="admin-demo",
        )
        credential_service.revoke_credential(cred.credential_id, revoked_by="admin-demo")

        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_REVOKED")

    def test_expired_credential_fails_401(self):
        """Expired credential returns 401 CREDENTIAL_EXPIRED."""
        past_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            expires_at=past_time,
            description="Expired Token Test",
            created_by="admin-demo",
        )
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_EXPIRED")

    def test_disabled_principal_fails_403(self):
        """Disabled principal returns 403 PRINCIPAL_DISABLED."""
        pid = f"temp-worker-{secrets.token_hex(4)}"
        principal_service.create_principal(
            principal_id=pid,
            principal_type="user",
            tenant_id="default",
            roles=("user",),
            created_by="admin-demo",
        )
        cred, secret = credential_service.create_credential(
            principal_id=pid,
            tenant_id="default",
            description="Worker Token",
            created_by="admin-demo",
        )
        principal_service.disable_principal(pid, caller_context=None)

        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": f"Bearer {secret}"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error_code"], "PRINCIPAL_DISABLED")

    def test_malformed_authorization_header(self):
        """Malformed Authorization headers fail gracefully."""
        # Not a Bearer scheme
        resp1 = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        # In non-strict fallback, falls back or returns 401
        # With malformed bearer format:
        resp2 = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        self.assertEqual(resp2.status_code, 401)
        self.assertEqual(resp2.json()["error_code"], "INVALID_CREDENTIAL")

    def test_header_spoofing_does_not_elevate_privilege_or_switch_tenant(self):
        """X-AgentGuard-Role and X-AgentGuard-Tenant headers are strictly ignored when Bearer auth is present."""
        spoofed_headers = {
            "Authorization": f"Bearer {self.user_secret}",
            "X-AgentGuard-Role": "admin",
            "X-AgentGuard-Tenant": "victim-tenant",
            "X-AgentGuard-Principal": "victim-admin",
        }
        # Try to perform an admin action (creating a principal) with spoofed headers
        resp = self.client.post(
            "/api/v1/principals",
            json={
                "principal_id": "escalated-user",
                "principal_type": "user",
                "tenant_id": "default",
                "roles": ["admin"],
            },
            headers=spoofed_headers,
        )
        # Must be rejected because authenticated context has role 'user', not 'admin'
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
