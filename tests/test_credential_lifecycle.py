"""
AgentGuard v0.8 - Credential Lifecycle Tests
Validates end-to-end credential lifecycle: creation, one-time disclosure,
Argon2id hashing, rotation, immediate revocation, replay prevention, and audit integration.
"""

import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service
from backend.services.audit_service import audit_service


class TestCredentialLifecycle(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Admin credential
        _, self.admin_secret = credential_service.create_credential(
            "admin-demo", "default", description="Lifecycle Admin", created_by="admin-demo"
        )
        self.admin_headers = {"Authorization": f"Bearer {self.admin_secret}"}

    def test_creation_lifecycle_and_one_time_disclosure(self):
        """Credential creation returns secret once; subsequent queries never expose the secret or hash."""
        resp = self.client.post(
            "/api/v1/credentials",
            json={
                "principal_id": "user-demo",
                "tenant_id": "default",
                "description": "Lifecycle Test Key",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        cred_id = data["credential_id"]
        secret = data["credential_secret"]

        self.assertTrue(secret.startswith("ag_"))
        self.assertIn(cred_id, secret)

        # GET credential endpoint
        get_resp = self.client.get(f"/api/v1/credentials/{cred_id}", headers=self.admin_headers)
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertNotIn("credential_secret", get_data)
        self.assertNotIn("credential_hash", get_data)
        self.assertEqual(get_data["status"], "ACTIVE")

    def test_rotation_invalidates_old_credential_and_prevents_replay(self):
        """Rotating a credential immediately revokes the old secret and activates the new secret."""
        # Create initial credential
        create_resp = self.client.post(
            "/api/v1/credentials",
            json={"principal_id": "user-demo", "tenant_id": "default", "description": "To Rotate"},
            headers=self.admin_headers,
        )
        cred_id = create_resp.json()["credential_id"]
        old_secret = create_resp.json()["credential_secret"]

        # Verify old secret works
        guard_resp1 = self.client.post(
            "/api/v1/guard", json={"prompt": "Hello"}, headers={"Authorization": f"Bearer {old_secret}"}
        )
        self.assertEqual(guard_resp1.status_code, 200)

        # Rotate credential
        rotate_resp = self.client.post(f"/api/v1/credentials/{cred_id}/rotate", headers=self.admin_headers)
        self.assertEqual(rotate_resp.status_code, 200)
        new_secret = rotate_resp.json()["credential_secret"]
        self.assertNotEqual(old_secret, new_secret)

        # Replay attempt: Old secret must be REJECTED immediately
        replay_resp = self.client.post(
            "/api/v1/guard", json={"prompt": "Hello"}, headers={"Authorization": f"Bearer {old_secret}"}
        )
        self.assertEqual(replay_resp.status_code, 401)
        self.assertEqual(replay_resp.json()["error_code"], "CREDENTIAL_REVOKED")

        # New secret works
        guard_resp2 = self.client.post(
            "/api/v1/guard", json={"prompt": "Hello"}, headers={"Authorization": f"Bearer {new_secret}"}
        )
        self.assertEqual(guard_resp2.status_code, 200)

    def test_revocation_takes_effect_immediately(self):
        """Revoking a credential invalidates it immediately with no cached grace period."""
        create_resp = self.client.post(
            "/api/v1/credentials",
            json={"principal_id": "user-demo", "tenant_id": "default", "description": "To Revoke"},
            headers=self.admin_headers,
        )
        cred_id = create_resp.json()["credential_id"]
        secret = create_resp.json()["credential_secret"]

        # Revoke
        rev_resp = self.client.post(f"/api/v1/credentials/{cred_id}/revoke", headers=self.admin_headers)
        self.assertEqual(rev_resp.status_code, 200)
        self.assertEqual(rev_resp.json()["status"], "REVOKED")

        # Immediate request fails
        resp = self.client.post(
            "/api/v1/guard", json={"prompt": "Hello"}, headers={"Authorization": f"Bearer {secret}"}
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_REVOKED")

    def test_expired_credential_fails_verification(self):
        """Expired credential fails verification immediately."""
        expired_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Expired Key",
            expires_at=expired_time,
            created_by="admin-demo",
        )
        resp = self.client.post(
            "/api/v1/guard", json={"prompt": "Hello"}, headers={"Authorization": f"Bearer {secret}"}
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error_code"], "CREDENTIAL_EXPIRED")

    def test_audit_logs_record_lifecycle_events_without_secrets(self):
        """Credential lifecycle operations generate audit events without leaking secrets or hashes."""
        create_resp = self.client.post(
            "/api/v1/credentials",
            json={"principal_id": "user-demo", "tenant_id": "default", "description": "Audit Lifecycle"},
            headers=self.admin_headers,
        )
        cred_id = create_resp.json()["credential_id"]
        secret = create_resp.json()["credential_secret"]

        # Rotate
        self.client.post(f"/api/v1/credentials/{cred_id}/rotate", headers=self.admin_headers)
        # Revoke
        self.client.post(f"/api/v1/credentials/{cred_id}/revoke", headers=self.admin_headers)

        # Inspect audit events
        admin_principal = principal_service.get_principal("admin-demo")
        events, _ = audit_service.query_events(principal=admin_principal, limit=50)
        for ev in events:
            # No secret or hash in audit event payload or metadata
            event_str = str(ev)
            self.assertNotIn(secret, event_str)
            self.assertNotIn("$argon2id$", event_str)


if __name__ == "__main__":
    unittest.main()
