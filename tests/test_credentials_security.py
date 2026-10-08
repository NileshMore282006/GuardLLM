"""
AgentGuard v0.8 - Credentials Security Tests
Validates cryptographic API credential generation, Argon2id hashing, one-time disclosure,
storage security, and administrative access controls.
"""

import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.credential_service import credential_service, CredentialError
from backend.services.principal_service import principal_service
from backend.services.tenant_service import tenant_service
from backend.services.request_context import RequestSecurityContext


class TestCredentialsSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        # Ensure default tenants and principals are seeded
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        # Admin context for managing credentials
        self.admin_ctx = RequestSecurityContext(
            principal_id="admin-demo",
            roles=("admin",),
            tenant_id="default",
            global_admin=True,
        )

        # Non-admin context
        self.user_ctx = RequestSecurityContext(
            principal_id="user-demo",
            roles=("user",),
            tenant_id="default",
            global_admin=False,
        )

    def test_credential_creation_one_time_secret(self):
        """Credential secret is generated cryptographically and returned exactly once."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Test one-time secret",
            created_by="admin-demo",
        )
        self.assertTrue(cred.credential_id.startswith("c_"))
        self.assertTrue(secret.startswith("ag_"))
        self.assertIn(cred.credential_id, secret)

        # GET credential record must NOT include the secret
        retrieved = credential_service.get_credential(cred.credential_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.credential_id, cred.credential_id)
        self.assertFalse(hasattr(retrieved, "secret"))
        self.assertFalse(hasattr(retrieved, "credential_secret"))

    def test_plaintext_secret_never_stored_in_database(self):
        """Database stores only Argon2id hash, never plaintext secret or raw token."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Hash test",
            created_by="admin-demo",
        )
        with credential_service._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT credential_hash FROM credentials WHERE credential_id = ?",
                (cred.credential_id,),
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            stored_hash = row["credential_hash"]
            # Must be Argon2id hash
            self.assertTrue(stored_hash.startswith("$argon2id$"))
            # Secret must not appear in the hash
            self.assertNotIn(secret, stored_hash)

    def test_credential_verification_success_and_failure(self):
        """Valid secret verifies; incorrect secret fails verification."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Verify test",
            created_by="admin-demo",
        )
        # Correct secret
        verified = credential_service.verify_credential(cred.credential_id, secret)
        self.assertIsNotNone(verified)
        self.assertEqual(verified.credential_id, cred.credential_id)

        # Incorrect secret
        wrong_secret = secret[:-4] + "xxxx"
        failed = credential_service.verify_credential(cred.credential_id, wrong_secret)
        self.assertIsNone(failed)

    def test_unknown_credential_id_handled_safely(self):
        """Unknown credential ID verification fails closed with constant-time dummy verification."""
        failed = credential_service.verify_credential("cred_nonexistent999", "ag_cred_nonexistent999_secret")
        self.assertIsNone(failed)

    def test_revoked_credential_fails_verification(self):
        """Revoked credential immediately fails verification."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Revoke test",
            created_by="admin-demo",
        )
        credential_service.revoke_credential(cred.credential_id, revoked_by="admin-demo")

        failed = credential_service.verify_credential(cred.credential_id, secret)
        self.assertIsNone(failed)

    def test_expired_credential_fails_verification(self):
        """Expired credential fails verification immediately."""
        expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Expire test",
            expires_at=expired_time,
            created_by="admin-demo",
        )
        failed = credential_service.verify_credential(cred.credential_id, secret)
        self.assertIsNone(failed)

    def test_disabled_credential_fails_verification(self):
        """Disabled credential fails verification."""
        cred, secret = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Disable test",
            created_by="admin-demo",
        )
        with credential_service._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE credentials SET status = 'DISABLED' WHERE credential_id = ?",
                (cred.credential_id,),
            )
            conn.commit()

        failed = credential_service.verify_credential(cred.credential_id, secret)
        self.assertIsNone(failed)

    def test_credential_ownership_binding(self):
        """Credentials are bound to specific principal and tenant and cannot be hijacked."""
        cred, _ = credential_service.create_credential(
            principal_id="user-demo",
            tenant_id="default",
            description="Ownership test",
            created_by="admin-demo",
        )
        retrieved = credential_service.get_credential(cred.credential_id)
        self.assertEqual(retrieved.principal_id, "user-demo")
        self.assertEqual(retrieved.tenant_id, "default")

    def test_api_credential_lifecycle_endpoints(self):
        """REST endpoints for credential creation, listing, inspection, rotation, revocation."""
        # Create credential for admin to authenticate via Bearer
        admin_cred, admin_secret = credential_service.create_credential(
            principal_id="admin-demo",
            tenant_id="default",
            description="Admin Token",
            created_by="admin-demo",
        )
        headers = {"Authorization": f"Bearer {admin_secret}"}

        # 1. POST /api/v1/credentials
        create_resp = self.client.post(
            "/api/v1/credentials",
            json={
                "principal_id": "user-demo",
                "tenant_id": "default",
                "description": "API Test Credential",
            },
            headers=headers,
        )
        self.assertEqual(create_resp.status_code, 201)
        data = create_resp.json()
        cred_id = data["credential_id"]
        secret = data["credential_secret"]
        self.assertIn("ag_", secret)

        # 2. GET /api/v1/credentials/{cred_id}
        get_resp = self.client.get(f"/api/v1/credentials/{cred_id}", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        get_data = get_resp.json()
        self.assertEqual(get_data["credential_id"], cred_id)
        self.assertNotIn("credential_secret", get_data)
        self.assertNotIn("credential_hash", get_data)

        # 3. POST /api/v1/credentials/{cred_id}/rotate
        rotate_resp = self.client.post(f"/api/v1/credentials/{cred_id}/rotate", headers=headers)
        self.assertEqual(rotate_resp.status_code, 200)
        new_secret = rotate_resp.json()["credential_secret"]
        new_cred_id = rotate_resp.json()["new_credential_id"]
        self.assertNotEqual(secret, new_secret)

        # Old secret must no longer work
        self.assertIsNone(credential_service.verify_credential(cred_id, secret))
        # New secret must work with new credential ID
        self.assertIsNotNone(credential_service.verify_credential(new_cred_id, new_secret))

        # 4. POST /api/v1/credentials/{new_cred_id}/revoke
        revoke_resp = self.client.post(f"/api/v1/credentials/{new_cred_id}/revoke", headers=headers)
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertEqual(revoke_resp.json()["status"], "REVOKED")

        # After revocation, new secret also fails
        self.assertIsNone(credential_service.verify_credential(new_cred_id, new_secret))


if __name__ == "__main__":
    unittest.main()
