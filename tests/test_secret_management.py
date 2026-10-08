"""
AgentGuard v0.9 - Secret & Key Management Tests
Verifies strict secret non-leakage, absence of plaintext secrets in database and logs,
fail-closed resolution, exception sanitization, and metrics safety.
"""

import io
import logging
import sqlite3
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.audit_service import audit_service
from backend.services.credential_service import credential_service
from backend.services.metrics_service import metrics
from backend.services.principal_service import principal_service
from backend.services.secret_service import EnvSecretProvider, SecretManager, secret_manager
from backend.services.tenant_service import tenant_service


class TestSecretManagement(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()
        _, self.admin_token = credential_service.create_credential(
            "admin-demo", "default", description="Secret Test Admin", created_by="admin-demo"
        )
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

    def test_credential_secret_never_persisted_plaintext(self):
        """Plaintext secret is never stored in SQLite database."""
        cred, secret_val = credential_service.create_credential(
            "user-demo", "default", description="Test Persistence", created_by="admin-demo"
        )
        # Inspect raw database record
        conn = credential_service._get_connection()
        try:
            cur = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (cred.credential_id,))
            row = dict(cur.fetchone())
            for col, val in row.items():
                if isinstance(val, str):
                    self.assertNotIn(
                        secret_val,
                        val,
                        f"Plaintext secret was persisted in column {col}!",
                    )
        finally:
            conn.close()

    def test_credential_secret_returned_exactly_once(self):
        """Plaintext secret is returned at creation time, but never on subsequent lookups or listings."""
        cred, secret_val = credential_service.create_credential(
            "user-demo", "default", description="One Time Return", created_by="admin-demo"
        )
        # API fetch single credential
        resp = self.client.get(f"/api/v1/credentials/{cred.credential_id}", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(secret_val, resp.text)
        self.assertNotIn("credential_hash", resp.text)

        # API list credentials
        list_resp = self.client.get("/api/v1/credentials", headers=self.admin_headers)
        self.assertEqual(list_resp.status_code, 200)
        self.assertNotIn(secret_val, list_resp.text)
        self.assertNotIn("credential_hash", list_resp.text)

    def test_secrets_never_appear_in_audit_records(self):
        """Audit events strictly exclude token secrets, auth headers, and canaries."""
        import uuid
        token_secret = "secret_canary_test_value_99"
        secret_manager.register_sensitive_value(token_secret)
        req_id = f"req-audit-sec-{uuid.uuid4()}"
        ev = audit_service.log_event(
            action="test_action",
            request_id=req_id,
            tool_name=f"tool_with_{token_secret}",
            error_code=f"err_{token_secret}",
        )
        events, _ = audit_service.query_events(
            principal=principal_service.get_principal("admin-demo"),
            request_id=req_id,
        )
        self.assertNotIn(token_secret, str(events))

    def test_secrets_never_appear_in_metrics(self):
        """Metrics dictionary never contains tokens or secrets."""
        data = metrics.get_metrics()
        metrics_str = str(data)
        self.assertNotIn("BLUE-ORANGE-42", metrics_str)
        self.assertNotIn(self.admin_token, metrics_str)

    def test_secret_redaction_helper(self):
        """Secret manager redacts credentials, bearer tokens, and registered secrets."""
        test_cred = "ag_0123456789abcdef_Abc123XyzSecretTokenLong"
        raw_text = f"User authenticated using Bearer {test_cred} and canary BLUE-ORANGE-42"
        redacted = secret_manager.redact_secrets(raw_text)
        self.assertNotIn("BLUE-ORANGE-42", redacted)
        self.assertNotIn("Abc123XyzSecretTokenLong", redacted)
        self.assertIn("[REDACTED_CREDENTIAL]", redacted)

    def test_exception_sanitization(self):
        """Sanitizing exceptions strips sensitive tokens from output."""
        exc = Exception(f"Failed to connect using token ag_1122334455667788_VerySecretKey12345")
        sanitized = secret_manager.sanitize_exception(exc)
        self.assertNotIn("VerySecretKey12345", sanitized)

    def test_fail_closed_on_missing_required_secret(self):
        """Attempting to resolve a required secret that is absent raises ConfigurationError."""
        from backend.services.config_validator import ConfigurationError
        mgr = SecretManager(provider=EnvSecretProvider(prefix="NONEXISTENT_PREFIX_"))
        with self.assertRaises(ConfigurationError):
            mgr.get_secret("MISSING_CRITICAL_KEY", required=True)


if __name__ == "__main__":
    unittest.main()
