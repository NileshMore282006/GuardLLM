"""
AgentGuard v0.9 - Health & Readiness Security Tests
Validates lightweight health probe, comprehensive multi-component readiness checks,
fail-safe behavior on broken dependencies or invalid configurations, and absence
of sensitive filesystem paths or credentials in responses.
"""

import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.audit_service import audit_service
from backend.services.credential_service import credential_service


class TestReadinessSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check_lightweight_and_safe(self):
        """GET /health returns 200 OK without invoking external dependencies."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertNotIn("password", resp.text)
        self.assertNotIn(".db", resp.text)

    def test_readiness_healthy_when_dependencies_available(self):
        """GET /ready returns 200 when all stores and Ollama are reachable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ready")
            self.assertEqual(data["ollama"], "connected")
            self.assertIn("checks", data)
            self.assertEqual(data["checks"]["audit_store"], "ok")
            self.assertEqual(data["checks"]["credential_store"], "ok")

    def test_readiness_fails_when_ollama_unavailable(self):
        """GET /ready returns 503 DEPENDENCY_UNAVAILABLE when Ollama is unreachable."""
        with patch("requests.get", side_effect=Exception("Connection refused")):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["status"], "not_ready")
            self.assertEqual(data["error"]["code"], "DEPENDENCY_UNAVAILABLE")
            self.assertNotIn("Traceback", resp.text)

    def test_readiness_fails_when_credential_store_unhealthy(self):
        """GET /ready returns 503 when credential database integrity check fails."""
        with patch.object(credential_service, "is_healthy", return_value=False):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["status"], "not_ready")
            self.assertEqual(data["error"]["code"], "DEPENDENCY_UNAVAILABLE")

    def test_readiness_fails_when_audit_store_unhealthy(self):
        """GET /ready returns 503 when audit database integrity check fails."""
        with patch.object(audit_service, "is_healthy", return_value=False):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["status"], "not_ready")
            self.assertEqual(data["error"]["code"], "DEPENDENCY_UNAVAILABLE")

    def test_readiness_never_leaks_db_paths_or_secrets(self):
        """Readiness responses never reveal filesystem paths or secrets."""
        with patch("requests.get", return_value=MagicMock(status_code=200)):
            resp = self.client.get("/ready")
            self.assertNotIn(".db", resp.text)
            self.assertNotIn("data/", resp.text)
            self.assertNotIn("BLUE-ORANGE-42", resp.text)


if __name__ == "__main__":
    unittest.main()
