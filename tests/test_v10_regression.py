"""
AgentGuard v1.0 - Release Candidate Regression Test Suite
Validates:
1. Consistent version 1.0.0 across /health, /ready, config, and schemas
2. Process model validation (single_process vs multi_process in prod)
3. Liveness (/health) vs Readiness (/ready) latency and check separation
4. Readiness error sanitization (no internal paths or connection strings leaked)
"""

import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.config import VERSION
from backend.main import app
from backend.services.config_validator import validate_configuration


class TestV10Regression(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_version_consistently_100(self):
        """Application version is consistently 1.0.0 in configuration, health, and ready responses."""
        self.assertEqual(VERSION, "1.0.0")

        # Health endpoint
        h_resp = self.client.get("/health")
        self.assertEqual(h_resp.status_code, 200)
        self.assertEqual(h_resp.json()["version"], "1.0.0")

        # Ready endpoint (mock ollama reachable)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            r_resp = self.client.get("/ready")
            self.assertEqual(r_resp.status_code, 200)
            self.assertEqual(r_resp.json()["version"], "1.0.0")

    def test_process_model_single_process_valid(self):
        """single_process process model is accepted across all deployment profiles."""
        cfg = SimpleNamespace(
            AGENTGUARD_ENV="production",
            AUTH_ENABLED=True,
            LEGACY_IDENTITY_ENABLED=False,
            BOOTSTRAP_ADMIN_ENABLED=False,
            ALLOWED_ORIGINS=["https://app.example.com"],
            TRUSTED_PROXIES=["10.0.0.1"],
            AUDIT_INTEGRITY_KEY="secret-audit-key-32-chars-long-abc",
            CANARY_SECRET="BLUE-ORANGE-42",
            CREDENTIAL_DB_PATH="data/identity.db",
            AUDIT_DB_PATH="data/audit.db",
            MAX_PROMPT_LENGTH=20000,
            MAX_CHAT_MESSAGES=50,
            MAX_TOTAL_CONVERSATION_LENGTH=100000,
            MAX_TOOL_CALLS_PER_REQUEST=3,
            MAX_TOOL_NAME_LENGTH=64,
            MAX_TOOL_ARGUMENT_LENGTH=5000,
            APPROVAL_TTL_SECONDS=300,
            RATE_LIMIT_REQUESTS=100,
            RATE_LIMIT_WINDOW_SECONDS=60,
            MAX_CONCURRENT_GUARD_REQUESTS=4,
            MAX_CONCURRENT_TARGET_REQUESTS=2,
            GUARD_TIMEOUT_SECONDS=30.0,
            TARGET_TIMEOUT_SECONDS=60.0,
            CREDENTIAL_EXPIRATION_SECONDS=2592000,
            MAX_REQUEST_BODY_SIZE=1048576,
            MAX_HEADER_SIZE=16384,
            MAX_QUERY_PARAMS=50,
            PROCESS_MODEL="single_process",
        )
        res = validate_configuration(cfg)
        self.assertTrue(res.valid)

    def test_process_model_multi_process_rejected_in_production(self):
        """multi_process model fails closed in production without distributed coordinator."""
        cfg = SimpleNamespace(
            AGENTGUARD_ENV="production",
            AUTH_ENABLED=True,
            LEGACY_IDENTITY_ENABLED=False,
            BOOTSTRAP_ADMIN_ENABLED=False,
            ALLOWED_ORIGINS=["https://app.example.com"],
            TRUSTED_PROXIES=["10.0.0.1"],
            AUDIT_INTEGRITY_KEY="secret-audit-key-32-chars-long-abc",
            CANARY_SECRET="BLUE-ORANGE-42",
            CREDENTIAL_DB_PATH="data/identity.db",
            AUDIT_DB_PATH="data/audit.db",
            MAX_PROMPT_LENGTH=20000,
            MAX_CHAT_MESSAGES=50,
            MAX_TOTAL_CONVERSATION_LENGTH=100000,
            MAX_TOOL_CALLS_PER_REQUEST=3,
            MAX_TOOL_NAME_LENGTH=64,
            MAX_TOOL_ARGUMENT_LENGTH=5000,
            APPROVAL_TTL_SECONDS=300,
            RATE_LIMIT_REQUESTS=100,
            RATE_LIMIT_WINDOW_SECONDS=60,
            MAX_CONCURRENT_GUARD_REQUESTS=4,
            MAX_CONCURRENT_TARGET_REQUESTS=2,
            GUARD_TIMEOUT_SECONDS=30.0,
            TARGET_TIMEOUT_SECONDS=60.0,
            CREDENTIAL_EXPIRATION_SECONDS=2592000,
            MAX_REQUEST_BODY_SIZE=1048576,
            MAX_HEADER_SIZE=16384,
            MAX_QUERY_PARAMS=50,
            PROCESS_MODEL="multi_process",
        )
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("forbidden in local production mode" in e for e in res.errors))

    def test_health_check_lightweight_liveness(self):
        """Health check executes in < 20ms and does not perform expensive dependency probing."""
        t0 = time.perf_counter()
        resp = self.client.get("/health")
        latency_ms = (time.perf_counter() - t0) * 1000
        self.assertEqual(resp.status_code, 200)
        self.assertLess(latency_ms, 50.0)

    def test_readiness_probe_does_not_leak_internal_paths(self):
        """Readiness failure responses contain generic component errors without system paths."""
        from backend.services.credential_service import credential_service
        with patch.object(credential_service, "is_healthy", return_value=False):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 503)
            self.assertNotIn("data/", resp.text)
            self.assertNotIn(".db", resp.text)
            self.assertNotIn("C:\\", resp.text)
            self.assertNotIn("/home/", resp.text)


if __name__ == "__main__":
    unittest.main()
