"""
AgentGuard v0.9 - HTTP Boundary & Network Security Tests
Validates request body size limits, Content-Type enforcement, malformed JSON handling,
standard security response headers, and anti-spoofing trusted proxy logic.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app, resolve_client_ip
from backend.services.credential_service import credential_service
from backend.services.principal_service import principal_service
from backend.services.tenant_service import tenant_service


class TestHTTPSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()
        _, self.user_token = credential_service.create_credential(
            "user-demo", "default", description="HTTP Test User", created_by="admin-demo"
        )
        self.headers = {
            "Authorization": f"Bearer {self.user_token}",
            "Content-Type": "application/json",
        }

    def test_security_headers_present_on_responses(self):
        """Responses include X-Content-Type-Options, X-Frame-Options, and Cache-Control."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(resp.headers.get("x-frame-options"), "DENY")
        self.assertIn("no-store", resp.headers.get("cache-control", ""))

    def test_oversized_payload_rejected_with_413(self):
        """Requests with Content-Length exceeding MAX_REQUEST_BODY_SIZE are rejected with 413."""
        # Send header advertising oversized body
        headers = dict(self.headers)
        headers["Content-Length"] = str(10 * 1024 * 1024)  # 10 MB > 1 MB limit
        resp = self.client.post("/api/v1/guard", content=b"{}", headers=headers)
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json()["error"]["code"], "PAYLOAD_TOO_LARGE")

    def test_malformed_json_returns_safe_validation_error(self):
        """Malformed JSON payloads return safe 422 VALIDATION_ERROR without stack traces."""
        resp = self.client.post(
            "/api/v1/guard",
            content=b"{bad_json: true,",
            headers=self.headers,
        )
        self.assertIn(resp.status_code, (400, 422))
        data = resp.json()
        self.assertIn("error", data)
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("File \"", resp.text)

    def test_unsupported_content_type_rejected(self):
        """Sending non-JSON Content-Type to mutating JSON endpoints returns 415."""
        headers = {
            "Authorization": f"Bearer {self.user_token}",
            "Content-Type": "text/xml",
        }
        resp = self.client.post(
            "/api/v1/guard",
            content=b"<prompt>hello</prompt>",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 415)
        self.assertEqual(resp.json()["error"]["code"], "VALIDATION_ERROR")

    def test_trusted_proxy_spoofing_defense(self):
        """X-Forwarded-For is ignored when the direct client is not a configured trusted proxy."""
        # Simulated untrusted request: client is from untrusted external IP
        from unittest.mock import MagicMock
        req = MagicMock()
        req.client.host = "203.0.113.50"  # untrusted public IP
        req.headers = {"x-forwarded-for": "10.0.0.99"}

        ip = resolve_client_ip(req)
        # Should NOT trust 10.0.0.99; should resolve to direct untrusted IP
        self.assertEqual(ip, "203.0.113.50")

    def test_trusted_proxy_forwarded_ip_honored(self):
        """X-Forwarded-For is accepted only when request arrives from trusted proxy (e.g. 127.0.0.1)."""
        from unittest.mock import MagicMock
        req = MagicMock()
        req.client.host = "127.0.0.1"  # in TRUSTED_PROXIES
        req.headers = {"x-forwarded-for": "198.51.100.25"}

        ip = resolve_client_ip(req)
        self.assertEqual(ip, "198.51.100.25")


if __name__ == "__main__":
    unittest.main()
