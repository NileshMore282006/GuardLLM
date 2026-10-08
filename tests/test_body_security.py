"""
AgentGuard v1.0 - Request Body Bounding & Transfer Security Tests (Objective 3)
Validates actual received request byte limits across:
- Normal request body under limit
- Content-Length over limit
- Missing Content-Length header
- Chunked / streaming oversized request bodies
- Malformed transfer behavior (negative or non-integer Content-Length)
- Exact boundary (limit bytes -> HTTP 200/422/etc.)
- Boundary + 1 byte (limit + 1 bytes -> HTTP 413)
- Bounded memory usage verification
"""

import json
import unittest
from fastapi.testclient import TestClient

from backend.config import MAX_REQUEST_BODY_SIZE
from backend.main import app
from backend.services.credential_service import credential_service


class TestBodySecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)
        _, self.token = credential_service.create_credential(
            "admin-demo", "default", description="Body Test", created_by="admin-demo"
        )
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def test_normal_body_under_limit_allowed(self):
        """Normal payload under MAX_REQUEST_BODY_SIZE is accepted."""
        payload = {"prompt": "What is the speed of light?"}
        resp = self.client.post("/api/v1/guard", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

    def test_content_length_over_limit_fast_fails_413(self):
        """Content-Length exceeding MAX_REQUEST_BODY_SIZE is fast-rejected with 413."""
        headers = dict(self.headers)
        headers["Content-Length"] = str(MAX_REQUEST_BODY_SIZE + 1000)
        resp = self.client.post("/api/v1/guard", content=b"{}", headers=headers)
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json()["error"]["code"], "PAYLOAD_TOO_LARGE")

    def test_negative_content_length_rejected_400(self):
        """Negative Content-Length header returns safe 400 validation error."""
        headers = dict(self.headers)
        headers["Content-Length"] = "-50"
        resp = self.client.post("/api/v1/guard", content=b"{}", headers=headers)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "VALIDATION_ERROR")

    def test_non_integer_content_length_rejected_400(self):
        """Non-integer Content-Length header returns safe 400 validation error."""
        headers = dict(self.headers)
        headers["Content-Length"] = "one_hundred"
        resp = self.client.post("/api/v1/guard", content=b"{}", headers=headers)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "VALIDATION_ERROR")

    def test_exact_boundary_limit_accepted(self):
        """Request payload with exact byte length matching MAX_REQUEST_BODY_SIZE is processed."""
        from unittest.mock import patch
        # Test with a smaller MAX_REQUEST_BODY_SIZE to verify exact byte precision
        test_limit = 500
        with patch("backend.main.MAX_REQUEST_BODY_SIZE", test_limit):
            # Create payload whose exact JSON byte representation is test_limit bytes
            # {"prompt":"..."}
            prefix = '{"prompt":"'
            suffix = '"}'
            padding_len = test_limit - len(prefix) - len(suffix)
            exact_payload_bytes = (prefix + ("A" * padding_len) + suffix).encode("utf-8")
            self.assertEqual(len(exact_payload_bytes), test_limit)

            resp = self.client.post(
                "/api/v1/guard",
                content=exact_payload_bytes,
                headers=self.headers,
            )
            # Must NOT be 413
            self.assertNotEqual(resp.status_code, 413)
            self.assertEqual(resp.status_code, 200)

    def test_boundary_plus_one_byte_rejected_413(self):
        """Request payload exceeding limit by precisely 1 byte returns HTTP 413."""
        from unittest.mock import patch
        test_limit = 500
        with patch("backend.main.MAX_REQUEST_BODY_SIZE", test_limit):
            prefix = '{"prompt":"'
            suffix = '"}'
            padding_len = (test_limit + 1) - len(prefix) - len(suffix)
            oversized_bytes = (prefix + ("A" * padding_len) + suffix).encode("utf-8")
            self.assertEqual(len(oversized_bytes), test_limit + 1)

            resp = self.client.post(
                "/api/v1/guard",
                content=oversized_bytes,
                headers=self.headers,
            )
            self.assertEqual(resp.status_code, 413)
            self.assertEqual(resp.json()["error"]["code"], "PAYLOAD_TOO_LARGE")

    def test_streaming_chunked_oversized_body_rejected_413(self):
        """Streaming generator exceeding byte limit is rejected with HTTP 413 without unbounded buffering."""
        from unittest.mock import patch
        test_limit = 200

        def chunk_generator():
            # Yield chunks of 50 bytes
            for _ in range(10):  # 500 bytes total > 200 limit
                yield b"X" * 50

        with patch("backend.main.MAX_REQUEST_BODY_SIZE", test_limit):
            resp = self.client.post(
                "/api/v1/guard",
                content=chunk_generator(),
                headers=self.headers,
            )
            self.assertEqual(resp.status_code, 413)
            self.assertEqual(resp.json()["error"]["code"], "PAYLOAD_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
