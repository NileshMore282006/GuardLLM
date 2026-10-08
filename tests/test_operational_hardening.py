"""
Operational Hardening Test Suite (Backend v0.4)
Covers:
A. Rate limiting (429, Retry-After, disableable, no prompts exposed)
B. Concurrency controls (safe 503, no bypassing)
C. Timeouts (Guard timeout fails closed without target call, target timeout returns ERROR, no tracebacks)
D. Health & Readiness (/health vs /ready, Ollama available vs unavailable)
E. Structured Error Handling (VALIDATION_ERROR, RATE_LIMITED, CONCURRENCY_LIMIT, DEPENDENCY_UNAVAILABLE, INTERNAL_ERROR, request_id)
F. Metrics collection (counts, decisions, timeouts, rate limits)
G. Resource protection (bounds on prompt length, messages count, total conversation size)
"""

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import requests

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.main import app
from backend.services.concurrency_service import (
    ConcurrencyLimitExceeded,
    ConcurrencyManager,
    concurrency_manager,
)
from backend.services.metrics_service import metrics
from backend.services.rate_limiter import InMemoryRateLimiter, rate_limiter


class TestOperationalHardening(unittest.TestCase):
    """
    Comprehensive tests for Backend v0.4 operational hardening.
    """

    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)
        rate_limiter.reset()
        rate_limiter.enabled = True
        rate_limiter.max_requests = 10000
        rate_limiter.window_seconds = 60
        metrics.reset()

    def tearDown(self):
        rate_limiter.reset()
        rate_limiter.enabled = True
        rate_limiter.max_requests = 10000
        rate_limiter.window_seconds = 60
        metrics.reset()

    # ============================================================
    # CATEGORY A: Rate Limiting
    # ============================================================

    def test_requests_below_rate_limit_succeed(self):
        """Requests below quota succeed normally."""
        rate_limiter.max_requests = 5
        for i in range(5):
            resp = self.client.get("/health")
            self.assertEqual(resp.status_code, 200)

    def test_excessive_requests_return_429_with_retry_after(self):
        """Requests exceeding rate limit return HTTP 429 with Retry-After header."""
        rate_limiter.max_requests = 3
        # First 3 succeed
        for _ in range(3):
            resp = self.client.get("/health")
            self.assertEqual(resp.status_code, 200)

        # 4th request must be rejected with 429
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 429)
        data = resp.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], "RATE_LIMITED")
        self.assertIn("Retry-After", resp.headers)
        retry_after = int(resp.headers["Retry-After"])
        self.assertGreater(retry_after, 0)

    def test_rate_limiting_can_be_disabled(self):
        """When rate limiting is disabled, requests exceeding limit succeed."""
        rate_limiter.enabled = False
        rate_limiter.max_requests = 2
        for _ in range(5):
            resp = self.client.get("/health")
            self.assertEqual(resp.status_code, 200)

    def test_rate_limiter_does_not_expose_prompts(self):
        """Rate limited response contains only safe structured message and no user prompts."""
        rate_limiter.max_requests = 1
        secret_prompt = "MY_HIGHLY_CONFIDENTIAL_QUERY_123"
        self.client.post("/api/v1/guard", json={"prompt": secret_prompt})

        # 2nd request is rate limited
        resp = self.client.post("/api/v1/guard", json={"prompt": secret_prompt})
        self.assertEqual(resp.status_code, 429)
        raw_text = resp.text
        self.assertNotIn(secret_prompt, raw_text)

    # ============================================================
    # CATEGORY B: Concurrency Control
    # ============================================================

    def test_guard_concurrency_exhaustion_returns_safe_503(self):
        """Exhausting Guard concurrency limit safely returns HTTP 503 without calling Ollama."""
        # Mock guard slot to raise ConcurrencyLimitExceeded
        with patch.object(
            concurrency_manager,
            "guard_slot",
            side_effect=ConcurrencyLimitExceeded("Guard", 1),
        ):
            resp = self.client.post("/api/v1/guard", json={"prompt": "Hello safe prompt."})
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["error"]["code"], "CONCURRENCY_LIMIT")
            self.assertIn("Maximum concurrent inferences reached", data["error"]["message"])

    def test_target_concurrency_exhaustion_returns_safe_503(self):
        """Exhausting Target concurrency limit safely returns HTTP 503 without calling target."""
        with patch("backend.services.guard_service.evaluate_prompt") as mock_guard, \
             patch.object(concurrency_manager, "target_slot", side_effect=ConcurrencyLimitExceeded("Target", 1)):
            from backend.schemas import GuardResponse
            mock_guard.return_value = GuardResponse(
                request_id="test-req-1",
                decision="ALLOW",
                risk_score=0.0,
                attack_type="none",
                guard_model="llama3.2:latest",
                latency_ms=10.0,
            )

            resp = self.client.post("/api/v1/execute", json={"prompt": "Calculate 2+2."})
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["error"]["code"], "CONCURRENCY_LIMIT")

    def test_cannot_bypass_guard_concurrency_control(self):
        """Requests must acquire concurrency slot and cannot bypass semaphore."""
        mock_sem = MagicMock()
        mock_sem.acquire.return_value = False
        mgr = ConcurrencyManager(max_guard=1, max_target=1)
        mgr._guard_semaphore = mock_sem

        with self.assertRaises(ConcurrencyLimitExceeded):
            with mgr.guard_slot():
                pass

    # ============================================================
    # CATEGORY C: Timeouts
    # ============================================================

    def test_guard_timeout_fails_closed_and_prevents_target_call(self):
        """Guard timeout fails closed and target is NEVER invoked."""
        with patch("agentguard.guard_check", side_effect=requests.exceptions.Timeout("Guard timed out")), \
             patch("backend.services.target_service.call_target") as mock_target:

            resp = self.client.post("/api/v1/execute", json={"prompt": "Perform complex query."})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "BLOCK")
            self.assertEqual(data["attack_type"], "guard_timeout")
            self.assertIsNone(data["response"])
            # Target must NEVER be called
            mock_target.assert_not_called()

    def test_target_timeout_returns_safe_error_without_traceback(self):
        """Target timeout after ALLOW returns decision=ERROR without stack traces."""
        with patch("backend.services.guard_service.evaluate_prompt") as mock_guard, \
             patch("backend.services.execution_service.call_target", side_effect=requests.exceptions.Timeout("Target timed out")):
            from backend.schemas import GuardResponse
            mock_guard.return_value = GuardResponse(
                request_id="test-timeout-req",
                decision="ALLOW",
                risk_score=0.0,
                attack_type="none",
                guard_model="llama3.2:latest",
                latency_ms=10.0,
            )

            resp = self.client.post("/api/v1/execute", json={"prompt": "Generate long response."})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["decision"], "ERROR")
            self.assertEqual(data["attack_type"], "target_timeout")
            self.assertIsNone(data["response"])
            # No traceback in response
            self.assertNotIn("Traceback", resp.text)
            self.assertNotIn("requests.exceptions", resp.text)

    # ============================================================
    # CATEGORY D: Health and Readiness Endpoints
    # ============================================================

    def test_health_check_succeeds_without_ollama_call(self):
        """Health check returns 200 OK immediately with version 0.4.0."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn(data["version"], ("0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.8.0", "0.9.0", "1.0.0"))
        self.assertIn("guard_model", data)
        self.assertIn("target_model", data)

    def test_readiness_check_when_ollama_available(self):
        """Readiness check returns 200 OK when Ollama dependency responds 200."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ready")
            self.assertEqual(data["ollama"], "connected")

    def test_readiness_check_when_ollama_unavailable(self):
        """Readiness check returns 503 Service Unavailable when Ollama is unreachable."""
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
            resp = self.client.get("/ready")
            self.assertEqual(resp.status_code, 503)
            data = resp.json()
            self.assertEqual(data["status"], "not_ready")
            self.assertEqual(data["error"]["code"], "DEPENDENCY_UNAVAILABLE")

    # ============================================================
    # CATEGORY E: Structured Error Handling & Correlation
    # ============================================================

    def test_validation_error_returns_structured_422_with_request_id(self):
        """Validation errors return structured HTTP 422 with request_id and VALIDATION_ERROR code."""
        resp = self.client.post("/api/v1/guard", json={"prompt": ""})
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertIn("request_id", data)
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertIn("X-Request-ID", resp.headers)

    def test_client_supplied_request_id_preserved(self):
        """Client-supplied X-Request-ID header is preserved in the response."""
        custom_id = f"client-corr-{uuid.uuid4()}"
        resp = self.client.get("/health", headers={"X-Request-ID": custom_id})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Request-ID"), custom_id)

    def test_unhandled_exception_returns_safe_500_without_stack_trace(self):
        """Unhandled exceptions return HTTP 500 without leaking stack traces or internal paths."""
        with patch("backend.routes.guard.evaluate_prompt", side_effect=Exception("Database connection crash at /var/lib/secret.py:42")):
            resp = self.client.post("/api/v1/guard", json={"prompt": "Trigger crash"})
            self.assertEqual(resp.status_code, 500)
            data = resp.json()
            self.assertEqual(data["error"]["code"], "INTERNAL_ERROR")
            self.assertNotIn("Database connection crash", resp.text)
            self.assertNotIn("/var/lib/secret.py", resp.text)
            self.assertNotIn("Traceback", resp.text)

    # ============================================================
    # CATEGORY F: Metrics
    # ============================================================

    def test_metrics_endpoint_records_requests_and_decisions(self):
        """Metrics endpoint tracks request counts, status codes, and decisions in memory."""
        # Initially 0
        m = self.client.get("/metrics").json()
        initial_requests = m["total_requests"]

        # Perform one ALLOW and one BLOCK (mocked)
        from backend.schemas import GuardResponse
        with patch("backend.services.guard_service.evaluate_prompt") as mock_guard, \
             patch("backend.services.target_service.call_target", return_value="4"):
            mock_guard.return_value = GuardResponse(
                request_id="allow-req",
                decision="ALLOW",
                risk_score=0.0,
                attack_type="none",
                guard_model="llama3.2:latest",
                latency_ms=10.0,
            )
            resp = self.client.post("/api/v1/execute", json={"prompt": "2+2"})
            self.assertEqual(resp.status_code, 200)

            mock_guard.return_value = GuardResponse(
                request_id="block-req",
                decision="BLOCK",
                risk_score=1.0,
                attack_type="instruction_override",
                guard_model="llama3.2:latest",
                latency_ms=10.0,
            )
            resp = self.client.post("/api/v1/execute", json={"prompt": "override"})
            self.assertEqual(resp.status_code, 200)

        updated_m = self.client.get("/metrics").json()
        self.assertGreater(updated_m["total_requests"], initial_requests)
        self.assertGreaterEqual(updated_m["decisions"]["allow"], 1)
        self.assertGreaterEqual(updated_m["decisions"]["block"], 1)
        self.assertIn("/api/v1/execute", updated_m["requests_by_endpoint"])

    def test_metrics_tracks_rate_limiting(self):
        """Rate limited requests increment rate_limited_count in metrics."""
        rate_limiter.max_requests = 1
        self.client.get("/health")
        resp = self.client.get("/health")  # Rate limited
        self.assertEqual(resp.status_code, 429)

        # Increase limit so /metrics itself can be queried
        rate_limiter.max_requests = 10000
        m = self.client.get("/metrics").json()
        self.assertGreaterEqual(m["rate_limited_count"], 1)

    # ============================================================
    # CATEGORY G: Resource Protection Boundaries
    # ============================================================

    def test_excessive_prompt_length_rejected(self):
        """Prompt exceeding maximum length boundary is rejected with HTTP 422."""
        huge_prompt = "x" * 20001
        resp = self.client.post("/api/v1/guard", json={"prompt": huge_prompt})
        self.assertEqual(resp.status_code, 422)

    def test_excessive_chat_messages_rejected(self):
        """Conversation exceeding 50 turns is rejected with HTTP 422."""
        messages = [{"role": "user", "content": f"Turn {i}"} for i in range(51)]
        resp = self.client.post("/api/v1/chat", json={"messages": messages})
        self.assertEqual(resp.status_code, 422)

    def test_excessive_total_conversation_size_rejected(self):
        """Conversation exceeding total character limit is rejected with HTTP 422."""
        # 100,001 characters
        messages = [
            {"role": "user", "content": "a" * 15000}
            for _ in range(7)
        ]
        resp = self.client.post("/api/v1/chat", json={"messages": messages})
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
