"""
AgentGuard v0.9 - Security Logging & Observability Tests
Validates that prompts, credentials, Authorization headers, and canary secrets
are strictly excluded or redacted from application logs and structured events.
"""

import io
import logging
import unittest

from backend.services.logging_service import (
    SecretRedactingFilter,
    configure_security_logging,
    format_security_log,
)
from backend.services.secret_service import secret_manager


class TestLoggingSecurity(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("agentguard.test_logger")
        self.logger.setLevel(logging.INFO)
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.addFilter(SecretRedactingFilter())
        self.logger.addHandler(self.handler)
        self.logger.propagate = False

    def tearDown(self):
        self.logger.removeHandler(self.handler)

    def test_bearer_credentials_redacted_from_log_records(self):
        """Bearer token strings in log messages are redacted to [REDACTED_CREDENTIAL]."""
        test_cred = "ag_0123456789abcdef_Abc123XyzSecretTokenLong"
        self.logger.info("Principal authenticated with credential %s", test_cred)
        output = self.log_stream.getvalue()
        self.assertNotIn("Abc123XyzSecretTokenLong", output)
        self.assertIn("[REDACTED_CREDENTIAL]", output)

    def test_canary_secret_redacted_from_log_records(self):
        """Canary secret BLUE-ORANGE-42 is never emitted to log output."""
        self.logger.warning("Canary detected: %s in evaluation", "BLUE-ORANGE-42")
        output = self.log_stream.getvalue()
        self.assertNotIn("BLUE-ORANGE-42", output)
        self.assertIn("[REDACTED_SECRET]", output)

    def test_authorization_header_redacted(self):
        """Authorization header tokens in messages are redacted."""
        self.logger.info("Header received: Authorization: Bearer secret_session_token_123456")
        output = self.log_stream.getvalue()
        self.assertNotIn("secret_session_token_123456", output)
        self.assertIn("[REDACTED_TOKEN]", output)

    def test_registered_secrets_redacted_from_logs(self):
        """Dynamic registered secrets are automatically scrubbed from logs."""
        custom_secret = "special_database_password_9999"
        secret_manager.register_sensitive_value(custom_secret)
        self.logger.error("DB connection error with %s", custom_secret)
        output = self.log_stream.getvalue()
        self.assertNotIn(custom_secret, output)
        self.assertIn("[REDACTED_SECRET]", output)

    def test_structured_log_formatter_excludes_prompts(self):
        """format_security_log produces only safe operational metadata without prompt text."""
        log_line = format_security_log(
            event_type="guard_evaluation",
            request_id="req-123",
            tenant_id="tenant-alpha",
            principal_id="user-demo",
            endpoint="/api/v1/guard",
            decision="BLOCK",
            error_code="INSTRUCTION_OVERRIDE",
            latency_ms=12.5,
            model="llama3.2:latest",
        )
        self.assertIn("request_id=req-123", log_line)
        self.assertIn("decision=BLOCK", log_line)
        self.assertIn("model=llama3.2:latest", log_line)
        self.assertNotIn("prompt=", log_line)
        self.assertNotIn("Ignore instructions", log_line)


if __name__ == "__main__":
    unittest.main()
