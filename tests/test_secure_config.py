"""
AgentGuard v0.9 - Secure Configuration Validation Tests
Validates deployment profiles (development, test, production), required controls,
rejection of unsafe defaults, key separation, and absence of secret leakage in errors.
"""

import unittest
from types import SimpleNamespace

from backend.services.config_validator import (
    ConfigurationError,
    validate_at_startup,
    validate_configuration,
)


class TestSecureConfig(unittest.TestCase):
    def _create_base_valid_prod_config(self):
        return SimpleNamespace(
            AGENTGUARD_ENV="production",
            AUTH_ENABLED=True,
            LEGACY_IDENTITY_ENABLED=False,
            BOOTSTRAP_ADMIN_ENABLED=False,
            ALLOWED_ORIGINS=["https://app.agentguard.internal", "https://admin.agentguard.internal"],
            TRUSTED_PROXIES=["10.0.0.1", "172.16.0.0/12"],
            AUDIT_INTEGRITY_KEY="very-strong-audit-hmac-key-2026-xyz",
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
        )

    def test_production_valid_configuration(self):
        """Valid production configuration passes validation."""
        cfg = self._create_base_valid_prod_config()
        res = validate_configuration(cfg)
        self.assertTrue(res.valid, f"Expected valid, got errors: {res.errors}")
        self.assertEqual(len(res.errors), 0)

    def test_production_auth_disabled_rejected(self):
        """Production mode strictly forbids auth being disabled."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUTH_ENABLED = False
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("AUTH_ENABLED" in err for err in res.errors))

    def test_production_legacy_identity_rejected(self):
        """Production mode strictly forbids legacy identity headers."""
        cfg = self._create_base_valid_prod_config()
        cfg.LEGACY_IDENTITY_ENABLED = True
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("LEGACY_IDENTITY_ENABLED" in err for err in res.errors))

    def test_production_wildcard_cors_rejected(self):
        """Production mode forbids wildcard CORS origins."""
        cfg = self._create_base_valid_prod_config()
        cfg.ALLOWED_ORIGINS = ["*"]
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("Wildcard CORS" in err for err in res.errors))

    def test_production_missing_audit_integrity_key_rejected(self):
        """Production mode strictly requires non-empty audit integrity key."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUDIT_INTEGRITY_KEY = None
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("AUDIT_INTEGRITY_KEY" in err for err in res.errors))

    def test_production_trivial_audit_key_rejected(self):
        """Trivial audit integrity keys are rejected in production."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUDIT_INTEGRITY_KEY = "password"
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)

    def test_key_separation_violation_rejected(self):
        """Audit integrity key cannot equal canary secret."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUDIT_INTEGRITY_KEY = "BLUE-ORANGE-42"
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("Cryptographic key separation" in err for err in res.errors))

    def test_database_path_traversal_rejected(self):
        """Database paths with directory traversal sequences are rejected."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUDIT_DB_PATH = "../../../etc/shadow.db"
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("directory traversal" in err for err in res.errors))

    def test_negative_numerical_limits_rejected(self):
        """Negative or zero numerical bounds are rejected."""
        cfg = self._create_base_valid_prod_config()
        cfg.MAX_PROMPT_LENGTH = -1
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        self.assertTrue(any("MAX_PROMPT_LENGTH" in err for err in res.errors))

    def test_development_mode_permits_relaxed_defaults(self):
        """Development mode permits relaxed local defaults."""
        cfg = SimpleNamespace(
            AGENTGUARD_ENV="development",
            AUTH_ENABLED=False,
            LEGACY_IDENTITY_ENABLED=True,
            BOOTSTRAP_ADMIN_ENABLED=True,
            ALLOWED_ORIGINS=["*"],
            TRUSTED_PROXIES=["127.0.0.1"],
            AUDIT_INTEGRITY_KEY=None,
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
        )
        res = validate_configuration(cfg)
        self.assertTrue(res.valid)
        self.assertGreater(len(res.warnings), 0)

    def test_configuration_errors_never_leak_secrets(self):
        """Configuration error messages mention parameter names, never secret values."""
        cfg = self._create_base_valid_prod_config()
        sensitive_pass = "super_secret_raw_token_xyz_99"
        cfg.AUDIT_INTEGRITY_KEY = sensitive_pass
        cfg.CANARY_SECRET = sensitive_pass  # triggers separation error
        res = validate_configuration(cfg)
        self.assertFalse(res.valid)
        for err in res.errors:
            self.assertNotIn(sensitive_pass, err)

    def test_startup_validation_fails_closed_in_production(self):
        """validate_at_startup raises ConfigurationError when production config is invalid."""
        cfg = self._create_base_valid_prod_config()
        cfg.AUTH_ENABLED = False
        with self.assertRaises(ConfigurationError):
            validate_at_startup(cfg)


if __name__ == "__main__":
    unittest.main()
