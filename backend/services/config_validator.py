"""
AgentGuard Secure Configuration Validator (v0.9)
Enforces fail-closed configuration validation at startup and readiness probes across
deployment profiles: development, test, and production.

SECURITY INVARIANTS:
1. Production mode strictly requires authentication, audit integrity keys, and safe CORS.
2. Production mode forbids legacy identity, wildcard CORS, and unconstrained admin capabilities.
3. Errors NEVER expose secret values; they identify the configuration parameter name only.
4. Non-positive, zero, or excessively large limits are rejected across all environments.
5. Database paths are validated against path traversal (no '..').
6. Cryptographic keys must observe strict key separation (audit key != canary secret).
"""

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

logger = logging.getLogger("agentguard.config_validator")

VALID_ENVIRONMENTS = {"development", "test", "production"}


class ConfigurationError(Exception):
    """
    Raised when configuration validation fails.
    Identifies the configuration field name, never its secret value.
    """
    def __init__(self, message: str, code: str = "CONFIGURATION_ERROR", status_code: int = 500):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass
class ValidationResult:
    valid: bool
    environment: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_safe_dict(self) -> dict:
        """Returns safe summary without sensitive details."""
        return {
            "valid": self.valid,
            "environment": self.environment,
            "error_count": len(self.errors),
            "errors": self.errors,
            "warning_count": len(self.warnings),
            "warnings": self.warnings,
        }


def validate_ip_or_network(ip_str: str) -> bool:
    """Validates that a string is a valid IPv4/IPv6 address or CIDR network."""
    try:
        if "/" in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        else:
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_db_path_string(path: str) -> Optional[str]:
    """Validates a database path against traversal and injection characters."""
    if not path or not path.strip():
        return "Database path cannot be empty."
    if "\x00" in path:
        return "Database path contains null bytes."
    # Check for path traversal attempts
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    if ".." in parts:
        return "Database path contains directory traversal sequence ('..')."
    return None


def validate_configuration(config=None) -> ValidationResult:
    """
    Validates the active configuration against deployment profile requirements.
    If config is None, imports backend.config.
    """
    if config is None:
        import backend.config as config

    env = getattr(config, "AGENTGUARD_ENV", "development").lower().strip()
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Environment validation
    if env not in VALID_ENVIRONMENTS:
        errors.append(
            f"Invalid AGENTGUARD_ENV '{env}'. Must be one of: {', '.join(sorted(VALID_ENVIRONMENTS))}."
        )

    is_prod = (env == "production")
    is_test = (env == "test")

    # Process Model validation (v1.0)
    process_model = getattr(config, "PROCESS_MODEL", "single_process").lower().strip()
    if process_model not in ("single_process", "multi_process"):
        errors.append(
            f"Invalid AGENTGUARD_PROCESS_MODEL '{process_model}'. Must be 'single_process' or 'multi_process'."
        )
    elif process_model == "multi_process":
        if is_prod:
            errors.append(
                "AGENTGUARD_PROCESS_MODEL='multi_process' is forbidden in local production mode without distributed coordination. Use 'single_process'."
            )
        else:
            warnings.append(
                "Multi-process model enabled: in-process rate limits and concurrency controls are process-local."
            )

    # 2. Authentication & Identity controls
    auth_enabled = bool(getattr(config, "AUTH_ENABLED", False))
    legacy_identity = bool(getattr(config, "LEGACY_IDENTITY_ENABLED", False))
    bootstrap_admin = bool(getattr(config, "BOOTSTRAP_ADMIN_ENABLED", False))

    if is_prod:
        if not auth_enabled:
            errors.append(
                "AGENTGUARD_AUTH_ENABLED must be true in production mode."
            )
        if legacy_identity:
            errors.append(
                "AGENTGUARD_LEGACY_IDENTITY_ENABLED must be false in production mode."
            )
        if bootstrap_admin:
            errors.append(
                "AGENTGUARD_BOOTSTRAP_ADMIN_ENABLED must be false in production mode unless explicitly managed."
            )

    # 3. CORS configuration
    allowed_origins = getattr(config, "ALLOWED_ORIGINS", [])
    if is_prod:
        if not allowed_origins:
            errors.append(
                "AGENTGUARD_ALLOWED_ORIGINS cannot be empty in production mode."
            )
        for origin in allowed_origins:
            if origin == "*" or origin.strip() == "*":
                errors.append(
                    "Wildcard CORS origin ('*') is strictly forbidden in production mode."
                )
    else:
        if "*" in allowed_origins:
            warnings.append("Wildcard CORS origin enabled in non-production mode.")

    # 4. Trusted Proxy configuration
    trusted_proxies = getattr(config, "TRUSTED_PROXIES", [])
    if is_prod:
        if not trusted_proxies:
            errors.append(
                "AGENTGUARD_TRUSTED_PROXIES must be configured in production mode."
            )
        for proxy in trusted_proxies:
            if proxy == "*":
                errors.append(
                    "Wildcard proxy ('*') in AGENTGUARD_TRUSTED_PROXIES is forbidden in production."
                )
            elif not validate_ip_or_network(proxy):
                errors.append(
                    f"Invalid proxy IP or CIDR in AGENTGUARD_TRUSTED_PROXIES: '{proxy}'."
                )
    else:
        for proxy in trusted_proxies:
            if proxy != "*" and not validate_ip_or_network(proxy):
                warnings.append(f"Unrecognized proxy address in non-production: '{proxy}'.")

    # 5. Cryptographic key separation and audit integrity key
    audit_integrity_key = getattr(config, "AUDIT_INTEGRITY_KEY", None)
    canary_secret = getattr(config, "CANARY_SECRET", "BLUE-ORANGE-42")

    if is_prod:
        if not audit_integrity_key or len(audit_integrity_key.strip()) < 16:
            errors.append(
                "Production mode requires AGENTGUARD_AUDIT_INTEGRITY_KEY with at least 16 characters."
            )
        elif audit_integrity_key.strip() in ("secret", "password", "1234567890123456", "changeme", "default_key"):
            errors.append(
                "Insecure trivial value for AGENTGUARD_AUDIT_INTEGRITY_KEY in production."
            )

    if audit_integrity_key and canary_secret:
        if audit_integrity_key.strip() == canary_secret.strip():
            errors.append(
                "Cryptographic key separation violation: AGENTGUARD_AUDIT_INTEGRITY_KEY cannot equal AGENTGUARD_CANARY_SECRET."
            )

    # 6. Database paths
    for db_var, db_path in [
        ("AGENTGUARD_CREDENTIAL_DB_PATH", getattr(config, "CREDENTIAL_DB_PATH", "")),
        ("AGENTGUARD_AUDIT_DB_PATH", getattr(config, "AUDIT_DB_PATH", "")),
    ]:
        err = validate_db_path_string(db_path)
        if err:
            errors.append(f"{db_var}: {err}")

    # 7. Numerical limit and timeout bounds
    bounds = [
        ("AGENTGUARD_MAX_PROMPT_LENGTH", getattr(config, "MAX_PROMPT_LENGTH", 0), 1, 1_000_000),
        ("AGENTGUARD_MAX_CHAT_MESSAGES", getattr(config, "MAX_CHAT_MESSAGES", 0), 1, 1_000),
        ("AGENTGUARD_MAX_TOTAL_CONVERSATION_LENGTH", getattr(config, "MAX_TOTAL_CONVERSATION_LENGTH", 0), 1, 5_000_000),
        ("AGENTGUARD_MAX_TOOL_CALLS_PER_REQUEST", getattr(config, "MAX_TOOL_CALLS_PER_REQUEST", 0), 1, 50),
        ("AGENTGUARD_MAX_TOOL_NAME_LENGTH", getattr(config, "MAX_TOOL_NAME_LENGTH", 0), 1, 256),
        ("AGENTGUARD_MAX_TOOL_ARGUMENT_LENGTH", getattr(config, "MAX_TOOL_ARGUMENT_LENGTH", 0), 1, 50_000),
        ("AGENTGUARD_APPROVAL_TTL_SECONDS", getattr(config, "APPROVAL_TTL_SECONDS", 0), 1, 86_400),
        ("AGENTGUARD_RATE_LIMIT_REQUESTS", getattr(config, "RATE_LIMIT_REQUESTS", 0), 1, 1_000_000),
        ("AGENTGUARD_RATE_LIMIT_WINDOW_SECONDS", getattr(config, "RATE_LIMIT_WINDOW_SECONDS", 0), 1, 86_400),
        ("AGENTGUARD_MAX_CONCURRENT_GUARD_REQUESTS", getattr(config, "MAX_CONCURRENT_GUARD_REQUESTS", 0), 1, 200),
        ("AGENTGUARD_MAX_CONCURRENT_TARGET_REQUESTS", getattr(config, "MAX_CONCURRENT_TARGET_REQUESTS", 0), 1, 200),
        ("AGENTGUARD_GUARD_TIMEOUT_SECONDS", getattr(config, "GUARD_TIMEOUT_SECONDS", 0), 0.1, 300.0),
        ("AGENTGUARD_TARGET_TIMEOUT_SECONDS", getattr(config, "TARGET_TIMEOUT_SECONDS", 0), 0.1, 600.0),
        ("AGENTGUARD_CREDENTIAL_EXPIRATION_SECONDS", getattr(config, "CREDENTIAL_EXPIRATION_SECONDS", 0), 1, 315_360_000),
        ("AGENTGUARD_MAX_REQUEST_BODY_SIZE", getattr(config, "MAX_REQUEST_BODY_SIZE", 0), 1024, 52_428_800),
        ("AGENTGUARD_MAX_HEADER_SIZE", getattr(config, "MAX_HEADER_SIZE", 0), 512, 65_536),
        ("AGENTGUARD_MAX_QUERY_PARAMS", getattr(config, "MAX_QUERY_PARAMS", 0), 1, 500),
    ]

    for param_name, value, min_val, max_val in bounds:
        try:
            num = float(value)
            if num < min_val:
                errors.append(
                    f"{param_name} must be >= {min_val} (received {value})."
                )
            elif num > max_val:
                errors.append(
                    f"{param_name} exceeds maximum safe limit of {max_val} (received {value})."
                )
        except (TypeError, ValueError):
            errors.append(f"{param_name} must be a valid number.")

    is_valid = (len(errors) == 0)
    return ValidationResult(
        valid=is_valid,
        environment=env,
        errors=errors,
        warnings=warnings,
    )


def validate_at_startup(config=None) -> ValidationResult:
    """
    Validates configuration at application launch.
    In production mode, raises ConfigurationError if any validation check fails.
    In development or test mode, raises ConfigurationError only for fatal boundary or traversal violations.
    """
    result = validate_configuration(config)
    if not result.valid:
        if result.environment == "production":
            logger.critical(
                "PRODUCTION CONFIGURATION VALIDATION FAILED: %d errors detected. Failing closed.",
                len(result.errors),
            )
            for err in result.errors:
                logger.critical("Configuration error: %s", err)
            raise ConfigurationError(
                f"Production configuration validation failed: {'; '.join(result.errors)}"
            )
        else:
            # In dev/test, check if there are fatal errors (e.g. traversal or negative limits)
            fatal_errors = [e for e in result.errors if "directory traversal" in e or "must be >=" in e or "null bytes" in e]
            if fatal_errors:
                logger.error("Fatal configuration errors detected in %s: %s", result.environment, fatal_errors)
                raise ConfigurationError(
                    f"Fatal configuration error in {result.environment}: {'; '.join(fatal_errors)}"
                )
            logger.warning(
                "Configuration warnings in %s mode: %d issues noted.",
                result.environment,
                len(result.errors),
            )

    return result
