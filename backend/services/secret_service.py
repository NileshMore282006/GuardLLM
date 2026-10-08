"""
AgentGuard Secret & Key Management Service (v0.9)
Dedicated secret-management abstraction providing clean separation of sensitive material,
environment-based secret resolution for local/self-contained deployment, safe redaction,
and an extensible interface for future external KMS / Vault / HSM integrations.

SECURITY INVARIANTS:
1. Plaintext secrets and tokens are NEVER persisted or logged.
2. Secrets are NEVER included in error messages, exception traces, metrics labels, or audit logs.
3. Strict key separation: audit integrity keys, canary secrets, and credentials NEVER share material.
4. When a secret is required in production and missing, the system strictly FAILS CLOSED.
5. In v0.9, local environment injection is supported. External KMS/Vault/HSM is deliberately out of scope,
   but this abstraction provides the exact contract needed for pluggable KMS providers in v1.0.
"""

from abc import ABC, abstractmethod
import os
import re
from typing import Dict, List, Optional, Set


class SecretProvider(ABC):
    """
    Abstract interface for secret resolution.
    Allows swapping local environment resolution for AWS KMS, HashiCorp Vault,
    or hardware security modules (HSM) without modifying application security logic.
    """

    @abstractmethod
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Resolves a secret by logical name. Returns None if absent."""
        pass

    @abstractmethod
    def has_secret(self, secret_name: str) -> bool:
        """Checks if a secret is available."""
        pass


class EnvSecretProvider(SecretProvider):
    """
    Environment-variable based secret provider for local and self-contained deployment.
    """

    def __init__(self, prefix: str = "AGENTGUARD_"):
        self.prefix = prefix

    def get_secret(self, secret_name: str) -> Optional[str]:
        # Try direct name, then prefixed name
        val = os.environ.get(secret_name)
        if val is not None and val.strip():
            return val.strip()
        prefixed = f"{self.prefix}{secret_name}"
        val = os.environ.get(prefixed)
        if val is not None and val.strip():
            return val.strip()
        return None

    def has_secret(self, secret_name: str) -> bool:
        return self.get_secret(secret_name) is not None


class SecretManager:
    """
    Centralized secret manager enforcing secret redaction, key separation,
    and fail-closed access control.
    """

    def __init__(self, provider: Optional[SecretProvider] = None):
        self._provider = provider or EnvSecretProvider()
        self._registered_secret_values: Set[str] = set()
        # Pre-seed default and environment canary secret
        canary = os.environ.get("AGENTGUARD_CANARY_SECRET", "BLUE-ORANGE-42")
        self.register_sensitive_value("BLUE-ORANGE-42")
        self.register_sensitive_value(canary)

    def set_provider(self, provider: SecretProvider) -> None:
        """Swaps the underlying provider (e.g., during tests or future KMS integration)."""
        self._provider = provider

    def register_sensitive_value(self, value: Optional[str]) -> None:
        """Registers a known sensitive value for automated string redaction."""
        if value and len(value.strip()) >= 4:
            self._registered_secret_values.add(value.strip())

    def get_secret(self, secret_name: str, required: bool = False) -> Optional[str]:
        """
        Retrieves a secret. If required is True and secret is missing or empty,
        raises a ConfigurationError identifying the missing secret name (never its value).
        """
        val = self._provider.get_secret(secret_name)
        if not val or not val.strip():
            if required:
                from backend.services.config_validator import ConfigurationError
                raise ConfigurationError(
                    f"Required security secret '{secret_name}' is missing or empty."
                )
            return None
        secret_clean = val.strip()
        self.register_sensitive_value(secret_clean)
        return secret_clean

    def get_audit_integrity_key(self, required: bool = False) -> Optional[str]:
        """
        Retrieves the dedicated audit integrity HMAC key.
        Strict key separation: This key is used ONLY for audit log tamper-evidence.
        """
        return self.get_secret("AUDIT_INTEGRITY_KEY", required=required)

    def get_canary_secret(self) -> str:
        """
        Retrieves the protected canary secret used to verify LLM exfiltration resistance.
        """
        canary = self.get_secret("CANARY_SECRET", required=False) or "BLUE-ORANGE-42"
        self.register_sensitive_value(canary)
        return canary

    def redact_secrets(self, text: Optional[str]) -> str:
        """
        Sanitizes text by replacing any known registered secrets, Bearer tokens,
        and Authorization header values with [REDACTED_SECRET].
        """
        if not text:
            return ""

        redacted = str(text)

        # 1. Redact Bearer credentials matching AgentGuard token pattern (ag_<id>_<secret>)
        redacted = re.sub(
            r"ag_[a-f0-9]{16,64}_[a-zA-Z0-9_\-]{16,64}",
            "[REDACTED_CREDENTIAL]",
            redacted,
        )

        # 2. Redact Bearer header tokens generally
        redacted = re.sub(
            r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{12,}",
            "Bearer [REDACTED_TOKEN]",
            redacted,
        )

        # 3. Redact any registered secret values
        for sec in sorted(self._registered_secret_values, key=len, reverse=True):
            if sec and sec in redacted:
                redacted = redacted.replace(sec, "[REDACTED_SECRET]")

        return redacted

    def sanitize_exception(self, exc: Exception) -> str:
        """Returns a string representation of an exception with all secrets redacted."""
        return self.redact_secrets(str(exc))


# Global secret manager singleton
secret_manager = SecretManager()
