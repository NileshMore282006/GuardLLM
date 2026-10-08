"""
AgentGuard Security Logging & Observability Layer (v0.9)
Provides structured, secret-redacting logging filters and safe telemetry formatting.

SECURITY INVARIANTS:
1. Full user prompts are NEVER logged.
2. Authorization headers and Bearer tokens are NEVER logged.
3. API credential secrets and Argon2 hashes are NEVER logged.
4. Canary secrets (e.g. BLUE-ORANGE-42) are NEVER logged.
5. Audit integrity HMAC keys are NEVER logged.
6. Exception traces are scrubbed of secrets before output.
7. Logs contain only safe operational metadata:
   request_id, tenant_id, principal_id, endpoint, decision, error_code, latency_ms,
   model, tool_name, approval_id, policy_version.
"""

import logging
import re
from typing import Any, Dict, Optional

from backend.services.secret_service import secret_manager


class SecretRedactingFilter(logging.Filter):
    """
    Logging filter that redacts secrets, credentials, tokens, and canary codes
    from all log messages and argument tuples.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # 1. Redact message string if string
            if isinstance(record.msg, str):
                record.msg = secret_manager.redact_secrets(record.msg)

            # 2. Redact arguments if present
            if record.args:
                if isinstance(record.args, dict):
                    redacted_args = {}
                    for k, v in record.args.items():
                        redacted_args[k] = secret_manager.redact_secrets(str(v)) if isinstance(v, str) else v
                    record.args = redacted_args
                elif isinstance(record.args, tuple):
                    redacted_args = []
                    for arg in record.args:
                        redacted_args.append(secret_manager.redact_secrets(str(arg)) if isinstance(arg, str) else arg)
                    record.args = tuple(redacted_args)

            # 3. Redact exception text if present
            if record.exc_text:
                record.exc_text = secret_manager.redact_secrets(record.exc_text)

        except Exception:
            # Never crash application due to logging filter
            pass

        return True


def format_security_log(
    event_type: str,
    request_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    principal_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    decision: Optional[str] = None,
    error_code: Optional[str] = None,
    latency_ms: Optional[float] = None,
    model: Optional[str] = None,
    tool_name: Optional[str] = None,
    approval_id: Optional[str] = None,
    policy_version: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Constructs a deterministic, safe structured key-value log line.
    Excludes prompts, secrets, and raw bodies.
    """
    parts = [f"event={event_type}"]
    if request_id:
        parts.append(f"request_id={request_id}")
    if tenant_id:
        parts.append(f"tenant={tenant_id}")
    if principal_id:
        parts.append(f"principal={principal_id}")
    if endpoint:
        parts.append(f"endpoint={endpoint}")
    if decision:
        parts.append(f"decision={decision}")
    if error_code:
        parts.append(f"error_code={error_code}")
    if latency_ms is not None:
        parts.append(f"latency_ms={latency_ms:.1f}")
    if model:
        parts.append(f"model={model}")
    if tool_name:
        parts.append(f"tool={tool_name}")
    if approval_id:
        parts.append(f"approval_id={approval_id}")
    if policy_version is not None:
        parts.append(f"policy_version={policy_version}")

    if extra:
        for k, v in sorted(extra.items()):
            safe_v = secret_manager.redact_secrets(str(v))[:100]
            parts.append(f"{k}={safe_v}")

    return " ".join(parts)


def configure_security_logging():
    """
    Installs SecretRedactingFilter on the agentguard logger and root logger handlers.
    """
    redacting_filter = SecretRedactingFilter()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(redacting_filter)

    ag_logger = logging.getLogger("agentguard")
    ag_logger.addFilter(redacting_filter)
    for handler in ag_logger.handlers:
        handler.addFilter(redacting_filter)
