"""
AgentGuard Backend Configuration (v0.9)
Centralizes environment variables and operational settings for Backend v0.9.
Provides configuration for secure deployment profiles (development, test, production),
secrets management, cryptographic integrity, SQLite database hardening,
HTTP boundary protections, category rate limits, and resource exhaustion boundaries.
"""

import os

# Application version (v1.0 Release Candidate)
VERSION = os.environ.get("AGENTGUARD_VERSION", "1.0.0")

# Deployment environment profile: development | test | production
import sys
_is_test_env = "unittest" in sys.modules or any("unittest" in a or "pytest" in a or "test" in a for a in sys.argv)
AGENTGUARD_ENV = os.environ.get("AGENTGUARD_ENV", "test" if _is_test_env else "development").lower().strip()
IS_PRODUCTION = (AGENTGUARD_ENV == "production")
IS_TEST = (AGENTGUARD_ENV == "test")
IS_DEVELOPMENT = (AGENTGUARD_ENV == "development")

# Process model: single_process | multi_process
# Note: In-process rate limiting and tenant concurrency are process-local.
# Local production deployments strictly enforce single_process.
PROCESS_MODEL = os.environ.get("AGENTGUARD_PROCESS_MODEL", "single_process").lower().strip()
IS_SINGLE_PROCESS = (PROCESS_MODEL == "single_process")

# Security models
GUARD_MODEL = os.environ.get("AGENTGUARD_GUARD_MODEL", "llama3.2:latest")
TARGET_MODEL = os.environ.get("AGENTGUARD_TARGET_MODEL", "llama3.2:latest")

# Ollama service endpoint
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

# Inference timeout protections in seconds
GUARD_TIMEOUT_SECONDS = float(os.environ.get("AGENTGUARD_GUARD_TIMEOUT_SECONDS", "30.0"))
TARGET_TIMEOUT_SECONDS = float(os.environ.get("AGENTGUARD_TARGET_TIMEOUT_SECONDS", "60.0"))

# In-process rate limiting configuration
RATE_LIMIT_ENABLED = os.environ.get("AGENTGUARD_RATE_LIMIT_ENABLED", "true").lower() in ("true", "1", "yes")
RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_RATE_LIMIT_REQUESTS", "50000" if IS_TEST else "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("AGENTGUARD_RATE_LIMIT_WINDOW_SECONDS", "60"))

# Category and tenant rate limits (v0.9)
AUTH_FAILURE_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_AUTH_FAILURE_RATE_LIMIT_REQUESTS", "5000" if IS_TEST else "10"))
APPROVAL_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_APPROVAL_RATE_LIMIT_REQUESTS", "5000" if IS_TEST else "30"))
CREDENTIAL_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_CREDENTIAL_RATE_LIMIT_REQUESTS", "5000" if IS_TEST else "20"))
POLICY_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_POLICY_RATE_LIMIT_REQUESTS", "5000" if IS_TEST else "30"))
AUDIT_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_AUDIT_RATE_LIMIT_REQUESTS", "5000" if IS_TEST else "50"))
TENANT_RATE_LIMIT_REQUESTS = int(os.environ.get("AGENTGUARD_TENANT_RATE_LIMIT_REQUESTS", "10000" if IS_TEST else "200"))

# Concurrency control limits for local inference protection
MAX_CONCURRENT_GUARD_REQUESTS = int(os.environ.get("AGENTGUARD_MAX_CONCURRENT_GUARD_REQUESTS", "4"))
MAX_CONCURRENT_TARGET_REQUESTS = int(os.environ.get("AGENTGUARD_MAX_CONCURRENT_TARGET_REQUESTS", "2"))
MAX_TENANT_CONCURRENT_REQUESTS = int(os.environ.get("AGENTGUARD_MAX_TENANT_CONCURRENT_REQUESTS", "4"))

# Request size & resource boundaries
MAX_PROMPT_LENGTH = int(os.environ.get("AGENTGUARD_MAX_PROMPT_LENGTH", "20000"))
MAX_CHAT_MESSAGES = int(os.environ.get("AGENTGUARD_MAX_CHAT_MESSAGES", "50"))
MAX_TOTAL_CONVERSATION_LENGTH = int(os.environ.get("AGENTGUARD_MAX_TOTAL_CONVERSATION_LENGTH", "100000"))
MAX_REQUEST_BODY_SIZE = int(os.environ.get("AGENTGUARD_MAX_REQUEST_BODY_SIZE", "1048576"))  # 1 MB
MAX_HEADER_SIZE = int(os.environ.get("AGENTGUARD_MAX_HEADER_SIZE", "16384"))  # 16 KB
MAX_QUERY_PARAMS = int(os.environ.get("AGENTGUARD_MAX_QUERY_PARAMS", "50"))

# Tool security configuration
MAX_TOOL_CALLS_PER_REQUEST = int(os.environ.get("AGENTGUARD_MAX_TOOL_CALLS_PER_REQUEST", "3"))
ALLOW_HIGH_RISK_TOOLS = os.environ.get("AGENTGUARD_ALLOW_HIGH_RISK_TOOLS", "false").lower() in ("true", "1", "yes")
ALLOW_CRITICAL_TOOLS = os.environ.get("AGENTGUARD_ALLOW_CRITICAL_TOOLS", "false").lower() in ("true", "1", "yes")
MAX_TOOL_NAME_LENGTH = int(os.environ.get("AGENTGUARD_MAX_TOOL_NAME_LENGTH", "64"))
MAX_TOOL_ARGUMENT_LENGTH = int(os.environ.get("AGENTGUARD_MAX_TOOL_ARGUMENT_LENGTH", "5000"))

# Human Approval & High-Risk Action Control
APPROVAL_TTL_SECONDS = int(os.environ.get("AGENTGUARD_APPROVAL_TTL_SECONDS", "300"))
MEDIUM_RISK_REQUIRE_APPROVAL = os.environ.get("AGENTGUARD_MEDIUM_RISK_REQUIRE_APPROVAL", "false").lower() in ("true", "1", "yes")

# Authentication, Identity & Tenant Isolation
# In production, default to enabled if not explicitly provided
_auth_default = "true" if IS_PRODUCTION else "false"
AUTH_ENABLED = os.environ.get("AGENTGUARD_AUTH_ENABLED", _auth_default).lower() in ("true", "1", "yes")
LEGACY_IDENTITY_ENABLED = os.environ.get("AGENTGUARD_LEGACY_IDENTITY_ENABLED", "false").lower() in ("true", "1", "yes")
IDENTITY_ENABLED = os.environ.get("AGENTGUARD_IDENTITY_ENABLED", "false").lower() in ("true", "1", "yes")
DEFAULT_PRINCIPAL = os.environ.get("AGENTGUARD_DEFAULT_PRINCIPAL", "user-demo")
DEFAULT_TENANT = os.environ.get("AGENTGUARD_DEFAULT_TENANT", "default")
CREDENTIAL_DB_PATH = os.environ.get("AGENTGUARD_CREDENTIAL_DB_PATH", os.path.join("data", "agentguard_identity.db"))
CREDENTIAL_HASH_ALGORITHM = os.environ.get("AGENTGUARD_CREDENTIAL_HASH_ALGORITHM", "argon2id")
CREDENTIAL_EXPIRATION_SECONDS = int(os.environ.get("AGENTGUARD_CREDENTIAL_EXPIRATION_SECONDS", "2592000"))
BOOTSTRAP_ADMIN_ENABLED = os.environ.get("AGENTGUARD_BOOTSTRAP_ADMIN_ENABLED", "false").lower() in ("true", "1", "yes")
BOOTSTRAP_ADMIN_PRINCIPAL = os.environ.get("AGENTGUARD_BOOTSTRAP_ADMIN_PRINCIPAL", "bootstrap-admin")

# Global admin capability: disabled by default in production
_admin_default = "false" if IS_PRODUCTION else "true"
GLOBAL_ADMIN_ENABLED = os.environ.get("AGENTGUARD_GLOBAL_ADMIN_ENABLED", _admin_default).lower() in ("true", "1", "yes")

# Persistent Security Audit Log & Cryptographic Integrity (v0.9)
AUDIT_DB_PATH = os.environ.get("AGENTGUARD_AUDIT_DB_PATH", os.path.join("data", "agentguard_audit.db"))
AUDIT_ENABLED = os.environ.get("AGENTGUARD_AUDIT_ENABLED", "true").lower() in ("true", "1", "yes")
AUDIT_CHAIN_ENABLED = os.environ.get("AGENTGUARD_AUDIT_CHAIN_ENABLED", "true").lower() in ("true", "1", "yes")
AUDIT_RETENTION_LIMIT = int(os.environ.get("AGENTGUARD_AUDIT_RETENTION_LIMIT", "100000"))
MAX_AUDIT_PAGE_SIZE = int(os.environ.get("AGENTGUARD_MAX_AUDIT_PAGE_SIZE", "100"))
AUDIT_INTEGRITY_KEY = os.environ.get("AGENTGUARD_AUDIT_INTEGRITY_KEY")
AUDIT_KEY_ALGORITHM = os.environ.get(
    "AGENTGUARD_AUDIT_KEY_ALGORITHM",
    "hmac-sha256" if AUDIT_INTEGRITY_KEY else "sha256",
)

# SQLite Database Hardening (v0.9)
SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("AGENTGUARD_SQLITE_BUSY_TIMEOUT_MS", "5000"))
SQLITE_WAL_MODE = os.environ.get("AGENTGUARD_SQLITE_WAL_MODE", "true").lower() in ("true", "1", "yes")

# Protected canary token to prevent secret exfiltration
CANARY_SECRET = os.environ.get("AGENTGUARD_CANARY_SECRET", "BLUE-ORANGE-42")

# Trusted Proxy Configuration (v0.9)
DEFAULT_TRUSTED_PROXIES = "127.0.0.1,::1"
TRUSTED_PROXIES = [
    proxy.strip()
    for proxy in os.environ.get("AGENTGUARD_TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES).split(",")
    if proxy.strip()
]

# CORS origins
DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:3000,"
    "http://localhost:5173,"
    "http://localhost:8000,"
    "http://127.0.0.1:3000,"
    "http://127.0.0.1:5173,"
    "http://127.0.0.1:8000"
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("AGENTGUARD_ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS).split(",")
    if origin.strip()
]

# Reversible Data Loss Prevention (DLP) & PII Tokenizer Configuration
DLP_ENABLED = os.environ.get("AGENTGUARD_DLP_ENABLED", "true").lower() in ("true", "1", "yes")
DLP_REVERSIBLE = os.environ.get("AGENTGUARD_DLP_REVERSIBLE", "true").lower() in ("true", "1", "yes")
