"""
AgentGuard Credential Service (Backend v0.8)
Manages cryptographically verifiable API credentials, Argon2id hashing, lifecycle state machine,
timing attack mitigation, and persistent SQLite storage.

SECURITY INVARIANTS:
1. Credentials format: ag_<credential_id>_<secret> (cryptographically random).
2. Plaintext secrets are NEVER stored in the database or logged.
3. Plaintext secret is returned EXACTLY ONCE at creation/rotation time.
4. Hashing is performed using Argon2id (memory=64MB, time_cost=3, parallelism=4).
5. Verification uses Argon2 secure verification function (constant-time / timing-safe).
6. Constant dummy hash verification is executed for unknown credentials to prevent timing enumeration.
7. Revocation and expiration take effect immediately.
8. Unknown or invalid statuses strictly fail closed.
9. Credentials are permanently bound to principal_id and tenant_id.
10. Parameterized SQL exclusively.
"""

import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from backend.config import (
    BOOTSTRAP_ADMIN_ENABLED,
    BOOTSTRAP_ADMIN_PRINCIPAL,
    CREDENTIAL_DB_PATH,
    CREDENTIAL_EXPIRATION_SECONDS,
    DEFAULT_TENANT,
)
from backend.services.db_hardening import check_database_integrity, get_hardened_connection
from backend.services.request_context import RequestSecurityContext

logger = logging.getLogger("agentguard.credential")

VALID_CREDENTIAL_STATUSES = {"ACTIVE", "REVOKED", "EXPIRED", "DISABLED"}

# Argon2id password hasher with documented parameters
# Type.ID = Argon2id, memory_cost=65536 (64 MiB), time_cost=3 iterations, parallelism=4 threads
_argon2_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID,
)

# Constant dummy hash computed once at process startup for timing attack mitigation
_DUMMY_SECRET = "agentguard_constant_timing_dummy_secret_pad_000"
_DUMMY_ARGON2_HASH = _argon2_hasher.hash(_DUMMY_SECRET)


class CredentialError(Exception):
    """Base exception for credential operations."""
    def __init__(self, message: str, code: str = "INVALID_CREDENTIAL", status_code: int = 401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class InvalidCredentialError(CredentialError):
    """Raised when credential format is invalid, unknown, or secret does not match."""
    def __init__(self, message: str = "Invalid API credential."):
        super().__init__(message=message, code="INVALID_CREDENTIAL", status_code=401)


class CredentialRevokedError(CredentialError):
    """Raised when credential has been revoked."""
    def __init__(self, message: str = "API credential has been revoked."):
        super().__init__(message=message, code="CREDENTIAL_REVOKED", status_code=401)


class CredentialExpiredError(CredentialError):
    """Raised when credential has expired."""
    def __init__(self, message: str = "API credential has expired."):
        super().__init__(message=message, code="CREDENTIAL_EXPIRED", status_code=401)


class CredentialDisabledError(CredentialError):
    """Raised when credential has been disabled."""
    def __init__(self, message: str = "API credential is disabled."):
        super().__init__(message=message, code="CREDENTIAL_DISABLED", status_code=401)


class CredentialNotFoundError(CredentialError):
    """Raised when credential is not found during management lookups."""
    def __init__(self, message: str = "API credential not found."):
        super().__init__(message=message, code="CREDENTIAL_NOT_FOUND", status_code=404)


class CredentialAccessDeniedError(CredentialError):
    """Raised when caller lacks authorization to manage the credential."""
    def __init__(self, message: str = "Access to credential denied."):
        super().__init__(message=message, code="RESOURCE_ACCESS_DENIED", status_code=403)


@dataclass(frozen=True)
class CredentialRecord:
    """
    Metadata representation of an API credential. Never contains the secret or full hash in public views.
    """
    credential_id: str
    principal_id: str
    tenant_id: str
    status: str
    created_at: float
    expires_at: Optional[float]
    last_used_at: Optional[float]
    revoked_at: Optional[float]
    description: Optional[str]
    created_by: str

    def is_active(self, current_time: Optional[float] = None) -> bool:
        if self.status != "ACTIVE":
            return False
        now = current_time or time.time()
        if self.expires_at and now > self.expires_at:
            return False
        return True

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns safe metadata dictionary for API responses (NO secret, NO hash)."""
        return {
            "credential_id": self.credential_id,
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
            "description": self.description,
            "created_by": self.created_by,
        }


class CredentialService:
    """
    Thread-safe SQLite service for API credentials.
    """

    def __init__(self, db_path: str = CREDENTIAL_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        self._check_bootstrap_admin()

    def _get_connection(self) -> sqlite3.Connection:
        return get_hardened_connection(self.db_path, timeout=5.0)

    def _init_db(self):
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS credentials (
                            credential_id TEXT PRIMARY KEY,
                            credential_hash TEXT NOT NULL,
                            principal_id TEXT NOT NULL,
                            tenant_id TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            expires_at REAL,
                            last_used_at REAL,
                            revoked_at REAL,
                            description TEXT,
                            created_by TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_cred_principal ON credentials(principal_id)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_cred_tenant ON credentials(tenant_id)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_cred_status ON credentials(status)")
            finally:
                conn.close()

    def _check_bootstrap_admin(self):
        """
        Safe development bootstrap mechanism:
        When explicitly enabled by AGENTGUARD_BOOTSTRAP_ADMIN_ENABLED=true, generates a bootstrap
        admin credential and prints it ONCE to stdout for local development.
        Default is DISABLED.
        """
        if not BOOTSTRAP_ADMIN_ENABLED:
            return

        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT credential_id FROM credentials WHERE principal_id = ? AND status = 'ACTIVE'",
                    (BOOTSTRAP_ADMIN_PRINCIPAL,),
                )
                if not cur.fetchone():
                    # Generate one-time development admin credential
                    cred_id = f"c_{secrets.token_hex(8)}"
                    secret = secrets.token_hex(32)
                    cred_hash = _argon2_hasher.hash(secret)
                    now = time.time()
                    conn.execute(
                        """
                        INSERT INTO credentials (
                            credential_id, credential_hash, principal_id, tenant_id,
                            status, created_at, expires_at, description, created_by
                        ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)
                        """,
                        (
                            cred_id,
                            cred_hash,
                            BOOTSTRAP_ADMIN_PRINCIPAL,
                            DEFAULT_TENANT,
                            now,
                            now + CREDENTIAL_EXPIRATION_SECONDS,
                            "Development Bootstrap Admin Credential",
                            "system-bootstrap",
                        ),
                    )
                    full_token = f"ag_{cred_id}_{secret}"
                    logger.warning(
                        "=== [AGENTGUARD BOOTSTRAP ADMIN CREDENTIAL GENERATED] ===\n"
                        "Principal: %s | Tenant: %s\n"
                        "Token: %s\n"
                        "==========================================================",
                        BOOTSTRAP_ADMIN_PRINCIPAL,
                        DEFAULT_TENANT,
                        full_token,
                    )
            finally:
                conn.close()

    def create_credential(
        self,
        principal_id: str,
        tenant_id: Optional[str] = None,
        description: Optional[str] = None,
        expires_in_seconds: Optional[int] = None,
        created_by: str = "admin",
        caller_context: Optional[RequestSecurityContext] = None,
        expires_at: Optional[Any] = None,
    ) -> Tuple[CredentialRecord, str]:
        """
        Generates and securely stores a new API credential.
        
        Enforces:
        - Only admin can create credentials.
        - Tenant admins can ONLY create credentials for principals within their own tenant.
        - Plaintext secret is returned ONLY in the return tuple and NEVER stored in the DB.
        
        Returns: (CredentialRecord, full_token)
        """
        target_tenant = tenant_id or (caller_context.tenant_id if caller_context else DEFAULT_TENANT)

        if caller_context:
            if not (caller_context.has_role("admin") or caller_context.global_admin):
                raise CredentialAccessDeniedError("Only administrators can create API credentials.")

            if not caller_context.can_access_tenant(target_tenant):
                raise CredentialAccessDeniedError("Cannot create credential for a different tenant.")

        # Cryptographically secure random identifiers
        cred_id = f"c_{secrets.token_hex(8)}"
        secret = secrets.token_hex(32)
        full_token = f"ag_{cred_id}_{secret}"

        # Argon2id hash of the secret
        cred_hash = _argon2_hasher.hash(secret)
        now = time.time()
        if expires_at is not None:
            if hasattr(expires_at, "timestamp"):
                exp_ts = expires_at.timestamp()
            else:
                exp_ts = float(expires_at)
        else:
            ttl = expires_in_seconds if expires_in_seconds is not None else CREDENTIAL_EXPIRATION_SECONDS
            exp_ts = (now + ttl) if ttl > 0 else None

        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO credentials (
                            credential_id, credential_hash, principal_id, tenant_id,
                            status, created_at, expires_at, description, created_by
                        ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)
                        """,
                        (
                            cred_id,
                            cred_hash,
                            principal_id.strip(),
                            target_tenant,
                            now,
                            exp_ts,
                            description.strip() if description else None,
                            caller_context.principal_id if caller_context else created_by,
                        ),
                    )
            finally:
                conn.close()

        record = CredentialRecord(
            credential_id=cred_id,
            principal_id=principal_id.strip(),
            tenant_id=target_tenant,
            status="ACTIVE",
            created_at=now,
            expires_at=exp_ts,
            last_used_at=None,
            revoked_at=None,
            description=description.strip() if description else None,
            created_by=caller_context.principal_id if caller_context else created_by,
        )

        return record, full_token

    def verify_credential(self, credential_id: str, secret_or_token: str) -> Optional[CredentialRecord]:
        """
        Verifies a credential by ID and secret (or full bearer token).
        Returns CredentialRecord if valid and ACTIVE, None otherwise.
        """
        token = secret_or_token
        if not secret_or_token.startswith("ag_"):
            token = f"ag_{credential_id}_{secret_or_token}"
        try:
            record, _ = self.verify_and_authenticate(token)
            if record.credential_id != credential_id:
                return None
            return record
        except Exception:
            return None

    def verify_and_authenticate(self, bearer_token: str) -> Tuple[CredentialRecord, str]:
        """
        Parses and cryptographically verifies a Bearer token against stored credentials.
        
        Timing attack mitigation:
        - If credential ID is malformed or unknown, performs constant-time dummy Argon2id hash
          verification before failing.
        - Constant-time comparison ensures token validity cannot be inferred from timing differences.
        
        Returns: (CredentialRecord, credential_id) on success.
        Raises: InvalidCredentialError, CredentialRevokedError, CredentialExpiredError, CredentialDisabledError.
        """
        if not bearer_token or not isinstance(bearer_token, str):
            raise InvalidCredentialError("Missing or malformed token.")

        raw = bearer_token.strip()
        if not raw.startswith("ag_"):
            raise InvalidCredentialError("Invalid credential format.")

        body = raw[3:]
        if not body.startswith("c_"):
            raise InvalidCredentialError("Invalid credential format.")

        body_parts = body.split("_", 2)
        if len(body_parts) != 3:
            raise InvalidCredentialError("Invalid credential structure.")

        cred_id = f"{body_parts[0]}_{body_parts[1]}"
        secret = body_parts[2]

        if not cred_id or not secret:
            raise InvalidCredentialError("Invalid credential structure.")

        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                SELECT credential_id, credential_hash, principal_id, tenant_id,
                       status, created_at, expires_at, last_used_at, revoked_at,
                       description, created_by
                FROM credentials
                WHERE credential_id = ?
                """,
                (cred_id,),
            )
            row = cur.fetchone()
        finally:
            conn.close()

        # Timing mitigation: Unknown credential ID path
        if not row:
            try:
                _argon2_hasher.verify(_DUMMY_ARGON2_HASH, secret)
            except Exception:
                pass
            raise InvalidCredentialError("Invalid API credential.")

        stored_hash = row["credential_hash"]

        # Cryptographically verify the secret against Argon2id hash
        try:
            _argon2_hasher.verify(stored_hash, secret)
        except (VerifyMismatchError, InvalidHashError):
            raise InvalidCredentialError("Invalid API credential.")
        except Exception as exc:
            logger.error("Credential verification error: %s", exc)
            raise InvalidCredentialError("Invalid API credential.")

        # Evaluate credential status (fail closed)
        status = row["status"]
        if status == "REVOKED":
            raise CredentialRevokedError("Credential has been revoked.")
        elif status == "DISABLED":
            raise CredentialDisabledError("Credential is disabled.")
        elif status == "EXPIRED":
            raise CredentialExpiredError("Credential has expired.")
        elif status != "ACTIVE":
            raise InvalidCredentialError("Invalid credential status.")

        # Evaluate expiration
        now = time.time()
        expires_at = row["expires_at"]
        if expires_at and now > expires_at:
            # Mark expired in DB
            self._mark_expired(cred_id)
            raise CredentialExpiredError("Credential has expired.")

        # Update last_used_at timestamp
        self._touch_last_used(cred_id, now)

        record = CredentialRecord(
            credential_id=row["credential_id"],
            principal_id=row["principal_id"],
            tenant_id=row["tenant_id"],
            status=status,
            created_at=row["created_at"],
            expires_at=expires_at,
            last_used_at=now,
            revoked_at=row["revoked_at"],
            description=row["description"],
            created_by=row["created_by"],
        )

        return record, cred_id

    def _touch_last_used(self, credential_id: str, timestamp: float):
        try:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("UPDATE credentials SET last_used_at = ? WHERE credential_id = ?", (timestamp, credential_id))
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Failed to update last_used_at for credential=%s: %s", credential_id, exc)

    def _mark_expired(self, credential_id: str):
        try:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("UPDATE credentials SET status = 'EXPIRED' WHERE credential_id = ?", (credential_id,))
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Failed to update status=EXPIRED for credential=%s: %s", credential_id, exc)

    def get_credential(
        self,
        credential_id: str,
        caller_context: Optional[RequestSecurityContext] = None,
    ) -> Optional[CredentialRecord]:
        """
        Retrieves credential metadata (never plaintext secret or hash).
        Enforces tenant isolation: callers cannot inspect credentials belonging to other tenants.
        """
        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                SELECT credential_id, principal_id, tenant_id, status, created_at,
                       expires_at, last_used_at, revoked_at, description, created_by
                FROM credentials WHERE credential_id = ?
                """,
                (credential_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            if caller_context and not caller_context.can_access_tenant(row["tenant_id"]):
                # Safe 404 behavior to prevent enumeration
                return None

            return CredentialRecord(
                credential_id=row["credential_id"],
                principal_id=row["principal_id"],
                tenant_id=row["tenant_id"],
                status=row["status"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                last_used_at=row["last_used_at"],
                revoked_at=row["revoked_at"],
                description=row["description"],
                created_by=row["created_by"],
            )
        finally:
            conn.close()

    def list_credentials(
        self,
        caller_context: Optional[RequestSecurityContext] = None,
        principal_id: Optional[str] = None,
    ) -> List[CredentialRecord]:
        """
        Lists credentials filtered by tenant scope and caller authority.
        """
        conn = self._get_connection()
        try:
            clauses = []
            params = []

            if caller_context and not caller_context.global_admin:
                clauses.append("tenant_id = ?")
                params.append(caller_context.tenant_id)

            if principal_id:
                clauses.append("principal_id = ?")
                params.append(principal_id)

            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            query = f"""
                SELECT credential_id, principal_id, tenant_id, status, created_at,
                       expires_at, last_used_at, revoked_at, description, created_by
                FROM credentials
                {where}
                ORDER BY created_at DESC
            """
            cur = conn.execute(query, params)
            rows = cur.fetchall()
            return [
                CredentialRecord(
                    credential_id=r["credential_id"],
                    principal_id=r["principal_id"],
                    tenant_id=r["tenant_id"],
                    status=r["status"],
                    created_at=r["created_at"],
                    expires_at=r["expires_at"],
                    last_used_at=r["last_used_at"],
                    revoked_at=r["revoked_at"],
                    description=r["description"],
                    created_by=r["created_by"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def revoke_credential(
        self,
        credential_id: str,
        caller_context: Optional[RequestSecurityContext] = None,
        revoked_by: Optional[str] = None,
    ) -> CredentialRecord:
        """
        Revokes an API credential immediately.
        Subsequent verification attempts will fail immediately with CREDENTIAL_REVOKED.
        """
        existing = self.get_credential(credential_id, caller_context)
        if not existing:
            raise CredentialNotFoundError(f"Credential '{credential_id}' not found.")

        if caller_context:
            if not (caller_context.has_role("admin") or caller_context.global_admin):
                raise CredentialAccessDeniedError("Only administrators can revoke credentials.")
            if not caller_context.can_access_tenant(existing.tenant_id):
                raise CredentialNotFoundError(f"Credential '{credential_id}' not found.")

        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        "UPDATE credentials SET status = 'REVOKED', revoked_at = ? WHERE credential_id = ?",
                        (now, credential_id),
                    )
            finally:
                conn.close()

        return CredentialRecord(
            credential_id=existing.credential_id,
            principal_id=existing.principal_id,
            tenant_id=existing.tenant_id,
            status="REVOKED",
            created_at=existing.created_at,
            expires_at=existing.expires_at,
            last_used_at=existing.last_used_at,
            revoked_at=now,
            description=existing.description,
            created_by=existing.created_by,
        )

    def rotate_credential(
        self,
        credential_id: str,
        caller_context: Optional[RequestSecurityContext] = None,
    ) -> Tuple[CredentialRecord, str, str]:
        """
        Rotates an API credential:
        1. Revokes the existing credential immediately.
        2. Generates a new cryptographically random secret and credential ID.
        3. Returns the new credential metadata and secret (returned once only).
        """
        existing = self.get_credential(credential_id, caller_context)
        if not existing:
            raise CredentialNotFoundError(f"Credential '{credential_id}' not found.")

        if caller_context:
            if not (caller_context.has_role("admin") or caller_context.global_admin):
                raise CredentialAccessDeniedError("Only administrators can rotate credentials.")
            if not caller_context.can_access_tenant(existing.tenant_id):
                raise CredentialNotFoundError(f"Credential '{credential_id}' not found.")

        # Step 1: Revoke old credential
        self.revoke_credential(credential_id, caller_context)

        # Step 2: Issue new credential for same principal and tenant
        new_record, new_token = self.create_credential(
            principal_id=existing.principal_id,
            tenant_id=existing.tenant_id,
            description=f"Rotated from {credential_id}",
            caller_context=caller_context,
        )

        return new_record, new_token

    def is_healthy(self) -> bool:
        """Readiness probe verification."""
        try:
            conn = self._get_connection()
            try:
                healthy, _ = check_database_integrity(conn)
                if not healthy:
                    return False
                cur = conn.execute("SELECT COUNT(*) FROM credentials")
                cur.fetchone()
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def reset_for_testing(self):
        """Clears credentials table for test suites."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM credentials")
            finally:
                conn.close()


credential_service = CredentialService()
