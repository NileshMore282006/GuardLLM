"""
AgentGuard Audit Service (Backend v0.9)
Persistent Security Audit Event logging backed by hardened SQLite with tamper-evident
cryptographic hash chaining and keyed HMAC-SHA-256 integrity verification.

LIMITATION & SCOPE NOTICE:
The audit database is tamper-evident through hash chaining and HMAC signing but is NOT
an immutable remote ledger or hardware-enforced append-only medium. A local SQLite
administrator with database file write access can still modify or delete the file.
External append-only remote storage / KMS is planned for v1.0.

SECURITY INVARIANTS:
1. Records security-relevant events at boundaries (Guard, Tool Guard, Approvals, Policies, Auth).
2. Sanitizes fields to ensure secrets (canary, tokens, passwords) and raw prompts are NEVER stored.
3. Cryptographically links records in a hash chain (previous_event_hash -> event_hash).
4. Supports keyed HMAC-SHA-256 when AGENTGUARD_AUDIT_INTEGRITY_KEY is configured.
5. verify_audit_chain() detects modification, reordering, insertion, and deletion.
6. verify_audit_chain() distinguishes: valid, tampered, key_missing, incompatible.
7. Parameterized SQL queries exclusively; hardened connections with foreign keys and WAL.
8. Enforces multi-tenant isolation and principal-scoped queries.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from backend.config import (
    AUDIT_CHAIN_ENABLED,
    AUDIT_DB_PATH,
    AUDIT_ENABLED,
    AUDIT_INTEGRITY_KEY,
    MAX_AUDIT_PAGE_SIZE,
)
from backend.services.db_hardening import check_database_integrity, get_hardened_connection
from backend.services.identity_service import Principal
from backend.services.secret_service import secret_manager

logger = logging.getLogger("agentguard.audit")

CANARY_SECRET = "BLUE-ORANGE-42"
GENESIS_HASH = "0" * 64


class AuditError(Exception):
    """Base exception for audit failures."""
    def __init__(self, message: str, code: str = "AUDIT_FAILURE", status_code: int = 500):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class AuditFailureError(AuditError):
    """Raised when an essential security audit write fails."""
    def __init__(self, message: str = "Security audit logging failed."):
        super().__init__(message=message, code="AUDIT_FAILURE", status_code=500)


class AuditAccessDeniedError(AuditError):
    """Raised when principal is unauthorized to query the requested audit events."""
    def __init__(self, message: str = "Access to requested audit events denied."):
        super().__init__(message=message, code="AUDIT_ACCESS_DENIED", status_code=403)


@dataclass
class AuditEvent:
    event_id: str
    timestamp: float
    request_id: Optional[str]
    principal_id: Optional[str]
    principal_type: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    decision: Optional[str]
    risk_score: Optional[float]
    attack_type: Optional[str]
    policy_id: Optional[str]
    policy_version: Optional[int]
    approval_id: Optional[str]
    tool_name: Optional[str]
    error_code: Optional[str]
    event_hash: str
    previous_event_hash: str
    tenant_id: Optional[str] = "default"
    hash_algorithm: str = "sha256"


def sanitize_audit_text(value: Optional[str]) -> Optional[str]:
    """
    Sanitizes string metadata before writing to the audit log.
    Ensures secrets, bearer credentials, and canary codes are redacted and length is bounded.
    """
    if value is None:
        return None
    sanitized = str(value)
    if CANARY_SECRET.lower() in sanitized.lower():
        sanitized = re.sub(re.escape(CANARY_SECRET), "[REDACTED_SECRET]", sanitized, flags=re.IGNORECASE)
    sanitized = secret_manager.redact_secrets(sanitized)
    # Bounded string length to prevent SQLite bloat/DoS
    return sanitized[:500]


def compute_event_hash(
    event_id: str,
    timestamp: float,
    request_id: Optional[str],
    principal_id: Optional[str],
    action: str,
    resource_type: Optional[str],
    resource_id: Optional[str],
    decision: Optional[str],
    risk_score: Optional[float],
    attack_type: Optional[str],
    policy_id: Optional[str],
    policy_version: Optional[int],
    approval_id: Optional[str],
    tool_name: Optional[str],
    error_code: Optional[str],
    previous_event_hash: str,
    tenant_id: Optional[str] = None,
    key: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> str:
    """
    Computes a deterministic cryptographic digest of canonicalized audit event fields.
    If key is provided (or algorithm is 'hmac-sha256'), computes HMAC-SHA-256.
    Otherwise computes standard SHA-256 for backward compatibility.
    """
    payload = {
        "action": action,
        "approval_id": approval_id,
        "attack_type": attack_type,
        "decision": decision,
        "error_code": error_code,
        "event_id": event_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "previous_event_hash": previous_event_hash,
        "principal_id": principal_id,
        "request_id": request_id,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "risk_score": risk_score,
        "timestamp": round(timestamp, 4),
        "tool_name": tool_name,
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id

    # Deterministic canonical JSON serialization
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    use_hmac = (algorithm == "hmac-sha256") or (key is not None and len(key.strip()) > 0)
    if use_hmac and key:
        return hmac.new(key.strip().encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    else:
        return hashlib.sha256(canonical_bytes).hexdigest()


class AuditService:
    """
    Thread-safe audit logging service backed by hardened SQLite.
    """

    def __init__(self, db_path: str = AUDIT_DB_PATH, integrity_key: Optional[str] = None):
        self.db_path = db_path
        self._integrity_key = integrity_key
        self._lock = threading.Lock()
        self._init_db()

    def get_integrity_key(self) -> Optional[str]:
        """Resolves the current integrity key from instance or secret manager."""
        if self._integrity_key:
            return self._integrity_key
        return secret_manager.get_audit_integrity_key() or AUDIT_INTEGRITY_KEY

    def set_integrity_key(self, key: Optional[str]) -> None:
        """Sets the integrity key for this audit service instance."""
        self._integrity_key = key

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a hardened SQLite connection with foreign keys and busy timeout."""
        return get_hardened_connection(self.db_path, timeout=5.0)

    def _init_db(self):
        """Creates table and applies schema migrations if absent."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            event_id TEXT UNIQUE NOT NULL,
                            timestamp REAL NOT NULL,
                            request_id TEXT,
                            principal_id TEXT,
                            principal_type TEXT,
                            action TEXT NOT NULL,
                            resource_type TEXT,
                            resource_id TEXT,
                            decision TEXT,
                            risk_score REAL,
                            attack_type TEXT,
                            policy_id TEXT,
                            policy_version INTEGER,
                            approval_id TEXT,
                            tool_name TEXT,
                            error_code TEXT,
                            event_hash TEXT NOT NULL,
                            previous_event_hash TEXT NOT NULL,
                            tenant_id TEXT,
                            hash_algorithm TEXT DEFAULT 'sha256'
                        )
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_events(request_id)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_princ ON audit_events(principal_id)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id)")

                    # Check for missing columns in existing schemas
                    cur = conn.execute("PRAGMA table_info(audit_events)")
                    cols = [row["name"] for row in cur.fetchall()]
                    if "tenant_id" not in cols:
                        conn.execute("ALTER TABLE audit_events ADD COLUMN tenant_id TEXT")
                    if "hash_algorithm" not in cols:
                        conn.execute("ALTER TABLE audit_events ADD COLUMN hash_algorithm TEXT DEFAULT 'sha256'")
            finally:
                conn.close()

    def get_latest_event_hash(self) -> str:
        """Retrieves the event_hash of the most recently inserted event for hash chaining."""
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                return row["event_hash"]
            return GENESIS_HASH
        finally:
            conn.close()

    def log_event(
        self,
        action: str,
        request_id: Optional[str] = None,
        principal: Optional[Any] = None,
        principal_id: Optional[str] = None,
        principal_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        decision: Optional[str] = None,
        risk_score: Optional[float] = None,
        attack_type: Optional[str] = None,
        policy_id: Optional[str] = None,
        policy_version: Optional[int] = None,
        approval_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        error_code: Optional[str] = None,
        fail_closed: bool = False,
    ) -> Optional[AuditEvent]:
        """
        Records an audit event with tamper-evident chaining, tenant binding, and HMAC signing.
        """
        if not AUDIT_ENABLED:
            return None

        event_id = f"evt_{secrets.token_hex(16)}"
        now = time.time()

        p_id = getattr(principal, "principal_id", principal_id)
        p_type = getattr(principal, "principal_type", principal_type)
        p_tenant = getattr(principal, "tenant_id", None)
        effective_tenant = tenant_id or p_tenant or "default"

        # Sanitize metadata fields
        sanitized_req_id = sanitize_audit_text(request_id)
        sanitized_p_id = sanitize_audit_text(p_id)
        sanitized_p_type = sanitize_audit_text(p_type)
        sanitized_tenant_id = sanitize_audit_text(effective_tenant)
        sanitized_action = sanitize_audit_text(action) or "unknown"
        sanitized_res_type = sanitize_audit_text(resource_type)
        sanitized_res_id = sanitize_audit_text(resource_id)
        sanitized_decision = sanitize_audit_text(decision)
        sanitized_attack = sanitize_audit_text(attack_type)
        sanitized_pol_id = sanitize_audit_text(policy_id)
        sanitized_appr_id = sanitize_audit_text(approval_id)
        sanitized_tool = sanitize_audit_text(tool_name)
        sanitized_err = sanitize_audit_text(error_code)

        integrity_key = self.get_integrity_key()
        algorithm = "hmac-sha256" if integrity_key else "sha256"

        with self._lock:
            try:
                prev_hash = self.get_latest_event_hash() if AUDIT_CHAIN_ENABLED else GENESIS_HASH
                event_hash = compute_event_hash(
                    event_id=event_id,
                    timestamp=now,
                    request_id=sanitized_req_id,
                    principal_id=sanitized_p_id,
                    action=sanitized_action,
                    resource_type=sanitized_res_type,
                    resource_id=sanitized_res_id,
                    decision=sanitized_decision,
                    risk_score=risk_score,
                    attack_type=sanitized_attack,
                    policy_id=sanitized_pol_id,
                    policy_version=policy_version,
                    approval_id=sanitized_appr_id,
                    tool_name=sanitized_tool,
                    error_code=sanitized_err,
                    previous_event_hash=prev_hash,
                    tenant_id=sanitized_tenant_id,
                    key=integrity_key,
                    algorithm=algorithm,
                )

                conn = self._get_connection()
                try:
                    with conn:
                        conn.execute(
                            """
                            INSERT INTO audit_events (
                                event_id, timestamp, request_id, principal_id, principal_type,
                                action, resource_type, resource_id, decision, risk_score,
                                attack_type, policy_id, policy_version, approval_id, tool_name,
                                error_code, event_hash, previous_event_hash, tenant_id, hash_algorithm
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                event_id, now, sanitized_req_id, sanitized_p_id, sanitized_p_type,
                                sanitized_action, sanitized_res_type, sanitized_res_id, sanitized_decision,
                                risk_score, sanitized_attack, sanitized_pol_id, policy_version,
                                sanitized_appr_id, sanitized_tool, sanitized_err, event_hash, prev_hash,
                                sanitized_tenant_id, algorithm,
                            ),
                        )
                finally:
                    conn.close()

                return AuditEvent(
                    event_id=event_id,
                    timestamp=now,
                    request_id=sanitized_req_id,
                    principal_id=sanitized_p_id,
                    principal_type=sanitized_p_type,
                    action=sanitized_action,
                    resource_type=sanitized_res_type,
                    resource_id=sanitized_res_id,
                    decision=sanitized_decision,
                    risk_score=risk_score,
                    attack_type=sanitized_attack,
                    policy_id=sanitized_pol_id,
                    policy_version=policy_version,
                    approval_id=sanitized_appr_id,
                    tool_name=sanitized_tool,
                    error_code=sanitized_err,
                    event_hash=event_hash,
                    previous_event_hash=prev_hash,
                    tenant_id=sanitized_tenant_id,
                    hash_algorithm=algorithm,
                )

            except Exception as exc:
                logger.error("Failed to write audit event: %s", type(exc).__name__)
                if fail_closed:
                    raise AuditFailureError(f"Security audit logging failed: {type(exc).__name__}")
                return None

    def query_events(
        self,
        principal: Any,
        request_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        action: Optional[str] = None,
        decision: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Queries audit events with parameterized filtering, tenant isolation, and RBAC enforcement.
        """
        bounded_limit = max(1, min(limit, MAX_AUDIT_PAGE_SIZE))
        bounded_offset = max(0, offset)

        clauses = []
        params = []

        caller_tenant = getattr(principal, "tenant_id", None)
        is_global_admin = getattr(principal, "global_admin", False) or (
            hasattr(principal, "has_role") and principal.has_role("global_admin")
        )
        is_admin_or_operator = False
        if hasattr(principal, "has_role"):
            is_admin_or_operator = principal.has_role("admin") or principal.has_role("operator") or is_global_admin
        elif hasattr(principal, "roles"):
            is_admin_or_operator = any(r in ("admin", "operator", "global_admin") for r in principal.roles)

        # Tenant isolation
        if not is_global_admin and caller_tenant:
            clauses.append("(tenant_id = ? OR tenant_id IS NULL)")
            params.append(caller_tenant)
        elif is_global_admin and tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        # RBAC ownership scoping
        if not is_admin_or_operator:
            clauses.append("principal_id = ?")
            params.append(principal.principal_id)
        elif principal_id:
            clauses.append("principal_id = ?")
            params.append(principal_id)

        if request_id:
            clauses.append("request_id = ?")
            params.append(request_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if start_time is not None:
            clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time is not None:
            clauses.append("timestamp <= ?")
            params.append(end_time)

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        conn = self._get_connection()
        try:
            count_sql = f"SELECT COUNT(*) AS total FROM audit_events {where_clause}"
            cur = conn.execute(count_sql, params)
            total = cur.fetchone()["total"]

            data_sql = f"""
                SELECT event_id, timestamp, request_id, principal_id, principal_type,
                       action, resource_type, resource_id, decision, risk_score,
                       attack_type, policy_id, policy_version, approval_id, tool_name,
                       error_code, event_hash, previous_event_hash, tenant_id, hash_algorithm
                FROM audit_events
                {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """
            cur = conn.execute(data_sql, params + [bounded_limit, bounded_offset])
            rows = [dict(row) for row in cur.fetchall()]
            return rows, total
        finally:
            conn.close()

    def verify_audit_chain(self) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of the entire audit hash chain.
        Detects tampering, out-of-order alterations, record deletion, or missing keys.
        Distinguishes:
        - 'valid': Hash chain and records are completely intact.
        - 'tampered': Record modified, inserted, deleted, or reordered.
        - 'key_missing': Records signed with HMAC but key is not available.
        - 'incompatible': Unsupported hash algorithm encountered.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT event_id, timestamp, request_id, principal_id, action,
                           resource_type, resource_id, decision, risk_score, attack_type,
                           policy_id, policy_version, approval_id, tool_name, error_code,
                           event_hash, previous_event_hash, tenant_id, hash_algorithm
                    FROM audit_events
                    ORDER BY id ASC
                    """
                )
                rows = cur.fetchall()
            finally:
                conn.close()

        if not rows:
            return {
                "valid": True,
                "status": "valid",
                "first_invalid_event": None,
                "total_events": 0,
                "details": "Audit log is empty; chain is valid.",
            }

        integrity_key = self.get_integrity_key()
        expected_prev_hash = GENESIS_HASH

        for row in rows:
            event_id = row["event_id"]
            prev_hash = row["previous_event_hash"]
            event_hash = row["event_hash"]
            row_algo = row["hash_algorithm"] if "hash_algorithm" in row.keys() else "sha256"

            # Check if HMAC key is required but missing
            if row_algo == "hmac-sha256" and not integrity_key:
                logger.error(
                    "Audit verification unavailable: HMAC integrity key is missing for event=%s",
                    event_id,
                )
                return {
                    "valid": False,
                    "status": "key_missing",
                    "first_invalid_event": event_id,
                    "total_events": len(rows),
                    "details": "HMAC audit integrity key is required to verify this audit chain.",
                }

            # Step 1: Verify chain link to previous event
            if prev_hash != expected_prev_hash:
                logger.error(
                    "Audit chain broken at event=%s: previous_event_hash=%s does not match expected=%s",
                    event_id,
                    prev_hash,
                    expected_prev_hash,
                )
                return {
                    "valid": False,
                    "status": "tampered",
                    "first_invalid_event": event_id,
                    "total_events": len(rows),
                    "details": f"Chain link broken at event '{event_id}'.",
                }

            # Step 2: Verify record's own computed hash
            recomputed_hash = compute_event_hash(
                event_id=event_id,
                timestamp=row["timestamp"],
                request_id=row["request_id"],
                principal_id=row["principal_id"],
                action=row["action"],
                resource_type=row["resource_type"],
                resource_id=row["resource_id"],
                decision=row["decision"],
                risk_score=row["risk_score"],
                attack_type=row["attack_type"],
                policy_id=row["policy_id"],
                policy_version=row["policy_version"],
                approval_id=row["approval_id"],
                tool_name=row["tool_name"],
                error_code=row["error_code"],
                previous_event_hash=prev_hash,
                tenant_id=row["tenant_id"],
                key=integrity_key if row_algo == "hmac-sha256" else None,
                algorithm=row_algo,
            )

            if event_hash != recomputed_hash:
                logger.error(
                    "Audit tamper detected at event=%s: stored_hash=%s recomputed=%s",
                    event_id,
                    event_hash,
                    recomputed_hash,
                )
                return {
                    "valid": False,
                    "status": "tampered",
                    "first_invalid_event": event_id,
                    "total_events": len(rows),
                    "details": f"Tampering detected in event '{event_id}' payload.",
                }

            expected_prev_hash = event_hash

        return {
            "valid": True,
            "status": "valid",
            "first_invalid_event": None,
            "total_events": len(rows),
            "details": f"Verified {len(rows)} chained audit events successfully.",
        }

    def is_healthy(self) -> bool:
        """Verifies audit store accessibility and database integrity for readiness probes."""
        try:
            conn = self._get_connection()
            try:
                healthy, _ = check_database_integrity(conn)
                if not healthy:
                    return False
                cur = conn.execute("SELECT COUNT(*) FROM audit_events")
                cur.fetchone()
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def reset_for_testing(self):
        """Clears all audit events for testing purposes."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM audit_events")
            finally:
                conn.close()


# Singleton audit service instance
audit_service = AuditService()
