"""
AgentGuard Principal Service (Backend v0.8)
Provides persistent storage, RBAC validation, and lifecycle administration for security principals.

SECURITY INVARIANTS:
1. Roles and tenants are NEVER inferred from client headers or request bodies.
2. Only administrative authority may create or modify principal records.
3. Tenant-scoped admins CANNOT create global admins or promote principals to roles they do not hold.
4. Users cannot change their own roles or tenant bindings (prevents self-promotion / escalation).
5. Disabling the final active administrator is strictly blocked unless explicit safety handling is met.
6. Unknown status fails closed.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from backend.config import CREDENTIAL_DB_PATH, DEFAULT_TENANT
from backend.services.db_hardening import check_database_integrity, get_hardened_connection
from backend.services.request_context import RequestSecurityContext

logger = logging.getLogger("agentguard.principal")

VALID_PRINCIPAL_TYPES = {"user", "service", "admin", "global_admin"}
VALID_ROLES = {"user", "operator", "admin", "global_admin"}
VALID_STATUSES = {"ACTIVE", "DISABLED"}


class PrincipalError(Exception):
    """Base exception for principal operations."""
    def __init__(self, message: str, code: str = "PRINCIPAL_ERROR", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class PrincipalNotFoundError(PrincipalError):
    """Raised when principal is not found."""
    def __init__(self, message: str = "Principal not found."):
        super().__init__(message=message, code="PRINCIPAL_NOT_FOUND", status_code=404)


class PrincipalDisabledError(PrincipalError):
    """Raised when principal is disabled."""
    def __init__(self, message: str = "Principal is disabled."):
        super().__init__(message=message, code="PRINCIPAL_DISABLED", status_code=403)


class PrincipalConflictError(PrincipalError):
    """Raised when creating a duplicate principal."""
    def __init__(self, message: str = "Principal already exists."):
        super().__init__(message=message, code="PRINCIPAL_CONFLICT", status_code=409)


class PrivilegeEscalationError(PrincipalError):
    """Raised when an operation attempts unauthorized privilege escalation."""
    def __init__(self, message: str = "Privilege escalation denied."):
        super().__init__(message=message, code="PRIVILEGE_ESCALATION", status_code=403)


@dataclass(frozen=True)
class PrincipalRecord:
    """
    Immutable representation of an authenticated principal in memory.
    """
    principal_id: str
    principal_type: str  # 'user', 'service', 'admin', 'global_admin'
    tenant_id: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "ACTIVE"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def is_active(self) -> bool:
        return self.status == "ACTIVE"

    def has_role(self, role: str) -> bool:
        if "global_admin" in self.roles and role in ("admin", "operator", "user"):
            return True
        return role in self.roles

    def has_any_role(self, roles: List[str]) -> bool:
        if "global_admin" in self.roles:
            return True
        return any(r in self.roles for r in roles)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "tenant_id": self.tenant_id,
            "roles": list(self.roles),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class PrincipalService:
    """
    Thread-safe SQLite service for principals.
    """

    def __init__(self, db_path: str = CREDENTIAL_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

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
                        CREATE TABLE IF NOT EXISTS principals (
                            principal_id TEXT PRIMARY KEY,
                            principal_type TEXT NOT NULL,
                            tenant_id TEXT NOT NULL,
                            roles TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL
                        )
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_princ_tenant ON principals(tenant_id)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_princ_status ON principals(status)")

                    self._seed_default_principals(conn)
            finally:
                conn.close()

    def _seed_defaults(self):
        """Re-initializes tables and seeds default principals if missing."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    self._seed_default_principals(conn)
                    conn.execute("UPDATE principals SET status = 'ACTIVE' WHERE principal_id IN ('admin-demo', 'user-demo', 'operator-demo', 'global-admin-demo')")
            finally:
                conn.close()

    def _seed_default_principals(self, conn: sqlite3.Connection):
        now = time.time()
        defaults = [
            ("user-demo", "user", DEFAULT_TENANT, ["user"], "ACTIVE"),
            ("operator-demo", "user", DEFAULT_TENANT, ["operator"], "ACTIVE"),
            ("admin-demo", "admin", DEFAULT_TENANT, ["admin"], "ACTIVE"),
            ("service-demo", "service", DEFAULT_TENANT, ["operator"], "ACTIVE"),
            ("disabled-demo", "user", DEFAULT_TENANT, ["user"], "DISABLED"),
            ("global-admin-demo", "global_admin", DEFAULT_TENANT, ["global_admin", "admin"], "ACTIVE"),
        ]
        for pid, ptype, tid, roles, status in defaults:
            cur = conn.execute("SELECT principal_id FROM principals WHERE principal_id = ?", (pid,))
            if not cur.fetchone():
                conn.execute(
                    """
                    INSERT INTO principals (principal_id, principal_type, tenant_id, roles, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (pid, ptype, tid, json.dumps(roles), status, now, now),
                )

    def get_principal(
        self,
        principal_id: str,
        caller_context: Optional[RequestSecurityContext] = None,
    ) -> Optional[PrincipalRecord]:
        """
        Retrieves principal by ID.
        If caller_context is provided, enforces tenant isolation.
        """
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "SELECT principal_id, principal_type, tenant_id, roles, status, created_at, updated_at FROM principals WHERE principal_id = ?",
                (principal_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            record = PrincipalRecord(
                principal_id=row["principal_id"],
                principal_type=row["principal_type"],
                tenant_id=row["tenant_id"],
                roles=tuple(json.loads(row["roles"])),
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

            if caller_context and not caller_context.can_access_tenant(record.tenant_id):
                # Safe 404 to avoid leaking cross-tenant existence
                return None

            return record
        finally:
            conn.close()

    def list_principals(
        self,
        caller_context: Optional[RequestSecurityContext] = None,
        tenant_id: Optional[str] = None,
    ) -> List[PrincipalRecord]:
        """
        Lists principals scoped by tenant permissions.
        """
        target_tenant = tenant_id
        if caller_context and not caller_context.global_admin:
            target_tenant = caller_context.tenant_id

        conn = self._get_connection()
        try:
            if target_tenant:
                cur = conn.execute(
                    "SELECT principal_id, principal_type, tenant_id, roles, status, created_at, updated_at FROM principals WHERE tenant_id = ? ORDER BY created_at ASC",
                    (target_tenant,),
                )
            else:
                cur = conn.execute(
                    "SELECT principal_id, principal_type, tenant_id, roles, status, created_at, updated_at FROM principals ORDER BY created_at ASC"
                )

            rows = cur.fetchall()
            return [
                PrincipalRecord(
                    principal_id=r["principal_id"],
                    principal_type=r["principal_type"],
                    tenant_id=r["tenant_id"],
                    roles=tuple(json.loads(r["roles"])),
                    status=r["status"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def create_principal(
        self,
        principal_id: str,
        principal_type: str = "user",
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        caller_context: Optional[RequestSecurityContext] = None,
        created_by: Optional[str] = None,
    ) -> PrincipalRecord:
        """
        Creates a new principal with strict RBAC privilege checks:
        - Only admin or global_admin can create principals.
        - Tenant admins can only create principals within their own tenant.
        - Tenant admins CANNOT grant roles they do not hold (e.g. global_admin).
        - Normal users CANNOT create principals.
        """
        pid = principal_id.strip() if principal_id else ""
        if not pid or len(pid) > 64:
            raise PrincipalError("Principal ID must be between 1 and 64 characters.", code="INVALID_PRINCIPAL_ID")

        ptype = principal_type.lower().strip()
        if ptype not in VALID_PRINCIPAL_TYPES:
            raise PrincipalError(f"Invalid principal type '{ptype}'. Permitted: {sorted(VALID_PRINCIPAL_TYPES)}")

        assigned_roles = [r.lower().strip() for r in (roles or ["user"])]
        for r in assigned_roles:
            if r not in VALID_ROLES:
                raise PrincipalError(f"Invalid role '{r}'. Permitted: {sorted(VALID_ROLES)}")

        target_tenant = tenant_id or (caller_context.tenant_id if caller_context else DEFAULT_TENANT)

        # RBAC and escalation checks
        if caller_context:
            if not (caller_context.has_role("admin") or caller_context.global_admin):
                raise PrivilegeEscalationError("Only administrators can create principals.")

            # Cross-tenant check
            if not caller_context.can_access_tenant(target_tenant):
                raise PrivilegeEscalationError("Cannot create principal for another tenant.")

            # Cannot create global_admin without global_admin authority
            if "global_admin" in assigned_roles or ptype == "global_admin":
                if not caller_context.global_admin:
                    raise PrivilegeEscalationError("Only global administrators can assign global_admin role.")

        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute("SELECT principal_id FROM principals WHERE principal_id = ?", (pid,))
                    if cur.fetchone():
                        raise PrincipalConflictError(f"Principal '{pid}' already exists.")

                    conn.execute(
                        """
                        INSERT INTO principals (principal_id, principal_type, tenant_id, roles, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)
                        """,
                        (pid, ptype, target_tenant, json.dumps(assigned_roles), now, now),
                    )
                return PrincipalRecord(
                    principal_id=pid,
                    principal_type=ptype,
                    tenant_id=target_tenant,
                    roles=tuple(assigned_roles),
                    status="ACTIVE",
                    created_at=now,
                    updated_at=now,
                )
            finally:
                conn.close()

    def update_principal(
        self,
        principal_id: str,
        principal_type: Optional[str] = None,
        roles: Optional[List[str]] = None,
        status: Optional[str] = None,
        caller_context: Optional[RequestSecurityContext] = None,
    ) -> PrincipalRecord:
        """
        Updates principal metadata.
        Guarantees:
        - Self-promotion / privilege escalation is blocked.
        - Tenant reassignment is forbidden.
        - Disabling the final active administrator is blocked.
        """
        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        "SELECT principal_id, principal_type, tenant_id, roles, status, created_at FROM principals WHERE principal_id = ?",
                        (principal_id,),
                    )
                    row = cur.fetchone()
                    if not row:
                        raise PrincipalNotFoundError(f"Principal '{principal_id}' not found.")

                    existing_tenant = row["tenant_id"]
                    existing_roles = json.loads(row["roles"])
                    existing_type = row["principal_type"]
                    existing_status = row["status"]

                    if caller_context:
                        # Cross-tenant check
                        if not caller_context.can_access_tenant(existing_tenant):
                            raise PrincipalNotFoundError(f"Principal '{principal_id}' not found.")

                        # Must be admin
                        if not (caller_context.has_role("admin") or caller_context.global_admin):
                            raise PrivilegeEscalationError("Only administrators can update principals.")

                        # Self-promotion check
                        if caller_context.principal_id == principal_id and roles is not None:
                            if set(roles) != set(existing_roles):
                                raise PrivilegeEscalationError("Principals cannot modify their own roles.")

                        # Cannot grant global_admin without global_admin authority
                        if roles is not None and "global_admin" in roles and not caller_context.global_admin:
                            raise PrivilegeEscalationError("Only global administrators can assign global_admin role.")

                    new_type = existing_type
                    if principal_type:
                        ptype = principal_type.lower().strip()
                        if ptype not in VALID_PRINCIPAL_TYPES:
                            raise PrincipalError(f"Invalid principal type '{ptype}'. Permitted: {sorted(VALID_PRINCIPAL_TYPES)}")
                        new_type = ptype

                    new_roles = existing_roles
                    if roles is not None:
                        sanitized_roles = [r.lower().strip() for r in roles]
                        for r in sanitized_roles:
                            if r not in VALID_ROLES:
                                raise PrincipalError(f"Invalid role '{r}'. Permitted: {sorted(VALID_ROLES)}")
                        new_roles = sanitized_roles

                    new_status = existing_status
                    if status is not None:
                        st = status.upper().strip()
                        if st not in VALID_STATUSES:
                            raise PrincipalError(f"Invalid status '{st}'. Permitted: {sorted(VALID_STATUSES)}")
                        
                        # Safety check: Prevent disabling the final active administrator in the tenant
                        if st == "DISABLED" and ("admin" in existing_roles or "global_admin" in existing_roles):
                            cur = conn.execute(
                                "SELECT COUNT(*) as active_admins FROM principals WHERE status = 'ACTIVE' AND tenant_id = ? AND (roles LIKE '%\"admin\"%' OR roles LIKE '%\"global_admin\"%') AND principal_id != ?",
                                (existing_tenant, principal_id),
                            )
                            active_admins = cur.fetchone()["active_admins"]
                            if active_admins == 0:
                                raise PrincipalError(
                                    "Cannot disable the final active administrator in the tenant.",
                                    code="FINAL_ADMIN_PROTECTION",
                                    status_code=400,
                                )
                        new_status = st

                    conn.execute(
                        """
                        UPDATE principals
                        SET principal_type = ?, roles = ?, status = ?, updated_at = ?
                        WHERE principal_id = ?
                        """,
                        (new_type, json.dumps(new_roles), new_status, now, principal_id),
                    )

                    return PrincipalRecord(
                        principal_id=principal_id,
                        principal_type=new_type,
                        tenant_id=existing_tenant,
                        roles=tuple(new_roles),
                        status=new_status,
                        created_at=row["created_at"],
                        updated_at=now,
                    )
            finally:
                conn.close()

    def disable_principal(self, principal_id: str, caller_context: Optional[RequestSecurityContext] = None) -> PrincipalRecord:
        return self.update_principal(principal_id=principal_id, status="DISABLED", caller_context=caller_context)

    def enable_principal(self, principal_id: str, caller_context: Optional[RequestSecurityContext] = None) -> PrincipalRecord:
        return self.update_principal(principal_id=principal_id, status="ACTIVE", caller_context=caller_context)

    def is_healthy(self) -> bool:
        """Verifies principals database accessibility and integrity."""
        try:
            conn = self._get_connection()
            try:
                healthy, _ = check_database_integrity(conn)
                if not healthy:
                    return False
                cur = conn.execute("SELECT COUNT(*) FROM principals")
                cur.fetchone()
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def reset_for_testing(self):
        """Resets principals table to defaults for testing."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM principals")
                    self._seed_default_principals(conn)
            finally:
                conn.close()


principal_service = PrincipalService()
