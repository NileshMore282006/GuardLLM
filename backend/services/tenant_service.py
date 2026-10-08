"""
AgentGuard Tenant Service (Backend v0.8)
Manages tenant metadata and provides strict server-side tenant isolation enforcement.

SECURITY INVARIANTS:
1. Unknown tenant status fails closed (refuses access).
2. Disabled tenants cannot accept authenticated requests or perform actions.
3. Cross-tenant administration requires GLOBAL_ADMIN privileges.
4. Tenant identification is derived solely from server-side credential/principal state,
   NEVER from client-supplied HTTP headers or bodies.
5. Parameterized SQL exclusively.
"""

import logging
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from backend.config import CREDENTIAL_DB_PATH, DEFAULT_TENANT
from backend.services.db_hardening import check_database_integrity, get_hardened_connection
from backend.services.request_context import RequestSecurityContext

logger = logging.getLogger("agentguard.tenant")

VALID_TENANT_STATUSES = {"ACTIVE", "DISABLED"}


class TenantError(Exception):
    """Base exception for tenant-related operations."""
    def __init__(self, message: str, code: str = "TENANT_ERROR", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class TenantNotFoundError(TenantError):
    """Raised when tenant is not found."""
    def __init__(self, message: str = "Tenant not found."):
        super().__init__(message=message, code="TENANT_NOT_FOUND", status_code=404)


class TenantDisabledError(TenantError):
    """Raised when tenant is disabled or inactive."""
    def __init__(self, message: str = "Tenant is disabled."):
        super().__init__(message=message, code="TENANT_DISABLED", status_code=403)


class TenantAccessDeniedError(TenantError):
    """Raised when a cross-tenant operation is unauthorized."""
    def __init__(self, message: str = "Cross-tenant access denied."):
        super().__init__(message=message, code="TENANT_ACCESS_DENIED", status_code=403)


class TenantConflictError(TenantError):
    """Raised when creating a duplicate tenant."""
    def __init__(self, message: str = "Tenant already exists."):
        super().__init__(message=message, code="TENANT_CONFLICT", status_code=409)


@dataclass
class Tenant:
    """
    Server-side representation of an isolated security tenant.
    """
    tenant_id: str
    name: str
    status: str  # 'ACTIVE', 'DISABLED'
    created_at: float
    updated_at: float

    def is_active(self) -> bool:
        return self.status == "ACTIVE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TenantService:
    """
    Thread-safe SQLite tenant service.
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
                        CREATE TABLE IF NOT EXISTS tenants (
                            tenant_id TEXT PRIMARY KEY,
                            name TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at REAL NOT NULL,
                            updated_at REAL NOT NULL
                        )
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_tenant_status ON tenants(status)")

                    # Ensure default tenant exists
                    cur = conn.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (DEFAULT_TENANT,))
                    if not cur.fetchone():
                        now = time.time()
                        conn.execute(
                            """
                            INSERT INTO tenants (tenant_id, name, status, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (DEFAULT_TENANT, "Default Tenant", "ACTIVE", now, now),
                        )
            finally:
                conn.close()

    def _seed_defaults(self):
        """Re-initializes tables and default tenant if needed."""
        self._init_db()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("UPDATE tenants SET status = 'ACTIVE' WHERE tenant_id IN ('default', 'tenant-alpha', 'tenant-beta')")
            finally:
                conn.close()

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        caller_context: Optional[RequestSecurityContext] = None,
        created_by: Optional[str] = None,
    ) -> Tenant:
        """
        Creates a new tenant. Requires global administrative authority.
        """
        if caller_context and not caller_context.global_admin:
            raise TenantAccessDeniedError("Only global administrators can create tenants.")

        tid = tenant_id.strip() if tenant_id else ""
        tname = name.strip() if name else ""

        if not tid or len(tid) > 64:
            raise TenantError("Tenant ID must be between 1 and 64 characters.", code="INVALID_TENANT_ID")
        if not tname or len(tname) > 128:
            raise TenantError("Tenant name must be between 1 and 128 characters.", code="INVALID_TENANT_NAME")

        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (tid,))
                    if cur.fetchone():
                        raise TenantConflictError(f"Tenant '{tid}' already exists.")

                    conn.execute(
                        """
                        INSERT INTO tenants (tenant_id, name, status, created_at, updated_at)
                        VALUES (?, ?, 'ACTIVE', ?, ?)
                        """,
                        (tid, tname, now, now),
                    )
                return Tenant(tenant_id=tid, name=tname, status="ACTIVE", created_at=now, updated_at=now)
            finally:
                conn.close()

    def get_tenant(self, tenant_id: str, caller_context: Optional[RequestSecurityContext] = None) -> Optional[Tenant]:
        """
        Retrieves tenant record by ID.
        Enforces tenant isolation: callers can only view their own tenant unless global admin.
        """
        if caller_context and not caller_context.can_access_tenant(tenant_id):
            raise TenantNotFoundError(f"Tenant '{tenant_id}' not found.")

        conn = self._get_connection()
        try:
            cur = conn.execute(
                "SELECT tenant_id, name, status, created_at, updated_at FROM tenants WHERE tenant_id = ?",
                (tenant_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return Tenant(
                tenant_id=row["tenant_id"],
                name=row["name"],
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
        finally:
            conn.close()

    def list_tenants(self, caller_context: Optional[RequestSecurityContext] = None) -> List[Tenant]:
        """
        Lists tenants.
        - Global admin: lists all tenants.
        - Tenant-scoped: lists only their bound tenant.
        """
        conn = self._get_connection()
        try:
            if caller_context and not caller_context.global_admin:
                cur = conn.execute(
                    "SELECT tenant_id, name, status, created_at, updated_at FROM tenants WHERE tenant_id = ?",
                    (caller_context.tenant_id,),
                )
            else:
                cur = conn.execute(
                    "SELECT tenant_id, name, status, created_at, updated_at FROM tenants ORDER BY created_at ASC"
                )

            rows = cur.fetchall()
            return [
                Tenant(
                    tenant_id=r["tenant_id"],
                    name=r["name"],
                    status=r["status"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ]
        finally:
            conn.close()

    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        status: Optional[str] = None,
        caller_context: Optional[RequestSecurityContext] = None,
    ) -> Tenant:
        """
        Updates tenant name or status.
        Only global admin may update tenant status or name.
        """
        if caller_context and not caller_context.global_admin:
            raise TenantAccessDeniedError("Only global administrators can update tenants.")

        if status is not None and status not in VALID_TENANT_STATUSES:
            raise TenantError(f"Invalid tenant status '{status}'. Valid: {sorted(VALID_TENANT_STATUSES)}")

        now = time.time()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute("SELECT tenant_id, name, status, created_at FROM tenants WHERE tenant_id = ?", (tenant_id,))
                    row = cur.fetchone()
                    if not row:
                        raise TenantNotFoundError(f"Tenant '{tenant_id}' not found.")

                    new_name = name.strip() if (name and name.strip()) else row["name"]
                    new_status = status if status is not None else row["status"]

                    conn.execute(
                        "UPDATE tenants SET name = ?, status = ?, updated_at = ? WHERE tenant_id = ?",
                        (new_name, new_status, now, tenant_id),
                    )
                    return Tenant(
                        tenant_id=tenant_id,
                        name=new_name,
                        status=new_status,
                        created_at=row["created_at"],
                        updated_at=now,
                    )
            finally:
                conn.close()

    def disable_tenant(self, tenant_id: str, caller_context: Optional[RequestSecurityContext] = None) -> Tenant:
        return self.update_tenant(tenant_id=tenant_id, status="DISABLED", caller_context=caller_context)

    def enable_tenant(self, tenant_id: str, caller_context: Optional[RequestSecurityContext] = None) -> Tenant:
        return self.update_tenant(tenant_id=tenant_id, status="ACTIVE", caller_context=caller_context)

    def is_tenant_active(self, tenant_id: str) -> bool:
        """
        Checks whether tenant exists and is ACTIVE.
        Fails closed (returns False) for unknown, disabled, or invalid tenants.
        """
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT status FROM tenants WHERE tenant_id = ?", (tenant_id,))
            row = cur.fetchone()
            if not row:
                return False
            return row["status"] == "ACTIVE"
        finally:
            conn.close()

    def enforce_tenant_isolation(
        self,
        context: RequestSecurityContext,
        resource_tenant_id: str,
        resource_name: str = "resource",
    ) -> None:
        """
        Enforces tenant isolation invariant:
        resource.tenant_id == principal.tenant_id unless principal has global_admin authority.
        """
        if context.global_admin:
            return

        if context.tenant_id != resource_tenant_id:
            logger.warning(
                "Tenant isolation VIOLATION: principal='%s' bound to tenant='%s' tried to access %s in tenant='%s'",
                context.principal_id,
                context.tenant_id,
                resource_name,
                resource_tenant_id,
            )
            # Safe 404 behavior to prevent tenant resource existence enumeration
            raise TenantNotFoundError(f"{resource_name.capitalize()} not found.")

    def is_healthy(self) -> bool:
        """Verifies tenant database accessibility and integrity."""
        try:
            conn = self._get_connection()
            try:
                healthy, _ = check_database_integrity(conn)
                if not healthy:
                    return False
                cur = conn.execute("SELECT COUNT(*) FROM tenants")
                cur.fetchone()
                return True
            finally:
                conn.close()
        except Exception:
            return False

    def reset_for_testing(self):
        """Resets tenant database for testing."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM tenants")
                    now = time.time()
                    conn.execute(
                        """
                        INSERT INTO tenants (tenant_id, name, status, created_at, updated_at)
                        VALUES (?, ?, 'ACTIVE', ?, ?)
                        """,
                        (DEFAULT_TENANT, "Default Tenant", now, now),
                    )
            finally:
                conn.close()


tenant_service = TenantService()
