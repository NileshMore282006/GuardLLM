"""
AgentGuard Request Security Context (Backend v0.8)
Represents a fully verified, immutable server-side security context for an executing request.

SECURITY INVARIANTS:
1. Downstream services MUST receive this context and NEVER trust raw HTTP headers.
2. Tenant ID is bound from authenticated credentials; clients cannot override it.
3. Roles are loaded from server-side storage; clients cannot self-promote.
4. Distinguishes global administrative authority from tenant-scoped administrative authority.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class RequestSecurityContext:
    """
    Immutable representation of the authenticated caller and their security scope.
    """
    principal_id: str
    request_id: str = "req-system"
    principal_type: str = "user"  # 'user', 'service', 'admin', 'global_admin'
    roles: Tuple[str, ...] = field(default_factory=tuple)  # e.g. ('user',), ('admin',)
    tenant_id: str = "default"
    credential_id: Optional[str] = None
    global_admin: bool = False
    authenticated_at: float = field(default_factory=time.time)
    active: bool = True

    def has_role(self, role: str) -> bool:
        """
        Checks whether context contains the role.
        Global administrators automatically fulfill tenant admin/operator/user role checks.
        """
        if self.global_admin and role in ("admin", "operator", "user"):
            return True
        return role in self.roles

    def has_any_role(self, roles: List[str]) -> bool:
        """
        Checks whether context contains at least one of the specified roles.
        """
        if self.global_admin:
            return True
        return any(r in self.roles for r in roles)

    def can_access_tenant(self, target_tenant_id: str) -> bool:
        """
        Enforces tenant isolation:
        - Global administrator can access any tenant.
        - Tenant-scoped principal can ONLY access their own bound tenant.
        """
        if self.global_admin:
            return True
        return self.tenant_id == target_tenant_id

    def to_safe_dict(self) -> dict:
        """Returns safe telemetry representation without sensitive attributes."""
        return {
            "request_id": self.request_id,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "roles": list(self.roles),
            "tenant_id": self.tenant_id,
            "credential_id": self.credential_id,
            "global_admin": self.global_admin,
            "authenticated_at": self.authenticated_at,
        }
