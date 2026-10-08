"""
AgentGuard Authorization Service (Backend v0.7)
Deterministic Role-Based Access Control (RBAC) layer.

IMPORTANT INVARIANTS:
1. Authorization is strictly deterministic.
2. The Guard LLM is NEVER consulted for authorization decisions.
3. Model output, user prompt text, and tool arguments can NEVER grant privileges.
4. Unknown roles, actions, or capabilities strictly fail closed (FORBIDDEN).
"""

import logging
from typing import Any, List, Optional, Set

from backend.services.identity_service import Principal

logger = logging.getLogger("agentguard.authorization")


class ForbiddenError(Exception):
    """Raised when an authenticated principal attempts an unauthorized action."""
    def __init__(self, message: str = "Access denied. Insufficient privileges.", code: str = "FORBIDDEN"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = 403


# Capability definitions mapped to permitted roles
ROLE_CAPABILITIES = {
    # Guard and target execution
    "guard:evaluate": {"user", "operator", "admin", "global_admin"},
    "guard:submit": {"user", "operator", "admin", "global_admin"},
    "target:execute": {"user", "operator", "admin", "global_admin"},
    "chat:execute": {"user", "operator", "admin", "global_admin"},
    "tool:execute": {"user", "operator", "admin", "global_admin"},
    "execute:low_risk": {"user", "operator", "admin", "global_admin"},
    
    # Approval capabilities
    "approval:create": {"user", "operator", "admin", "global_admin"},
    "approval:read_own": {"user", "operator", "admin", "global_admin"},
    "approval:inspect_own": {"user", "operator", "admin", "global_admin"},
    "approval:read_all": {"operator", "admin", "global_admin"},
    "approval:inspect_all": {"operator", "admin", "global_admin"},
    "approval:approve": {"operator", "admin", "global_admin"},
    "approval:deny": {"operator", "admin", "global_admin"},
    
    # Policy capabilities
    "policy:read": {"operator", "admin", "global_admin"},
    "policy:create": {"admin", "global_admin"},
    "policy:update": {"admin", "global_admin"},
    "policy:delete": {"admin", "global_admin"},
    "policy:admin": {"admin", "global_admin"},
    
    # Audit capabilities
    "audit:read_own": {"user", "operator", "admin", "global_admin"},
    "audit:read_all": {"operator", "admin", "global_admin"},
    "audit:verify": {"admin", "global_admin"},

    # Credential capabilities (v0.8)
    "credential:create": {"admin", "global_admin"},
    "credential:read_own": {"user", "operator", "admin", "global_admin"},
    "credential:read_all": {"admin", "global_admin"},
    "credential:revoke": {"admin", "global_admin"},
    "credential:rotate": {"admin", "global_admin"},

    # Principal capabilities (v0.8)
    "principal:create": {"admin", "global_admin"},
    "principal:read": {"admin", "global_admin"},
    "principal:update": {"admin", "global_admin"},
    "principal:disable": {"admin", "global_admin"},
    "principal:enable": {"admin", "global_admin"},

    # Tenant capabilities (v0.8 - Global admin restricted)
    "tenant:create": {"global_admin"},
    "tenant:read": {"admin", "global_admin"},
    "tenant:update": {"global_admin"},
    "tenant:disable": {"global_admin"},
    "tenant:enable": {"global_admin"},
    "tenant:admin": {"global_admin"},
}


def check_permission(
    principal: Any,
    action: str,
    resource_type: Optional[str] = None,
    resource_owner: Optional[str] = None,
    target_principal_id: Optional[str] = None,
) -> bool:
    """
    Evaluates whether the principal is authorized to perform the action.
    
    Ownership-aware authorization:
    - Global administrator has authority over all tenant resources and actions.
    - If action requires reading own resource (e.g. approval, audit, credential), verifies
      either principal has 'admin'/'operator' role or is the resource owner.
    - If action has no permitted roles or is unknown, fails closed (returns False).
    """
    # Active status check
    if hasattr(principal, "active") and not principal.active:
        return False
    if hasattr(principal, "is_active") and not principal.is_active():
        return False

    # Global admin authority bypasses tenant-scoped restrictions
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    if is_global_admin:
        return True

    owner = resource_owner or target_principal_id

    allowed_roles = ROLE_CAPABILITIES.get(action)
    if allowed_roles is None:
        logger.warning("Authorization rejected: Unknown capability action='%s'", action)
        return False

    # Check if principal roles intersect with allowed roles
    p_roles = getattr(principal, "roles", ())
    has_role_match = any(role in allowed_roles for role in p_roles)
    if not has_role_match:
        return False

    # Ownership checks for scoped actions
    if action in ("approval:read_own", "approval:inspect_own", "audit:read_own", "credential:read_own"):
        if any(r in p_roles for r in ("admin", "operator", "global_admin")):
            return True
        if owner is not None and owner != getattr(principal, "principal_id", None):
            logger.warning(
                "Ownership check failed: principal='%s' attempted to access resource owned by '%s'",
                getattr(principal, "principal_id", "unknown"),
                owner,
            )
            return False

    return True


def enforce_permission(
    principal: Principal,
    action: str,
    resource_type: Optional[str] = None,
    resource_owner: Optional[str] = None,
    target_principal_id: Optional[str] = None,
) -> None:
    """
    Asserts that the principal is authorized to perform the action.
    Raises ForbiddenError (HTTP 403) if authorization fails.
    """
    if not check_permission(
        principal,
        action,
        resource_type=resource_type,
        resource_owner=resource_owner,
        target_principal_id=target_principal_id,
    ):
        logger.warning(
            "Authorization DENIED: principal='%s' roles=%s action='%s' resource_type=%s owner=%s",
            principal.principal_id,
            principal.roles,
            action,
            resource_type,
            resource_owner,
        )
        raise ForbiddenError(
            f"Principal '{principal.principal_id}' is not authorized to perform action '{action}'."
        )


require_permission = enforce_permission


def require_role(principal: Any, allowed_roles: List[str]) -> None:
    """
    Requires the principal to have at least one of the specified allowed roles.
    Raises ForbiddenError if principal lacks all allowed roles.
    """
    if getattr(principal, "global_admin", False) or (hasattr(principal, "has_role") and principal.has_role("global_admin")):
        return

    if hasattr(principal, "active") and not principal.active:
        raise ForbiddenError(f"Principal '{principal.principal_id}' is disabled.")
    if hasattr(principal, "is_active") and not principal.is_active():
        raise ForbiddenError(f"Principal '{principal.principal_id}' is disabled.")

    if not any(principal.has_role(role) for role in allowed_roles):
        raise ForbiddenError(
            f"Principal '{getattr(principal, 'principal_id', 'unknown')}' lacks required role (requires one of: {allowed_roles})."
        )

