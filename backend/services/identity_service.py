"""
AgentGuard Identity Service (Backend v0.7)
Local and development-only identity/principal abstraction.

LIMITATION & SCOPE NOTICE:
This v0.7 identity system is development/local identity only and is NOT
production authentication. It does NOT integrate with OAuth, OIDC, JWT, SAML,
or external identity providers.

Responsibilities:
1. Resolves principal metadata from the development header 'X-AgentGuard-Principal'.
2. Validates principal existence against local registry using constant-time comparison.
3. Disregards and rejects client-supplied role headers (e.g. 'X-AgentGuard-Role') to prevent
   privilege self-assignment.
4. Enforces immutable principal records and active/disabled states.
5. Provides fallback to configured default development principal when identity is disabled.
"""

import hmac
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from fastapi import Request

from backend.config import DEFAULT_PRINCIPAL, IDENTITY_ENABLED

logger = logging.getLogger("agentguard.identity")

# Canonical development header names
HEADER_PRINCIPAL = "x-agentguard-principal"
HEADER_ROLE_ATTEMPT = "x-agentguard-role"


class IdentityError(Exception):
    """Base exception for identity resolution errors."""
    def __init__(self, code: str, message: str, status_code: int = 401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class AuthenticationRequiredError(IdentityError):
    """Raised when authentication is required but no principal was supplied."""
    def __init__(self, message: str = "Authentication required. Missing principal header."):
        super().__init__(code="AUTHENTICATION_REQUIRED", message=message, status_code=401)


class InvalidPrincipalError(IdentityError):
    """Raised when the supplied principal is unknown or malformed."""
    def __init__(self, message: str = "Invalid principal identifier."):
        super().__init__(code="INVALID_PRINCIPAL", message=message, status_code=401)


class PrincipalDisabledError(IdentityError):
    """Raised when the principal is disabled or inactive."""
    def __init__(self, message: str = "Principal account is disabled."):
        super().__init__(code="PRINCIPAL_DISABLED", message=message, status_code=403)


@dataclass(frozen=True)
class Principal:
    """
    Immutable representation of an authenticated security principal.
    Roles and identity cannot be modified once resolved.
    """
    principal_id: str
    principal_type: str  # 'user', 'service', 'admin'
    roles: tuple = field(default_factory=tuple)  # e.g. ('user',), ('operator',), ('admin',)
    tenant_id: str = "default"
    active: bool = True

    def has_role(self, role: str) -> bool:
        """Checks if principal has the specified role."""
        return role in self.roles

    def has_any_role(self, roles: List[str]) -> bool:
        """Checks if principal has any of the specified roles."""
        return any(r in self.roles for r in roles)


class IdentityRegistry:
    """
    In-memory registry of configured local development principals.
    Thread-safe and deterministic.
    """

    def __init__(self):
        self._principals: Dict[str, Principal] = {}
        self._initialize_default_principals()

    def _initialize_default_principals(self):
        """Populates default local development principals."""
        self._principals = {
            "user-demo": Principal(
                principal_id="user-demo",
                principal_type="user",
                roles=("user",),
                tenant_id="default",
                active=True,
            ),
            "operator-demo": Principal(
                principal_id="operator-demo",
                principal_type="user",
                roles=("operator",),
                tenant_id="default",
                active=True,
            ),
            "admin-demo": Principal(
                principal_id="admin-demo",
                principal_type="admin",
                roles=("admin",),
                tenant_id="default",
                active=True,
            ),
            "service-demo": Principal(
                principal_id="service-demo",
                principal_type="service",
                roles=("operator",),
                tenant_id="default",
                active=True,
            ),
            "disabled-demo": Principal(
                principal_id="disabled-demo",
                principal_type="user",
                roles=("user",),
                tenant_id="default",
                active=False,
            ),
        }

    def register_principal(self, principal: Principal) -> None:
        """Registers or updates a development principal."""
        self._principals[principal.principal_id] = principal

    def get_principal(self, principal_id: str) -> Optional[Principal]:
        """
        Retrieves principal using constant-time string comparison across configured keys
        to prevent timing enumeration.
        """
        matched_principal: Optional[Principal] = None
        for pid, principal in self._principals.items():
            if hmac.compare_digest(pid, principal_id):
                matched_principal = principal
        return matched_principal

    def reset(self):
        """Resets registry to default development principals."""
        self._initialize_default_principals()


# Singleton identity registry instance
identity_registry = IdentityRegistry()


def resolve_principal(
    request: Optional[Request] = None,
    principal_id: Optional[str] = None,
    require_auth: Optional[bool] = None,
) -> Principal:
    """
    Resolves the principal for the current execution context.
    
    1. Extracts 'X-AgentGuard-Principal' from request headers if available.
    2. Explicitly rejects and warns if the client tried to send 'X-AgentGuard-Role'.
    3. If identity header is present, validates against registry.
    4. If identity header is absent:
       - If IDENTITY_ENABLED or require_auth: raises AuthenticationRequiredError.
       - Otherwise: returns DEFAULT_PRINCIPAL ('user-demo').
    """
    should_enforce = IDENTITY_ENABLED if require_auth is None else require_auth
    extracted_id: Optional[str] = principal_id

    if request is not None:
        # Check if request has an authenticated security context from Bearer token
        ctx = getattr(request.state, "context", None) or getattr(request.state, "principal", None)
        if ctx is not None and getattr(ctx, "credential_id", None):
            return ctx

        # Check for privilege self-assignment attack attempt
        if HEADER_ROLE_ATTEMPT in request.headers:
            attempted_role = request.headers.get(HEADER_ROLE_ATTEMPT)
            logger.warning(
                "Security alert: Client attempted self-assigned role via '%s: %s'. Ignoring untrusted header.",
                HEADER_ROLE_ATTEMPT,
                attempted_role,
            )

        header_val = request.headers.get(HEADER_PRINCIPAL)
        if header_val is not None:
            extracted_id = header_val.strip()

    # Case A: An explicit principal ID was provided (in header or argument)
    if extracted_id is not None and extracted_id != "":
        principal = identity_registry.get_principal(extracted_id)
        if principal is None:
            logger.warning("Authentication failed: Unknown principal_id='%s'", extracted_id)
            raise InvalidPrincipalError(f"Principal '{extracted_id}' is not recognized.")

        if not principal.active:
            logger.warning("Authentication failed: Disabled principal_id='%s'", extracted_id)
            raise PrincipalDisabledError(f"Principal '{extracted_id}' is disabled.")

        return principal

    # Case B: No principal header was provided
    if should_enforce:
        logger.warning("Authentication required: Missing '%s' header.", HEADER_PRINCIPAL)
        raise AuthenticationRequiredError(f"Authentication required. Missing '{HEADER_PRINCIPAL}' header.")

    # Case C: Identity enforcement is off -> fallback to default development principal
    default_p = identity_registry.get_principal(DEFAULT_PRINCIPAL)
    if default_p is None:
        default_p = Principal(
            principal_id=DEFAULT_PRINCIPAL,
            principal_type="user",
            roles=("user",),
            tenant_id="default",
            active=True,
        )
    return default_p


def require_authenticated(request: Request) -> Principal:
    """
    Dependency helper to require an authenticated, active principal.
    Always enforces identity check regardless of global IDENTITY_ENABLED.
    """
    return resolve_principal(request=request, require_auth=True)


def require_role(principal: Principal, allowed_roles: List[str]) -> None:
    """
    Helper function to verify that the principal has at least one of the required roles.
    Raises ForbiddenError (from authorization_service) if unprivileged.
    """
    from backend.services.authorization_service import ForbiddenError

    if not principal.has_any_role(allowed_roles):
        logger.warning(
            "Authorization rejected: principal=%s with roles=%s lacks required roles=%s",
            principal.principal_id,
            principal.roles,
            allowed_roles,
        )
        raise ForbiddenError(
            f"Principal '{principal.principal_id}' does not have sufficient permissions. Required roles: {allowed_roles}"
        )
