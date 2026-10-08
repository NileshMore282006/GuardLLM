"""
AgentGuard Authentication Service (Backend v0.8)
Extracts, verifies, and binds cryptographically random Bearer credentials into trusted
server-side RequestSecurityContext objects.

SECURITY INVARIANTS:
1. AUTHENTICATION -> IDENTITY -> TENANT -> AUTHORIZATION
2. Client-supplied headers (X-AgentGuard-Role, X-AgentGuard-Tenant, X-AgentGuard-Principal)
   are STRICTLY DISREGARDED when credentials are used.
3. Disabled credentials, disabled principals, or disabled tenants strictly fail closed.
4. Secrets, bearer tokens, and hashes are NEVER logged or included in audit trails.
5. Consistent error codes (AUTHENTICATION_REQUIRED, INVALID_CREDENTIAL, CREDENTIAL_REVOKED,
   CREDENTIAL_EXPIRED, CREDENTIAL_DISABLED, PRINCIPAL_DISABLED, TENANT_DISABLED).
"""

import logging
from typing import Optional
from fastapi import Request

from backend.config import (
    AUTH_ENABLED,
    DEFAULT_PRINCIPAL,
    DEFAULT_TENANT,
    IDENTITY_ENABLED,
    LEGACY_IDENTITY_ENABLED,
)
from backend.services.audit_service import audit_service
from backend.services.credential_service import (
    CredentialDisabledError,
    CredentialError,
    CredentialExpiredError,
    CredentialRevokedError,
    InvalidCredentialError,
    credential_service,
)
from backend.services.identity_service import (
    AuthenticationRequiredError,
    IdentityError,
    InvalidPrincipalError,
    PrincipalDisabledError,
    identity_registry,
)
from backend.services.principal_service import principal_service
from backend.services.request_context import RequestSecurityContext
from backend.services.tenant_service import TenantDisabledError, tenant_service

logger = logging.getLogger("agentguard.auth")

# Headers monitored for spoofing attempts
HEADER_ROLE_ATTEMPT = "x-agentguard-role"
HEADER_TENANT_ATTEMPT = "x-agentguard-tenant"
HEADER_PRINCIPAL_ATTEMPT = "x-agentguard-principal"


def extract_bearer_token(request: Request) -> Optional[str]:
    """
    Extracts Bearer token from HTTP Authorization header.
    Format: 'Authorization: Bearer <token>'
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return None

    parts = auth_header.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def authenticate_request(
    request: Request,
    require_auth: Optional[bool] = None,
) -> RequestSecurityContext:
    """
    Authenticates an incoming request and returns a trusted RequestSecurityContext.
    
    Order of precedence:
    1. Authorization: Bearer <credential> (Preferred, cryptographically verifiable)
    2. Legacy development identity (X-AgentGuard-Principal) ONLY IF enabled by configuration.
    3. Default development context when auth is disabled.
    """
    request_id = getattr(request.state, "request_id", "req-unknown")
    bearer_token = extract_bearer_token(request)

    # Detect header spoofing attempts
    attempted_role = request.headers.get(HEADER_ROLE_ATTEMPT)
    attempted_tenant = request.headers.get(HEADER_TENANT_ATTEMPT)
    attempted_principal = request.headers.get(HEADER_PRINCIPAL_ATTEMPT)

    if attempted_role or attempted_tenant:
        logger.warning(
            "Security alert: Client attempted header spoofing (role='%s', tenant='%s'). Disregarding untrusted headers.",
            attempted_role,
            attempted_tenant,
        )

    # -------------------------------------------------------------
    # Case 1: Bearer token is provided -> Cryptographic verification
    # -------------------------------------------------------------
    if bearer_token is not None:
        try:
            # Step A: Verify credential secret and state
            cred_record, cred_id = credential_service.verify_and_authenticate(bearer_token)

            # Step B: Resolve principal and check active status
            principal = principal_service.get_principal(cred_record.principal_id)
            if not principal:
                logger.warning("Auth failure: Principal '%s' not found for valid credential", cred_record.principal_id)
                audit_service.log_event(
                    action="auth_failure",
                    request_id=request_id,
                    principal_id=cred_record.principal_id,
                    error_code="INVALID_PRINCIPAL",
                    decision="BLOCK",
                )
                raise InvalidPrincipalError(f"Principal '{cred_record.principal_id}' not found.")

            if not principal.is_active():
                logger.warning("Auth failure: Principal '%s' is disabled", cred_record.principal_id)
                audit_service.log_event(
                    action="auth_failure",
                    request_id=request_id,
                    principal_id=cred_record.principal_id,
                    error_code="PRINCIPAL_DISABLED",
                    decision="BLOCK",
                )
                raise PrincipalDisabledError(f"Principal '{cred_record.principal_id}' is disabled.")

            # Step C: Resolve tenant and check active status
            tenant = tenant_service.get_tenant(cred_record.tenant_id)
            if not tenant or not tenant.is_active():
                logger.warning("Auth failure: Tenant '%s' is disabled or missing", cred_record.tenant_id)
                audit_service.log_event(
                    action="auth_failure",
                    request_id=request_id,
                    principal_id=cred_record.principal_id,
                    error_code="TENANT_DISABLED",
                    decision="BLOCK",
                )
                raise TenantDisabledError(f"Tenant '{cred_record.tenant_id}' is disabled.")

            # Step D: Construct trusted RequestSecurityContext
            is_global_admin = principal.has_role("global_admin") or "global_admin" in principal.roles
            ctx = RequestSecurityContext(
                request_id=request_id,
                principal_id=principal.principal_id,
                principal_type=principal.principal_type,
                roles=principal.roles,
                tenant_id=cred_record.tenant_id,
                credential_id=cred_id,
                global_admin=is_global_admin,
            )

            # Step E: Log safe audit success (NO token, NO secret, NO hash)
            audit_service.log_event(
                action="auth_success",
                request_id=request_id,
                principal_id=principal.principal_id,
                principal_type=principal.principal_type,
                resource_type="credential",
                resource_id=cred_id,
                decision="ALLOW",
            )
            return ctx

        except (CredentialError, IdentityError, TenantDisabledError) as exc:
            audit_service.log_event(
                action="auth_failure",
                request_id=request_id,
                error_code=exc.code,
                decision="BLOCK",
            )
            raise

    # -------------------------------------------------------------
    # Case 2: Bearer token is ABSENT
    # -------------------------------------------------------------
    should_enforce = AUTH_ENABLED if require_auth is None else require_auth

    # If enforcement is active and legacy fallback is permitted
    if should_enforce:
        if LEGACY_IDENTITY_ENABLED and attempted_principal:
            logger.info("Using legacy development identity fallback for '%s'", attempted_principal)
            p = identity_registry.get_principal(attempted_principal.strip())
            if not p:
                raise InvalidPrincipalError(f"Legacy principal '{attempted_principal}' not recognized.")
            if not p.active:
                raise PrincipalDisabledError(f"Legacy principal '{attempted_principal}' is disabled.")

            return RequestSecurityContext(
                request_id=request_id,
                principal_id=p.principal_id,
                principal_type=p.principal_type,
                roles=p.roles,
                tenant_id=p.tenant_id,
                credential_id=None,
                global_admin=("admin" in p.roles and p.principal_id == "global-admin-demo"),
            )

        # Authentication is required but missing
        logger.warning("Authentication required: Missing Authorization Bearer credential.")
        audit_service.log_event(
            action="auth_failure",
            request_id=request_id,
            error_code="AUTHENTICATION_REQUIRED",
            decision="BLOCK",
        )
        raise AuthenticationRequiredError("Authentication required. Missing Bearer credential.")

    # -------------------------------------------------------------
    # Case 3: Auth is not strictly enforced -> Compatibility fallback
    # -------------------------------------------------------------
    # Check if legacy v0.7 development identity was requested
    if attempted_principal:
        p = identity_registry.get_principal(attempted_principal.strip())
        if p and p.active:
            return RequestSecurityContext(
                request_id=request_id,
                principal_id=p.principal_id,
                principal_type=p.principal_type,
                roles=p.roles,
                tenant_id=p.tenant_id,
                credential_id=None,
                global_admin=("admin" in p.roles and p.principal_id == "global-admin-demo"),
            )
        elif p and not p.active:
            raise PrincipalDisabledError(f"Principal '{attempted_principal}' is disabled.")
        elif IDENTITY_ENABLED:
            raise InvalidPrincipalError(f"Principal '{attempted_principal}' is not recognized.")

    # Final fallback for v0.1 - v0.6 backwards compatibility tests
    return RequestSecurityContext(
        request_id=request_id,
        principal_id=DEFAULT_PRINCIPAL,
        principal_type="user",
        roles=("user",),
        tenant_id=DEFAULT_TENANT,
        credential_id=None,
        global_admin=False,
    )
