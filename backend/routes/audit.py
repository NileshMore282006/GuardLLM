"""
Audit API Routes (Backend v0.7)
Endpoints for querying persistent security audit events and verifying chain integrity.

RBAC ACCESS RULES:
- admin: view all events, verify audit chain
- operator: view all events
- user: view ONLY their own events (ownership-scoped)
"""

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from backend.schemas import (
    AuditEventResponse,
    AuditListResponse,
    AuditVerifyResponse,
)
from backend.services.audit_service import audit_service
from backend.services.identity_service import Principal, require_role, resolve_principal

logger = logging.getLogger("agentguard.audit_route")

router = APIRouter(prefix="/api/v1/audit", tags=["Security Audit"])


def get_current_principal(request: Request) -> Any:
    """Dependency helper to resolve request principal or security context."""
    ctx = getattr(request.state, "context", None) or getattr(request.state, "principal", None)
    if ctx is not None:
        return ctx
    return resolve_principal(request=request)


@router.get(
    "/events",
    response_model=AuditListResponse,
    status_code=status.HTTP_200_OK,
    summary="Query security audit events",
    description=(
        "Retrieves chained audit events with safe metadata. "
        "Admins and operators can inspect events within their bound tenant; global admins can inspect across tenants; users can only inspect their own."
    ),
    responses={
        200: {"model": AuditListResponse},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Access denied to requested scope."},
    },
)
def query_audit_events_endpoint(
    request: Request,
    request_id: Optional[str] = Query(None, description="Filter by correlation request ID"),
    principal_id: Optional[str] = Query(None, description="Filter by principal ID (Admin/Operator only)"),
    tenant_id: Optional[str] = Query(None, description="Filter by tenant ID (Global Admin only)"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    decision: Optional[str] = Query(None, description="Filter by decision (ALLOW, BLOCK, etc.)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    start_time: Optional[float] = Query(None, description="Filter by minimum timestamp"),
    end_time: Optional[float] = Query(None, description="Filter by maximum timestamp"),
    limit: int = Query(50, ge=1, le=100, description="Page limit (max 100)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    principal: Any = Depends(get_current_principal),
) -> AuditListResponse:
    """Queries audit events with tenant isolation and ownership enforcement."""
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )

    # Client-supplied tenant_id CANNOT override the caller's tenant
    caller_tenant = getattr(principal, "tenant_id", "default")
    if not is_global_admin and tenant_id is not None and tenant_id != caller_tenant:
        logger.warning(
            "Tenant isolation violation: principal='%s' attempted to query audit events for tenant='%s'",
            getattr(principal, "principal_id", "unknown"),
            tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "TENANT_ACCESS_DENIED",
                "message": "Cannot query audit events outside your assigned tenant.",
            },
        )

    # If a normal user attempts to filter for another user's events, enforce ownership
    has_admin_or_op = False
    if hasattr(principal, "has_role"):
        has_admin_or_op = principal.has_role("admin") or principal.has_role("operator") or is_global_admin
    elif hasattr(principal, "roles"):
        has_admin_or_op = any(r in ("admin", "operator", "global_admin") for r in principal.roles)

    if not has_admin_or_op:
        p_id = getattr(principal, "principal_id", None)
        if principal_id is not None and principal_id != p_id:
            logger.warning(
                "Ownership check failed: principal='%s' attempted to query audit events for principal='%s'",
                p_id,
                principal_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "AUDIT_ACCESS_DENIED",
                    "message": "Users are only permitted to inspect their own security audit events.",
                },
            )

    rows, total = audit_service.query_events(
        principal=principal,
        request_id=request_id,
        principal_id=principal_id,
        tenant_id=tenant_id if is_global_admin else caller_tenant,
        action=action,
        decision=decision,
        resource_type=resource_type,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )

    return AuditListResponse(
        events=[AuditEventResponse(**row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/verify",
    response_model=AuditVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify audit log hash chain cryptographic integrity (Admin only)",
    description="Verifies the SHA-256 hash chaining of all recorded audit events to detect tampering.",
    responses={
        200: {"model": AuditVerifyResponse},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires admin role."},
    },
)
def verify_audit_chain_endpoint(
    request: Request,
    principal: Any = Depends(get_current_principal),
) -> AuditVerifyResponse:
    """Verifies cryptographic chain integrity."""
    require_role(principal, ["admin", "global_admin"])
    result = audit_service.verify_audit_chain()
    return AuditVerifyResponse(**result)
