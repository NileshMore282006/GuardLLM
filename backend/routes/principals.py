"""
AgentGuard Principal Administration Routes (Backend v0.8)
Endpoints for creating, managing, enabling, and disabling security principals.

SECURITY INVARIANTS:
1. Only administrators may modify principal records.
2. Self-promotion and role escalation are strictly blocked.
3. Tenant reassignment is forbidden.
4. Tenant admins cannot manage principals outside their bound tenant.
5. Tenant admins cannot assign the global_admin role.
6. Disabling the final active administrator is blocked.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.schemas import (
    ErrorResponse,
    PrincipalCreateRequest,
    PrincipalListResponse,
    PrincipalResponse,
    PrincipalUpdateRequest,
)
from backend.services.audit_service import audit_service
from backend.services.authorization_service import ForbiddenError
from backend.services.principal_service import (
    PrincipalConflictError,
    PrincipalError,
    PrincipalNotFoundError,
    PrivilegeEscalationError,
    principal_service,
)
from backend.services.request_context import RequestSecurityContext

logger = logging.getLogger("agentguard.routes.principals")

router = APIRouter(
    prefix="/api/v1/principals",
    tags=["Principals"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required."},
        403: {"model": ErrorResponse, "description": "Insufficient authorization."},
        404: {"model": ErrorResponse, "description": "Principal not found."},
    },
)


def _get_context(request: Request) -> RequestSecurityContext:
    context = getattr(request.state, "context", None) or getattr(request.state, "principal", None)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return context


@router.post(
    "",
    response_model=PrincipalResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Principal",
    description="Registers a new security principal bound to a tenant.",
)
def create_principal(payload: PrincipalCreateRequest, request: Request) -> PrincipalResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can create principals.")

    try:
        record = principal_service.create_principal(
            principal_id=payload.principal_id,
            principal_type=payload.principal_type,
            tenant_id=payload.tenant_id,
            roles=payload.roles,
            caller_context=ctx,
        )
        audit_service.log_event(
            action="principal_create",
            request_id=request_id,
            principal=ctx,
            tenant_id=record.tenant_id,
            resource_type="principal",
            resource_id=record.principal_id,
            decision="ALLOW",
        )
        return PrincipalResponse(**record.to_dict())
    except PrivilegeEscalationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)
    except PrincipalConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)
    except PrincipalError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.get(
    "",
    response_model=PrincipalListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Principals",
    description="Lists principals within the caller's tenant scope (or all tenants for global admin).",
)
def list_principals(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Optional tenant filter (global admin only)"),
) -> PrincipalListResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can list principals.")

    records = principal_service.list_principals(caller_context=ctx, tenant_id=tenant_id)
    items = [PrincipalResponse(**r.to_dict()) for r in records]
    return PrincipalListResponse(principals=items, total=len(items))


@router.get(
    "/{principal_id}",
    response_model=PrincipalResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Principal",
    description="Retrieves a principal record by ID.",
)
def get_principal(principal_id: str, request: Request) -> PrincipalResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin or ctx.principal_id == principal_id):
        raise ForbiddenError("Unauthorized to view this principal.")

    record = principal_service.get_principal(principal_id, caller_context=ctx)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Principal '{principal_id}' not found.")

    return PrincipalResponse(**record.to_dict())


@router.put(
    "/{principal_id}",
    response_model=PrincipalResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Principal",
    description="Updates principal metadata, roles, or status.",
)
def update_principal(principal_id: str, payload: PrincipalUpdateRequest, request: Request) -> PrincipalResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can update principals.")

    try:
        updated = principal_service.update_principal(
            principal_id=principal_id,
            principal_type=payload.principal_type,
            roles=payload.roles,
            status=payload.status,
            caller_context=ctx,
        )
        audit_service.log_event(
            action="principal_update",
            request_id=request_id,
            principal=ctx,
            tenant_id=updated.tenant_id,
            resource_type="principal",
            resource_id=principal_id,
            decision="ALLOW",
        )
        return PrincipalResponse(**updated.to_dict())
    except PrivilegeEscalationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)
    except PrincipalNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Principal '{principal_id}' not found.")
    except PrincipalError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post(
    "/{principal_id}/disable",
    response_model=PrincipalResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable Principal",
    description="Disables a principal account immediately.",
)
def disable_principal(principal_id: str, request: Request) -> PrincipalResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can disable principals.")

    try:
        disabled = principal_service.disable_principal(principal_id, caller_context=ctx)
        audit_service.log_event(
            action="principal_disable",
            request_id=request_id,
            principal=ctx,
            tenant_id=disabled.tenant_id,
            resource_type="principal",
            resource_id=principal_id,
            decision="ALLOW",
        )
        return PrincipalResponse(**disabled.to_dict())
    except PrincipalNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Principal '{principal_id}' not found.")
    except PrincipalError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post(
    "/{principal_id}/enable",
    response_model=PrincipalResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable Principal",
    description="Enables a principal account.",
)
def enable_principal(principal_id: str, request: Request) -> PrincipalResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can enable principals.")

    try:
        enabled = principal_service.enable_principal(principal_id, caller_context=ctx)
        audit_service.log_event(
            action="principal_enable",
            request_id=request_id,
            principal=ctx,
            tenant_id=enabled.tenant_id,
            resource_type="principal",
            resource_id=principal_id,
            decision="ALLOW",
        )
        return PrincipalResponse(**enabled.to_dict())
    except PrincipalNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Principal '{principal_id}' not found.")
    except PrincipalError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
