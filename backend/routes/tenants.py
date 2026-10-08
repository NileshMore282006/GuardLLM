"""
AgentGuard Tenant Administration Routes (Backend v0.8)
Endpoints for provisioning, inspecting, enabling, and disabling isolated security tenants.

SECURITY INVARIANTS:
1. ONLY Global Administrators (GLOBAL_ADMIN) may create, update, enable, or disable tenants.
2. Tenant administrators cannot access or administer other tenants.
3. Unknown or disabled tenants fail closed.
4. Tenant isolation is enforced strictly server-side.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status

from backend.schemas import (
    ErrorResponse,
    TenantCreateRequest,
    TenantListResponse,
    TenantResponse,
    TenantUpdateRequest,
)
from backend.services.audit_service import audit_service
from backend.services.authorization_service import ForbiddenError
from backend.services.request_context import RequestSecurityContext
from backend.services.tenant_service import (
    TenantAccessDeniedError,
    TenantConflictError,
    TenantError,
    TenantNotFoundError,
    tenant_service,
)

logger = logging.getLogger("agentguard.routes.tenants")

router = APIRouter(
    prefix="/api/v1/tenants",
    tags=["Tenants"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required."},
        403: {"model": ErrorResponse, "description": "Global admin authority required."},
        404: {"model": ErrorResponse, "description": "Tenant not found."},
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
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Tenant",
    description="Provisions a new isolated tenant. Strictly restricted to Global Administrators.",
)
def create_tenant(payload: TenantCreateRequest, request: Request) -> TenantResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not ctx.global_admin:
        audit_service.log_event(
            action="authz_failure",
            request_id=request_id,
            principal=ctx,
            resource_type="tenant",
            decision="BLOCK",
            error_code="FORBIDDEN",
        )
        raise ForbiddenError("Only global administrators can create tenants.")

    try:
        tenant = tenant_service.create_tenant(
            tenant_id=payload.tenant_id,
            name=payload.name,
            caller_context=ctx,
        )
        audit_service.log_event(
            action="tenant_create",
            request_id=request_id,
            principal=ctx,
            tenant_id=tenant.tenant_id,
            resource_type="tenant",
            resource_id=tenant.tenant_id,
            decision="ALLOW",
        )
        return TenantResponse(**tenant.to_dict())
    except TenantConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)
    except TenantAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)
    except TenantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.get(
    "",
    response_model=TenantListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Tenants",
    description="Lists tenants. Global admins see all tenants; tenant-scoped principals only see their own tenant.",
)
def list_tenants(request: Request) -> TenantListResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can view tenants.")

    tenants = tenant_service.list_tenants(caller_context=ctx)
    items = [TenantResponse(**t.to_dict()) for t in tenants]
    return TenantListResponse(tenants=items, total=len(items))


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Tenant",
    description="Retrieves tenant metadata. Enforces strict tenant isolation.",
)
def get_tenant(tenant_id: str, request: Request) -> TenantResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can inspect tenants.")

    tenant = tenant_service.get_tenant(tenant_id, caller_context=ctx)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found.")

    return TenantResponse(**tenant.to_dict())


@router.put(
    "/{tenant_id}",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Tenant",
    description="Updates tenant properties. Strictly restricted to Global Administrators.",
)
def update_tenant(tenant_id: str, payload: TenantUpdateRequest, request: Request) -> TenantResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not ctx.global_admin:
        raise ForbiddenError("Only global administrators can update tenants.")

    try:
        updated = tenant_service.update_tenant(
            tenant_id=tenant_id,
            name=payload.name,
            status=payload.status,
            caller_context=ctx,
        )
        audit_service.log_event(
            action="tenant_update",
            request_id=request_id,
            principal=ctx,
            tenant_id=tenant_id,
            resource_type="tenant",
            resource_id=tenant_id,
            decision="ALLOW",
        )
        return TenantResponse(**updated.to_dict())
    except TenantNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found.")
    except TenantAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)
    except TenantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post(
    "/{tenant_id}/disable",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable Tenant",
    description="Disables a tenant. All requests for this tenant will fail closed immediately.",
)
def disable_tenant(tenant_id: str, request: Request) -> TenantResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not ctx.global_admin:
        raise ForbiddenError("Only global administrators can disable tenants.")

    try:
        disabled = tenant_service.disable_tenant(tenant_id, caller_context=ctx)
        audit_service.log_event(
            action="tenant_disable",
            request_id=request_id,
            principal=ctx,
            tenant_id=tenant_id,
            resource_type="tenant",
            resource_id=tenant_id,
            decision="ALLOW",
        )
        return TenantResponse(**disabled.to_dict())
    except TenantNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found.")
    except TenantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post(
    "/{tenant_id}/enable",
    response_model=TenantResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable Tenant",
    description="Enables a tenant.",
)
def enable_tenant(tenant_id: str, request: Request) -> TenantResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not ctx.global_admin:
        raise ForbiddenError("Only global administrators can enable tenants.")

    try:
        enabled = tenant_service.enable_tenant(tenant_id, caller_context=ctx)
        audit_service.log_event(
            action="tenant_enable",
            request_id=request_id,
            principal=ctx,
            tenant_id=tenant_id,
            resource_type="tenant",
            resource_id=tenant_id,
            decision="ALLOW",
        )
        return TenantResponse(**enabled.to_dict())
    except TenantNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found.")
    except TenantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
