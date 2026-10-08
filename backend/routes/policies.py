"""
Policy Administration API Routes (Backend v0.7)
Endpoints for managing and querying security policies.

RBAC ACCESS RULES:
- admin: create, read, update, delete
- operator: read only
- user: forbidden (403 FORBIDDEN)
"""

import logging
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from backend.schemas import (
    PolicyCreateRequest,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdateRequest,
)
from backend.services.identity_service import Principal, require_role, resolve_principal
from backend.services.policy_service import (
    PolicyInvalidError,
    PolicyNotFoundError,
    policy_service,
)

logger = logging.getLogger("agentguard.policies_route")

router = APIRouter(prefix="/api/v1/policies", tags=["Policy Administration"])


def get_current_principal(request: Request) -> Any:
    """Dependency helper to resolve request principal or security context."""
    ctx = getattr(request.state, "context", None) or getattr(request.state, "principal", None)
    if ctx is not None:
        return ctx
    return resolve_principal(request=request)


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security policy (Admin only)",
    description="Registers an explicit policy rule. Requires admin privileges.",
    responses={
        201: {"model": PolicyResponse},
        400: {"description": "Invalid policy definition."},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires admin role."},
    },
)
def create_policy_endpoint(
    payload: PolicyCreateRequest,
    request: Request,
    principal: Any = Depends(get_current_principal),
) -> PolicyResponse:
    """Creates a new security policy with version 1 and tenant binding."""
    require_role(principal, ["admin", "global_admin"])
    request_id = getattr(request.state, "request_id", None)
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    target_tenant = payload.tenant_id if (is_global_admin and payload.tenant_id) else getattr(principal, "tenant_id", "default")

    try:
        policy = policy_service.create_policy(
            name=payload.name,
            description=payload.description or "",
            action=payload.action,
            principal_scope=payload.principal_scope,
            tool_scope=payload.tool_scope,
            risk_levels=payload.risk_levels,
            priority=payload.priority,
            enabled=payload.enabled,
            principal=principal,
            request_id=request_id,
            tenant_id=target_tenant,
        )
        return PolicyResponse(**policy.to_dict())
    except PolicyInvalidError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": err.code, "message": err.message},
        )


@router.get(
    "",
    response_model=PolicyListResponse,
    status_code=status.HTTP_200_OK,
    summary="List security policies (Admin or Operator)",
    description="Retrieves active and configured security policies. Requires admin or operator role.",
    responses={
        200: {"model": PolicyListResponse},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires operator or admin role."},
    },
)
def list_policies_endpoint(
    request: Request,
    include_disabled: bool = True,
    principal: Any = Depends(get_current_principal),
) -> PolicyListResponse:
    """Lists configured policies scoped by tenant."""
    require_role(principal, ["operator", "admin", "global_admin"])
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    target_tenant = None if is_global_admin else getattr(principal, "tenant_id", "default")
    policies = policy_service.list_policies(include_disabled=include_disabled, tenant_id=target_tenant)
    return PolicyListResponse(
        policies=[PolicyResponse(**p.to_dict()) for p in policies],
        total=len(policies),
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Get security policy details (Admin or Operator)",
    description="Retrieves a specific policy rule by ID. Requires admin or operator role.",
    responses={
        200: {"model": PolicyResponse},
        404: {"description": "Policy not found."},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires operator or admin role."},
    },
)
def get_policy_endpoint(
    policy_id: str,
    request: Request,
    principal: Any = Depends(get_current_principal),
) -> PolicyResponse:
    """Retrieves policy by ID with tenant isolation."""
    require_role(principal, ["operator", "admin", "global_admin"])
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    target_tenant = None if is_global_admin else getattr(principal, "tenant_id", "default")
    policy = policy_service.get_policy(policy_id, tenant_id=target_tenant)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "POLICY_NOT_FOUND", "message": f"Policy '{policy_id}' not found."},
        )
    return PolicyResponse(**policy.to_dict())


@router.put(
    "/{policy_id}",
    response_model=PolicyResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a security policy (Admin only)",
    description="Updates policy fields and increments the policy version. Requires admin role.",
    responses={
        200: {"model": PolicyResponse},
        400: {"description": "Invalid policy updates."},
        404: {"description": "Policy not found."},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires admin role."},
    },
)
def update_policy_endpoint(
    policy_id: str,
    payload: PolicyUpdateRequest,
    request: Request,
    principal: Any = Depends(get_current_principal),
) -> PolicyResponse:
    """Updates existing policy and increments version with tenant isolation."""
    require_role(principal, ["admin", "global_admin"])
    request_id = getattr(request.state, "request_id", None)
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    target_tenant = None if is_global_admin else getattr(principal, "tenant_id", "default")

    try:
        updated = policy_service.update_policy(
            policy_id=policy_id,
            name=payload.name,
            description=payload.description,
            action=payload.action,
            principal_scope=payload.principal_scope,
            tool_scope=payload.tool_scope,
            risk_levels=payload.risk_levels,
            priority=payload.priority,
            enabled=payload.enabled,
            principal=principal,
            request_id=request_id,
            tenant_id=target_tenant,
        )
        return PolicyResponse(**updated.to_dict())
    except PolicyNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": err.code, "message": err.message},
        )
    except PolicyInvalidError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": err.code, "message": err.message},
        )


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_200_OK,
    summary="Soft-delete a security policy (Admin only)",
    description="Soft-deletes a policy rule, marking it disabled while preserving audit history.",
    responses={
        200: {"description": "Policy successfully deleted."},
        404: {"description": "Policy not found."},
        401: {"description": "Authentication required or invalid principal."},
        403: {"description": "Forbidden: Requires admin role."},
    },
)
def delete_policy_endpoint(
    policy_id: str,
    request: Request,
    principal: Any = Depends(get_current_principal),
) -> dict:
    """Soft-deletes policy with tenant isolation."""
    require_role(principal, ["admin", "global_admin"])
    request_id = getattr(request.state, "request_id", None)
    is_global_admin = getattr(principal, "global_admin", False) or (
        hasattr(principal, "has_role") and principal.has_role("global_admin")
    )
    target_tenant = None if is_global_admin else getattr(principal, "tenant_id", "default")

    try:
        deleted = policy_service.delete_policy(
            policy_id,
            principal=principal,
            request_id=request_id,
            tenant_id=target_tenant,
        )
        return {
            "policy_id": policy_id,
            "status": "deleted",
            "version": deleted.version,
            "deleted": True,
            "message": f"Policy '{policy_id}' soft-deleted successfully.",
        }
    except PolicyNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": err.code, "message": err.message},
        )
