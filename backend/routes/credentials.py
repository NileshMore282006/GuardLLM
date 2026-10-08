"""
AgentGuard Credential Administration Routes (Backend v0.8)
Endpoints for generating, inspecting, revoking, and rotating secure API credentials.

SECURITY INVARIANTS:
1. Only authorized administrators (or global admins) can create, revoke, or rotate credentials.
2. Tenant administrators can only manage credentials within their own bound tenant.
3. Plaintext secret is returned EXACTLY ONCE upon creation or rotation.
4. Plaintext secret is NEVER stored, NEVER logged, and NEVER returned from GET endpoints.
5. Revocation is immediate.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.schemas import (
    CredentialCreatedResponse,
    CredentialCreateRequest,
    CredentialListResponse,
    CredentialResponse,
    CredentialRotateResponse,
    ErrorResponse,
)
from backend.services.audit_service import audit_service
from backend.services.authorization_service import ForbiddenError, check_permission
from backend.services.credential_service import (
    CredentialAccessDeniedError,
    CredentialNotFoundError,
    credential_service,
)
from backend.services.request_context import RequestSecurityContext

logger = logging.getLogger("agentguard.routes.credentials")

router = APIRouter(
    prefix="/api/v1/credentials",
    tags=["Credentials"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required or invalid credential."},
        403: {"model": ErrorResponse, "description": "Insufficient authorization."},
        404: {"model": ErrorResponse, "description": "Credential not found."},
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
    response_model=CredentialCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API Credential",
    description="Generates a cryptographically random Bearer credential. The secret is returned exactly once.",
)
def create_credential(payload: CredentialCreateRequest, request: Request) -> CredentialCreatedResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        audit_service.log_event(
            action="authz_failure",
            request_id=request_id,
            principal=ctx,
            resource_type="credential",
            decision="BLOCK",
            error_code="FORBIDDEN",
        )
        raise ForbiddenError("Only administrators can create API credentials.")

    try:
        record, token = credential_service.create_credential(
            principal_id=payload.principal_id,
            tenant_id=payload.tenant_id,
            description=payload.description,
            expires_in_seconds=payload.expires_in_seconds,
            caller_context=ctx,
        )

        audit_service.log_event(
            action="credential_create",
            request_id=request_id,
            principal=ctx,
            tenant_id=record.tenant_id,
            resource_type="credential",
            resource_id=record.credential_id,
            decision="ALLOW",
        )

        return CredentialCreatedResponse(
            credential_id=record.credential_id,
            credential_secret=token,
            token=token,
            principal_id=record.principal_id,
            tenant_id=record.tenant_id,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )
    except CredentialAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)


@router.get(
    "",
    response_model=CredentialListResponse,
    status_code=status.HTTP_200_OK,
    summary="List API Credentials",
    description="Lists API credentials metadata within the caller's authorized tenant scope. Never returns secrets or hashes.",
)
def list_credentials(
    request: Request,
    principal_id: Optional[str] = Query(None, description="Optional filter by principal ID"),
) -> CredentialListResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can list credentials.")

    records = credential_service.list_credentials(
        caller_context=ctx,
        principal_id=principal_id,
    )

    safe_list = [CredentialResponse(**r.to_safe_dict()) for r in records]
    return CredentialListResponse(credentials=safe_list, total=len(safe_list))


@router.get(
    "/{credential_id}",
    response_model=CredentialResponse,
    status_code=status.HTTP_200_OK,
    summary="Get API Credential Metadata",
    description="Retrieves credential metadata without revealing secrets or hashes.",
)
def get_credential(credential_id: str, request: Request) -> CredentialResponse:
    ctx = _get_context(request)
    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can inspect credentials.")

    record = credential_service.get_credential(credential_id, caller_context=ctx)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential '{credential_id}' not found.")

    return CredentialResponse(**record.to_safe_dict())


@router.post(
    "/{credential_id}/revoke",
    response_model=CredentialResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke API Credential",
    description="Immediately revokes an API credential. Subsequent requests using this credential will fail closed.",
)
def revoke_credential(credential_id: str, request: Request) -> CredentialResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can revoke credentials.")

    try:
        revoked = credential_service.revoke_credential(credential_id, caller_context=ctx)
        audit_service.log_event(
            action="credential_revoke",
            request_id=request_id,
            principal=ctx,
            tenant_id=revoked.tenant_id,
            resource_type="credential",
            resource_id=credential_id,
            decision="ALLOW",
        )
        return CredentialResponse(**revoked.to_safe_dict())
    except CredentialNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential '{credential_id}' not found.")
    except CredentialAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)


@router.post(
    "/{credential_id}/rotate",
    response_model=CredentialRotateResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate API Credential",
    description="Revokes the existing credential and issues a new cryptographically random secret returned exactly once.",
)
def rotate_credential(credential_id: str, request: Request) -> CredentialRotateResponse:
    ctx = _get_context(request)
    request_id = getattr(request.state, "request_id", "req-unknown")

    if not (ctx.has_role("admin") or ctx.global_admin):
        raise ForbiddenError("Only administrators can rotate credentials.")

    try:
        new_record, new_token = credential_service.rotate_credential(
            credential_id,
            caller_context=ctx,
        )
        audit_service.log_event(
            action="credential_rotate",
            request_id=request_id,
            principal=ctx,
            tenant_id=new_record.tenant_id,
            resource_type="credential",
            resource_id=new_record.credential_id,
            decision="ALLOW",
        )
        return CredentialRotateResponse(
            old_credential_id=credential_id,
            new_credential_id=new_record.credential_id,
            credential_secret=new_token,
            token=new_token,
            principal_id=new_record.principal_id,
            tenant_id=new_record.tenant_id,
            created_at=new_record.created_at,
            expires_at=new_record.expires_at,
        )
    except CredentialNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential '{credential_id}' not found.")
    except CredentialAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)
