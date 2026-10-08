"""
Approvals API Routes (Backend v0.6)
Provides explicit human authorization endpoints for high-risk and critical tool actions.

LIMITATION & SCOPE NOTE:
v0.6 implements the approval security state machine and explicit approval boundary
for local development and testing. It does NOT provide production identity verification
or authenticated role-based access control (RBAC).

ENDPOINTS:
- POST /api/v1/approvals: Submit a tool proposal to evaluate risk and generate an approval request.
- GET /api/v1/approvals/{approval_id}: Inspect safe approval status, TTL, and telemetry.
- POST /api/v1/approvals/{approval_id}/approve: Explicitly approve and execute the action exactly once.
- POST /api/v1/approvals/{approval_id}/deny: Explicitly reject the action (tool never runs).
- GET /api/v1/approvals: List in-memory approval records for local debugging.
"""

import logging
import time
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from backend.schemas import (
    ApprovalActionResponse,
    ApprovalCreateRequest,
    ApprovalCreateResponse,
    ApprovalDetailResponse,
    ErrorDetail,
    ErrorResponse,
)
from backend.services.approval_service import (
    ActionBindingMismatchError,
    approve_and_execute,
    create_approval_request,
    deny_approval,
    validate_approval_id_format,
)
from backend.config import IDENTITY_ENABLED
from backend.services.approval_store import (
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalRecord,
    ApprovalReplayError,
    ApprovalStatus,
    InvalidApprovalStateError,
    approval_store,
)
from backend.services.authorization_service import ForbiddenError
from backend.services.identity_service import Principal, resolve_principal

logger = logging.getLogger("agentguard.approvals_route")

router = APIRouter(prefix="/api/v1/approvals", tags=["Human Approvals"])


@router.post(
    "",
    response_model=ApprovalCreateResponse,
    status_code=status.HTTP_200_OK,
    summary="Create or evaluate an approval request for a tool call",
    description=(
        "Submits a tool call to the risk classification and approval gateway.\n"
        "- Low-risk actions return NOT_REQUIRED.\n"
        "- High-risk and critical actions create a cryptographically bound approval request in PENDING_APPROVAL state.\n"
        "- Invalid tools or prompt-injected arguments fail closed and return BLOCK."
    ),
    responses={
        200: {"model": ApprovalCreateResponse},
        422: {"description": "Validation error in request schema."},
    },
)
def create_approval_endpoint(payload: ApprovalCreateRequest, request: Request) -> ApprovalCreateResponse:
    """
    Evaluates tool proposal risk and initiates a human approval request if required.
    """
    start_time = time.perf_counter()
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    principal = resolve_principal(request=request)

    decision, record, reason = create_approval_request(
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        request_id=request_id,
        conversation_id=payload.conversation_id,
        principal=principal,
    )
    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    if decision == "PENDING_APPROVAL" and record is not None:
        return ApprovalCreateResponse(
            request_id=request_id,
            approval_id=record.approval_id,
            decision="PENDING_APPROVAL",
            approval_status=ApprovalStatus.PENDING_APPROVAL.value,
            tool_name=payload.tool_name,
            risk_level=record.risk_level,
            arguments_summary=record.arguments_summary,
            reason=record.reason,
            created_at=record.created_at,
            expires_at=record.expires_at,
            result=None,
            latency_ms=elapsed_ms,
        )
    elif decision == "ALLOW":
        return ApprovalCreateResponse(
            request_id=request_id,
            approval_id=None,
            decision="ALLOW",
            approval_status=ApprovalStatus.NOT_REQUIRED.value,
            tool_name=payload.tool_name,
            risk_level="low",
            arguments_summary="none",
            reason="Low-risk tool; no approval required by policy.",
            result=None,
            latency_ms=elapsed_ms,
        )
    else:
        # BLOCKED (e.g. unknown tool, prompt injection in arguments)
        return ApprovalCreateResponse(
            request_id=request_id,
            approval_id=None,
            decision="BLOCK",
            approval_status=ApprovalStatus.DENIED.value,
            tool_name=payload.tool_name,
            risk_level=None,
            arguments_summary=None,
            reason=f"Security violation or invalid tool call: {reason}",
            result=None,
            latency_ms=elapsed_ms,
        )


@router.get(
    "/{approval_id}",
    response_model=ApprovalDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect approval request details and status",
    description=(
        "Retrieves safe metadata and current state for an approval request.\n"
        "Never exposes raw sensitive arguments or protected secrets."
    ),
    responses={
        200: {"model": ApprovalDetailResponse},
        400: {"model": ErrorResponse, "description": "Invalid approval ID format."},
        404: {"model": ErrorResponse, "description": "Approval ID not found."},
    },
)
def get_approval_endpoint(approval_id: str, request: Request):
    """
    Inspects safe approval details with ownership enforcement.
    """
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    principal = resolve_principal(request=request)

    if not validate_approval_id_format(approval_id):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "INVALID_APPROVAL_ID",
                    "message": "The provided approval ID format is invalid.",
                },
            },
        )

    target_tenant = None if getattr(principal, "global_admin", False) else getattr(principal, "tenant_id", "default")
    record = approval_store.get_approval(approval_id, tenant_id=target_tenant)
    if not record:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_NOT_FOUND",
                    "message": f"Approval request '{approval_id}' was not found.",
                },
            },
        )

    # Ownership check: standard users can only inspect their own approvals
    has_explicit_principal = bool(request.headers.get("x-agentguard-principal"))
    if IDENTITY_ENABLED or has_explicit_principal:
        if not (principal.has_role("admin") or principal.has_role("operator")):
            if record.principal_id != principal.principal_id:
                logger.warning(
                    "Ownership check failed on approval: principal='%s' attempted to inspect approval owned by '%s'",
                    principal.principal_id,
                    record.principal_id,
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "FORBIDDEN",
                            "message": "Users are only permitted to inspect their own approval requests.",
                        },
                    },
                )

    return ApprovalDetailResponse(**record.to_safe_dict())


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Explicitly approve and execute an action",
    description=(
        "Explicitly transitions an approval from PENDING_APPROVAL to APPROVED,\n"
        "then immediately executes the mock tool exactly once (transitioning to CONSUMED).\n"
        "Model outputs can NEVER trigger this transition. Operator or Admin role required."
    ),
    responses={
        200: {"model": ApprovalActionResponse},
        400: {"model": ErrorResponse, "description": "Invalid ID or approval expired."},
        403: {"model": ErrorResponse, "description": "Forbidden: Requires operator or admin role."},
        404: {"model": ErrorResponse, "description": "Approval ID not found."},
        409: {"model": ErrorResponse, "description": "Approval already consumed (replay attempt) or policy conflict."},
    },
)
def approve_endpoint(approval_id: str, request: Request):
    """
    Explicit human approval operation. Executes the tool exactly once.
    Requires operator or admin role when identity is enabled.
    """
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    principal = resolve_principal(request=request)
    has_explicit_principal = bool(request.headers.get("x-agentguard-principal"))
    has_bearer = bool(request.headers.get("authorization", "").lower().startswith("bearer"))
    approving_p = principal if (IDENTITY_ENABLED or has_explicit_principal or has_bearer) else None

    if not validate_approval_id_format(approval_id):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "INVALID_APPROVAL_ID",
                    "message": "The provided approval ID format is invalid.",
                },
            },
        )

    try:
        outcome = approve_and_execute(approval_id, approving_principal=approving_p)
        return ApprovalActionResponse(
            request_id=request_id,
            approval_id=approval_id,
            decision=outcome["decision"],
            approval_status=outcome["approval_status"],
            tool_name=outcome["tool_name"],
            result=outcome.get("result"),
            risk_level=outcome.get("risk_level"),
            latency_ms=outcome.get("latency_ms"),
            attack_type=outcome.get("attack_type"),
        )
    except ForbiddenError as exc:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "request_id": request_id,
                "error": {
                    "code": "FORBIDDEN",
                    "message": str(exc),
                },
            },
        )
    except ActionBindingMismatchError as exc:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "request_id": request_id,
                "error": {
                    "code": "POLICY_CONFLICT",
                    "message": str(exc),
                },
            },
        )
    except ApprovalNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_NOT_FOUND",
                    "message": f"Approval request '{approval_id}' was not found.",
                },
            },
        )
    except ApprovalExpiredError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_EXPIRED",
                    "message": str(exc),
                },
            },
        )
    except ApprovalReplayError as exc:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_ALREADY_CONSUMED",
                    "message": str(exc),
                },
            },
        )
    except InvalidApprovalStateError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "INVALID_APPROVAL_STATE",
                    "message": str(exc),
                },
            },
        )
    except Exception as exc:
        logger.error("Unexpected error in approve_endpoint: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_EXECUTION_ERROR",
                    "message": "Failed to complete approved tool execution.",
                },
            },
        )


@router.post(
    "/{approval_id}/deny",
    response_model=ApprovalActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Explicitly deny an approval request",
    description=(
        "Explicitly transitions an approval to DENIED.\n"
        "The associated tool is guaranteed to never execute. Repeated calls are safe and idempotent. "
        "Requires operator or admin role."
    ),
    responses={
        200: {"model": ApprovalActionResponse},
        400: {"model": ErrorResponse, "description": "Invalid ID or approval state."},
        403: {"model": ErrorResponse, "description": "Forbidden: Requires operator or admin role."},
        404: {"model": ErrorResponse, "description": "Approval ID not found."},
    },
)
def deny_endpoint(approval_id: str, request: Request):
    """
    Explicit denial operation. Prevents action execution.
    Requires operator or admin role when identity is enabled.
    """
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    principal = resolve_principal(request=request)
    has_explicit_principal = bool(request.headers.get("x-agentguard-principal"))
    has_bearer = bool(request.headers.get("authorization", "").lower().startswith("bearer"))
    denying_p = principal if (IDENTITY_ENABLED or has_explicit_principal or has_bearer) else None

    if not validate_approval_id_format(approval_id):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "INVALID_APPROVAL_ID",
                    "message": "The provided approval ID format is invalid.",
                },
            },
        )

    try:
        outcome = deny_approval(
            approval_id,
            reason="Rejected via HTTP API",
            denying_principal=denying_p,
        )
        return ApprovalActionResponse(
            request_id=request_id,
            approval_id=approval_id,
            decision="BLOCK",
            approval_status=ApprovalStatus.DENIED.value,
            tool_name=outcome["tool_name"],
            result=None,
            risk_level=outcome.get("risk_level"),
            attack_type="none",
        )
    except ForbiddenError as exc:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "request_id": request_id,
                "error": {
                    "code": "FORBIDDEN",
                    "message": str(exc),
                },
            },
        )
    except ApprovalNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "request_id": request_id,
                "error": {
                    "code": "APPROVAL_NOT_FOUND",
                    "message": f"Approval request '{approval_id}' was not found.",
                },
            },
        )
    except InvalidApprovalStateError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "request_id": request_id,
                "error": {
                    "code": "INVALID_APPROVAL_STATE",
                    "message": str(exc),
                },
            },
        )


@router.get(
    "",
    response_model=List[ApprovalDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="List local approval records",
    description="Returns stored approval records. Users see only their own; operators/admins see all.",
)
def list_approvals_endpoint(request: Request):
    """
    Returns list of stored approval records with ownership scoping.
    """
    principal = getattr(request.state, "context", None) or getattr(request.state, "principal", None) or resolve_principal(request=request)
    target_tenant = None if getattr(principal, "global_admin", False) else getattr(principal, "tenant_id", "default")
    records = approval_store.list_approvals(tenant_id=target_tenant)

    has_explicit_principal = bool(request.headers.get("x-agentguard-principal")) or bool(request.headers.get("authorization"))
    if IDENTITY_ENABLED or has_explicit_principal:
        if not (principal.has_role("admin") or principal.has_role("operator")):
            records = [r for r in records if r.principal_id == principal.principal_id]

    return [ApprovalDetailResponse(**r.to_safe_dict()) for r in records]

