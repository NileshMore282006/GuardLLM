"""
Guard API Route
Defines POST /api/v1/guard endpoint.
"""

from fastapi import APIRouter, Request, status
from backend.schemas import GuardRequest, GuardResponse
from backend.services.audit_service import audit_service
from backend.services.guard_service import evaluate_prompt
from backend.services.identity_service import resolve_principal

router = APIRouter(tags=["Security Guard"])


@router.post(
    "/api/v1/guard",
    response_model=GuardResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate prompt security with AgentGuard v5",
    description=(
        "Analyzes a user prompt through the complete AgentGuard v5 multi-layer "
        "security pipeline (Normalization, Structured Analysis, Deterministic Pre-Checks, "
        "Guard LLM, and Policy Engine) and returns the security decision."
    ),
    responses={
        200: {
            "description": "Security evaluation successfully performed (either ALLOW or BLOCK).",
            "model": GuardResponse,
        },
        422: {
            "description": "Validation error: prompt is missing, empty, whitespace-only, or oversized.",
        },
        429: {
            "description": "Rate limit or concurrency limit exceeded.",
        },
        503: {
            "description": "Inference concurrency capacity exhausted.",
        },
    },
)
def guard_endpoint(payload: GuardRequest, request: Request) -> GuardResponse:
    """
    HTTP route handler for prompt security analysis.
    """
    request_id = getattr(request.state, "request_id", None)
    principal = resolve_principal(request=request)
    resp = evaluate_prompt(payload.prompt, request_id=request_id)

    audit_service.log_event(
        action="guard_block" if resp.decision == "BLOCK" else "guard_allow",
        request_id=resp.request_id,
        principal=principal,
        resource_type="prompt",
        decision=resp.decision,
        risk_score=resp.risk_score,
        attack_type=resp.attack_type,
    )
    return resp
