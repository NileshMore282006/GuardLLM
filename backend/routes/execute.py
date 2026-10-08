"""
Execute API Route
Defines POST /api/v1/execute endpoint for guarded target LLM execution.
"""

from fastapi import APIRouter, Request, status
from backend.schemas import ExecuteRequest, ExecuteResponse
from backend.services.audit_service import audit_service
from backend.services.execution_service import execute_prompt
from backend.services.identity_service import resolve_principal

router = APIRouter(tags=["Guarded Execution"])


@router.post(
    "/api/v1/execute",
    response_model=ExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute prompt against target LLM with AgentGuard v5 protection",
    description=(
        "Safely executes a user prompt against the target LLM strictly under the "
        "protection of the AgentGuard v5 security engine.\n\n"
        "1. Analyzes the prompt through the multi-layer security engine.\n"
        "2. If BLOCKED, halts execution immediately without contacting the target LLM.\n"
        "3. If ALLOWED, invokes the target LLM and filters output through the leak sanitizer.\n"
        "4. Returns the sanitized response or safe error payload."
    ),
    responses={
        200: {
            "description": "Execution evaluation successfully performed (ALLOW, BLOCK, or safe ERROR).",
            "model": ExecuteResponse,
        },
        422: {
            "description": "Validation error: prompt is missing, empty, whitespace-only, or oversized.",
        },
        429: {
            "description": "Rate limit exceeded.",
        },
        503: {
            "description": "Inference concurrency capacity exhausted.",
        },
    },
)
def execute_endpoint(payload: ExecuteRequest, request: Request) -> ExecuteResponse:
    """
    HTTP route handler for guarded prompt execution.
    """
    request_id = getattr(request.state, "request_id", None)
    principal = resolve_principal(request=request)
    resp = execute_prompt(payload.prompt, request_id=request_id)

    action = "guard_block" if resp.decision == "BLOCK" else ("target_execute" if resp.decision == "ALLOW" else "target_error")
    audit_service.log_event(
        action=action,
        request_id=resp.request_id,
        principal=principal,
        resource_type="prompt",
        decision=resp.decision,
        risk_score=resp.risk_score,
        attack_type=resp.attack_type,
    )
    return resp
