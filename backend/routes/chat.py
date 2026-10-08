"""
Chat API Route
Defines POST /api/v1/chat endpoint for context-aware guarded multi-turn conversations.
"""

from fastapi import APIRouter, Request, status
from backend.schemas import ChatRequest, ChatResponse
from backend.services.audit_service import audit_service
from backend.services.chat_service import execute_chat
from backend.services.identity_service import resolve_principal

router = APIRouter(tags=["Multi-Turn Chat"])


@router.post(
    "/api/v1/chat",
    response_model=ChatResponse,
    status_code=status.HTTP_200_OK,
    summary="Guarded multi-turn chat execution with AgentGuard v5 context security",
    description=(
        "Safely executes a multi-turn conversation sequence under the protection of "
        "the AgentGuard v5 context-aware security engine.\n\n"
        "1. Validates conversation roles (strictly 'user' and 'assistant').\n"
        "2. Constructs canonical context representation and evaluates cross-turn attacks.\n"
        "3. If BLOCKED or on Guard error/timeout, halts execution immediately without contacting the target LLM.\n"
        "4. If ALLOWED, invokes the target LLM with the conversation history and filters output for secret leaks.\n"
        "5. Returns the sanitized assistant response or safe error payload."
    ),
    responses={
        200: {
            "description": "Conversation evaluation successfully performed (ALLOW, BLOCK, or safe ERROR).",
            "model": ChatResponse,
        },
        422: {
            "description": (
                "Validation error: empty messages, missing/empty content, unsupported role "
                "(e.g., 'system', 'developer', 'tool'), excessive message count, or oversized conversation."
            ),
        },
        429: {
            "description": "Rate limit exceeded.",
        },
        503: {
            "description": "Inference concurrency capacity exhausted.",
        },
    },
)
def chat_endpoint(payload: ChatRequest, request: Request) -> ChatResponse:
    """
    HTTP route handler for context-aware multi-turn prompt execution.
    """
    request_id = getattr(request.state, "request_id", None)
    principal = resolve_principal(request=request)
    resp = execute_chat(payload, request_id=request_id)

    action = "guard_block" if resp.decision == "BLOCK" else ("chat_execute" if resp.decision == "ALLOW" else "chat_error")
    audit_service.log_event(
        action=action,
        request_id=resp.request_id,
        principal=principal,
        resource_type="chat",
        resource_id=resp.conversation_id,
        decision=resp.decision,
        risk_score=resp.risk_score,
        attack_type=resp.attack_type,
    )
    return resp
