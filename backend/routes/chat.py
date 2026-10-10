"""
Chat API Route
Defines POST /api/v1/chat endpoint for context-aware guarded multi-turn conversations,
as well as GET/DELETE endpoints backed by SQLite persistent storage.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Request, status
from backend.schemas import ChatRequest, ChatResponse
from backend.services.audit_service import audit_service
from backend.services.chat_service import execute_chat
from backend.services.chat_store import chat_store
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
    Persists turns to hardened SQLite database.
    """
    request_id = getattr(request.state, "request_id", None)
    principal = resolve_principal(request=request)
    resp = execute_chat(payload, request_id=request_id)

    # Persist the turn to SQLite
    user_msg = payload.messages[-1].content if payload.messages else ""
    turn_num = (len(payload.messages) + 1) // 2
    chat_store.save_turn(
        conversation_id=resp.conversation_id,
        turn_data={
            "id": resp.request_id,
            "turn_number": max(1, turn_num),
            "user_message": user_msg,
            "assistant_response": resp.response if resp.decision == "ALLOW" else None,
            "decision": resp.decision,
            "risk_score": resp.risk_score,
            "attack_type": resp.attack_type,
            "guard_model": resp.guard_model,
            "target_model": resp.target_model,
            "latency_ms": resp.latency_ms,
        },
    )

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


@router.get(
    "/api/v1/chat/conversations",
    summary="List recent chat conversations stored in SQLite",
    description="Returns a list of conversation summaries sorted by most recent activity.",
)
def list_conversations(limit: int = 50) -> List[Dict[str, Any]]:
    """Lists recent conversation records from SQLite."""
    return chat_store.list_conversations(limit=limit)


@router.get(
    "/api/v1/chat/conversations/{conversation_id}",
    summary="Get conversation detail and all turns",
    description="Retrieves a specific conversation with all historical turns from SQLite.",
)
def get_conversation(conversation_id: str) -> Dict[str, Any]:
    """Retrieves conversation turns and metadata by conversation_id."""
    conv = chat_store.get_conversation(conversation_id)
    if not conv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation '{conversation_id}' not found.",
        )
    return conv


@router.delete(
    "/api/v1/chat/conversations/{conversation_id}",
    summary="Delete conversation from SQLite",
    description="Deletes a conversation and all associated turns from SQLite storage.",
)
def delete_conversation(conversation_id: str) -> Dict[str, Any]:
    """Deletes conversation and associated records from SQLite."""
    deleted = chat_store.delete_conversation(conversation_id)
    return {"success": deleted, "conversation_id": conversation_id}
