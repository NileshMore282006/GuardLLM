"""
OpenAI Compatibility Proxy Route
Provides drop-in /v1/chat/completions and /v1/models endpoints for standard OpenAI SDKs,
LangChain, LlamaIndex, CrewAI, AutoGen, and other LLM application frameworks.

All requests pass through AgentGuard v5 multi-layer inspection:
1. Canonical multi-turn and single-turn adversarial prompt injection evaluation.
2. If BLOCKED, returns safe refusal choice (or HTTP 400 on error-mode header).
3. If ALLOWED, executes target LLM and enforces output secret leak sanitization.
4. Tamper-evident forward-chained HMAC audit logging.
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, Header, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse

import agentguard
from backend.config import DLP_ENABLED, DLP_REVERSIBLE, GUARD_MODEL, OLLAMA_BASE_URL, TARGET_MODEL, VERSION
from backend.services.dlp_service import dlp_service, DLPVault
from backend.schemas import (
    ChatMessage,
    OpenAIChatChoice,
    OpenAIChatChoiceMessage,
    OpenAIChatCompletionRequest,
    OpenAIChatCompletionResponse,
    OpenAIGuardMetadata,
    OpenAIModelCard,
    OpenAIModelListResponse,
    OpenAIUsage,
)
from backend.services import context_guard_service, target_service
from backend.services.audit_service import audit_service
from backend.services.concurrency_service import ConcurrencyLimitExceeded
from backend.services.identity_service import resolve_principal
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.openai_proxy")

router = APIRouter(tags=["OpenAI Compatibility"])


def _build_model_list() -> List[OpenAIModelCard]:
    """
    Constructs the list of models supported by the gateway.
    Queries local Ollama if available, always including the configured models.
    """
    now = int(time.time())
    model_ids = {TARGET_MODEL, GUARD_MODEL, "agentguard", "agentguard-guarded"}

    # Attempt to query Ollama installed models dynamically
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            for item in resp.json().get("models", []):
                name = item.get("name")
                if name:
                    model_ids.add(name)
    except Exception:
        pass

    cards = []
    for mid in sorted(model_ids):
        cards.append(
            OpenAIModelCard(
                id=mid,
                object="model",
                created=now,
                owned_by="agentguard",
                root=mid,
            )
        )
    return cards


@router.get(
    "/v1/models",
    response_model=OpenAIModelListResponse,
    status_code=status.HTTP_200_OK,
    summary="List available models (OpenAI Compatible)",
    description="Returns list of models available through the AgentGuard security gateway.",
)
def list_models() -> OpenAIModelListResponse:
    """
    Returns OpenAI-compatible model list for client discovery.
    """
    cards = _build_model_list()
    return OpenAIModelListResponse(object="list", data=cards)


@router.get(
    "/v1/models/{model_id:path}",
    response_model=OpenAIModelCard,
    status_code=status.HTTP_200_OK,
    summary="Retrieve model details (OpenAI Compatible)",
)
def get_model(model_id: str) -> OpenAIModelCard:
    """
    Retrieves details for a specific model identifier.
    """
    return OpenAIModelCard(
        id=model_id,
        object="model",
        created=int(time.time()),
        owned_by="agentguard",
        root=model_id,
    )


def _estimate_tokens(text: str) -> int:
    """Lightweight approximation for OpenAI usage token counts."""
    if not text:
        return 0
    words = len(text.split())
    return max(1, int(words * 1.33))


@router.post(
    "/v1/chat/completions",
    status_code=status.HTTP_200_OK,
    summary="Create chat completion with AgentGuard security enforcement (OpenAI Compatible)",
    description=(
        "Standard OpenAI Chat Completions endpoint. Intercepts incoming messages, "
        "evaluates them through the multi-layer security engine (homoglyphs, reversed text, "
        "instruction overrides, roleplay attacks), and scrubs outputs for canary secrets."
    ),
)
def chat_completions(
    payload: OpenAIChatCompletionRequest,
    request: Request,
    block_mode: Optional[str] = Query(None, description="Set to 'error' to return HTTP 400 on guard block."),
    x_agentguard_block_mode: Optional[str] = Header(None, alias="X-AgentGuard-Block-Mode"),
    x_agentguard_dlp: Optional[str] = Header(None, alias="X-AgentGuard-DLP"),
    x_agentguard_dlp_mask_only: Optional[str] = Header(None, alias="X-AgentGuard-DLP-Mask-Only"),
) -> Any:
    """
    OpenAI-compatible chat completions endpoint guarded by AgentGuard with reversible DLP.
    """
    start_time = time.perf_counter()
    request_id = getattr(request.state, "request_id", None) or f"chatcmpl-{uuid.uuid4().hex[:12]}"
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:20]}"
    created_ts = int(time.time())
    principal = resolve_principal(request=request)

    # Determine desired block reporting mode: "content" (refusal message) or "error" (HTTP 400)
    error_mode = (
        (block_mode and block_mode.lower() == "error")
        or (x_agentguard_block_mode and x_agentguard_block_mode.lower() == "error")
    )

    # 1. Prepare messages for context inspection
    # Convert supported messages to internal ChatMessage schema where applicable
    valid_chat_messages: List[ChatMessage] = []
    canonical_turns: List[str] = []
    total_prompt_chars = 0

    for msg in payload.messages:
        role_norm = msg.role.strip().lower()
        content_str = str(msg.content or "").strip()
        total_prompt_chars += len(content_str)
        canonical_turns.append(f"[{role_norm.upper()}]\n{content_str}")

        # ChatMessage only allows "user" or "assistant"
        if role_norm in ("user", "assistant") and content_str:
            valid_chat_messages.append(ChatMessage(role=role_norm, content=content_str))

    canonical_context = "\n\n".join(canonical_turns)

    # 2. Evaluate through Context Guard & AgentGuard Engine
    guard_decision = "ALLOW"
    risk_score = 0.0
    attack_type = "none"

    try:
        # A. Check multi-turn heuristics if applicable
        if valid_chat_messages:
            heur_result = context_guard_service.check_multiturn_heuristics(
                valid_chat_messages, canonical_context
            )
            if heur_result:
                guard_decision = "BLOCK"
                risk_score = heur_result.get("risk_score", 1.0)
                attack_type = heur_result.get("attack_type", "context_manipulation")

        # B. Full Guard Check on conversation context
        if guard_decision == "ALLOW":
            with context_guard_service.concurrency_manager.guard_slot():
                guard_res = agentguard.guard_check(canonical_context)
            
            raw_decision = guard_res.get("decision", "BLOCK")
            guard_decision = raw_decision if raw_decision in ("ALLOW", "BLOCK") else "BLOCK"
            risk_score = float(guard_res.get("risk_score", 0.0 if guard_decision == "ALLOW" else 1.0))
            attack_type = str(guard_res.get("attack_type", "none" if guard_decision == "ALLOW" else "prompt_injection"))

    except ConcurrencyLimitExceeded:
        raise
    except Exception as exc:
        logger.error("Guard evaluation failure in OpenAI proxy (failing closed): %s", exc)
        guard_decision = "BLOCK"
        risk_score = 1.0
        attack_type = "guard_error"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    # 3. Handle BLOCKED Request
    if guard_decision != "ALLOW":
        metrics.record_decision("BLOCK")
        audit_service.log_event(
            action="openai_guard_block",
            request_id=request_id,
            principal=principal,
            resource_type="openai_chat",
            resource_id=payload.model,
            decision="BLOCK",
            risk_score=risk_score,
            attack_type=attack_type,
        )

        if error_mode:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "message": f"Security policy violation: {attack_type} detected by AgentGuard.",
                        "type": "security_violation",
                        "code": "GUARD_BLOCKED",
                        "param": None,
                    }
                },
                headers={
                    "X-Request-ID": request_id,
                    "X-AgentGuard-Decision": "BLOCK",
                    "X-AgentGuard-Attack-Type": attack_type,
                },
            )

        # Standard OpenAI graceful response with refusal content
        refusal_content = (
            f"I cannot fulfill this request because it violates security policy "
            f"(AgentGuard: BLOCKED - {attack_type} detected)."
        )
        prompt_tokens = _estimate_tokens(canonical_context)
        completion_tokens = _estimate_tokens(refusal_content)

        return OpenAIChatCompletionResponse(
            id=completion_id,
            object="chat.completion",
            created=created_ts,
            model=payload.model,
            choices=[
                OpenAIChatChoice(
                    index=0,
                    message=OpenAIChatChoiceMessage(role="assistant", content=refusal_content),
                    finish_reason="stop",
                )
            ],
            usage=OpenAIUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            system_fingerprint="fp_agentguard_v10",
            agentguard=OpenAIGuardMetadata(
                decision="BLOCK",
                risk_score=risk_score,
                attack_type=attack_type,
                latency_ms=elapsed_ms,
                dlp_entities_masked=0,
                dlp_types=[],
            ),
        )

    # 4. DLP Tokenization & Target LLM Execution (Guard ALLOW)
    dlp_active = DLP_ENABLED and (x_agentguard_dlp is None or x_agentguard_dlp.lower() != "false")
    dlp_reversible = DLP_REVERSIBLE and (x_agentguard_dlp_mask_only is None or x_agentguard_dlp_mask_only.lower() != "true")

    dlp_vault = DLPVault()
    target_payload = []
    for m in payload.messages:
        raw_msg_content = str(m.content or "")
        if dlp_active:
            masked_msg, dlp_vault = dlp_service.tokenize(raw_msg_content, vault=dlp_vault)
        else:
            masked_msg = raw_msg_content
        target_payload.append({"role": m.role.strip().lower(), "content": masked_msg})

    if dlp_vault.detected_entities:
        logger.info(
            "DLP anonymized %d entities in request %s (types: %s)",
            len(dlp_vault.detected_entities),
            request_id,
            list(dict.fromkeys(e["type"] for e in dlp_vault.detected_entities)),
        )

    try:
        raw_target_response = target_service.call_target_chat(target_payload)
    except ConcurrencyLimitExceeded:
        raise
    except Exception as target_exc:
        logger.error("Target LLM execution failed in OpenAI proxy: %s", target_exc)
        metrics.record_decision("ERROR")
        audit_service.log_event(
            action="openai_target_error",
            request_id=request_id,
            principal=principal,
            resource_type="openai_chat",
            resource_id=payload.model,
            decision="ERROR",
            risk_score=0.0,
            attack_type="target_error",
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": {
                    "message": "Downstream LLM inference service is currently unavailable.",
                    "type": "api_error",
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "param": None,
                }
            },
            headers={"X-Request-ID": request_id},
        )

    # 5. Output Secret Leak Sanitizer
    sanitized_response, leak_prevented = agentguard.output_leak_sanitizer(raw_target_response)
    if leak_prevented:
        logger.warning("Canary/secret leak redacted in OpenAI proxy response for %s", request_id)

    # 5b. Reversible PII Restoration (De-anonymization)
    if dlp_active and dlp_reversible and dlp_vault.reverse_map:
        final_response = dlp_service.de_tokenize(sanitized_response, dlp_vault)
    else:
        final_response = sanitized_response

    total_latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    metrics.record_decision("ALLOW")
    audit_service.log_event(
        action="openai_chat_execute",
        request_id=request_id,
        principal=principal,
        resource_type="openai_chat",
        resource_id=payload.model,
        decision="ALLOW",
        risk_score=risk_score,
        attack_type="none",
    )

    prompt_tokens = _estimate_tokens(canonical_context)
    completion_tokens = _estimate_tokens(final_response)

    # 6. Streaming Mode (SSE Server-Sent Events)
    if payload.stream:
        def sse_event_stream():
            # Initial chunk (role)
            init_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": payload.model,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}],
            }
            yield f"data: {json.dumps(init_chunk)}\n\n"

            # Content chunk (yield response in words/tokens)
            words = final_response.split(" ")
            for i, w in enumerate(words):
                chunk_str = w if i == 0 else " " + w
                chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": payload.model,
                    "choices": [{"index": 0, "delta": {"content": chunk_str}, "finish_reason": None}],
                }
                yield f"data: {json.dumps(chunk)}\n\n"

            # Final finish chunk
            finish_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": payload.model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            yield f"data: {json.dumps(finish_chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            sse_event_stream(),
            media_type="text/event-stream",
            headers={
                "X-Request-ID": request_id,
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )

    # Non-streaming Response
    return OpenAIChatCompletionResponse(
        id=completion_id,
        object="chat.completion",
        created=created_ts,
        model=payload.model,
        choices=[
            OpenAIChatChoice(
                index=0,
                message=OpenAIChatChoiceMessage(role="assistant", content=final_response),
                finish_reason="stop",
            )
        ],
        usage=OpenAIUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
        system_fingerprint="fp_agentguard_v10",
        agentguard=OpenAIGuardMetadata(
            decision="ALLOW",
            risk_score=risk_score,
            attack_type="none",
            latency_ms=total_latency_ms,
            dlp_entities_masked=len(dlp_vault.detected_entities),
            dlp_types=list(dict.fromkeys(e["type"] for e in dlp_vault.detected_entities)),
        ),
    )
