"""
Chat Service Layer
Orchestrates context-aware security evaluation and guarded multi-turn target execution for Backend v0.3/v0.4.
Enforces strict invariants:
1. Complete conversation context evaluated prior to any target execution.
2. Target LLM is NEVER called when context is BLOCKED or Guard fails/times out.
3. Target LLM output is ALWAYS sanitized for secret leaks.
4. Target infrastructure errors/timeouts return a safe non-BLOCK error payload without stack traces.
5. Separate latencies for Context Guard and Target model are measured and returned.
"""

import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import requests
import agentguard
from backend.config import GUARD_MODEL, TARGET_MODEL
from backend.schemas import ChatRequest, ChatResponse
from backend.services.concurrency_service import ConcurrencyLimitExceeded
from backend.services.metrics_service import metrics
from backend.services import context_guard_service, target_service

logger = logging.getLogger("agentguard.chat_service")


def execute_chat(request: ChatRequest, request_id: Optional[str] = None) -> ChatResponse:
    """
    Executes a multi-turn conversation sequence through the guarded pipeline:
    1. Evaluates conversation context with context-aware Guard under concurrency control
    2. Enforces decision (BLOCK/ERROR -> halt execution immediately)
    3. Invokes target LLM on ALLOW with supported messages under concurrency control
    4. Sanitizes target output with output leak sanitizer
    Measures separate Context Guard and Target latencies.
    """
    start_time = time.perf_counter()
    if not request_id or not request_id.strip():
        request_id = str(uuid.uuid4())
    conversation_id = (
        request.conversation_id.strip()
        if (request.conversation_id and request.conversation_id.strip())
        else f"conv-{uuid.uuid4()}"
    )

    try:
        # Step 1: Context-aware security evaluation
        context_start = time.perf_counter()
        guard_result = context_guard_service.evaluate_chat_context(request.messages)
        context_latency_ms = round((time.perf_counter() - context_start) * 1000.0, 2)

        # Step 2: Handle BLOCK or Guard failure -> DO NOT CALL TARGET LLM
        if guard_result.decision != "ALLOW":
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.info(
                "Chat execution halted by Guard: request_id=%s conv_id=%s decision=%s risk_score=%.2f attack_type=%s turns=%d context_latency_ms=%.1f latency_ms=%.1f",
                request_id,
                conversation_id,
                guard_result.decision,
                guard_result.risk_score or 1.0,
                guard_result.attack_type,
                len(request.messages),
                context_latency_ms,
                elapsed_ms,
            )
            return ChatResponse(
                request_id=request_id,
                conversation_id=conversation_id,
                decision=guard_result.decision,
                risk_score=guard_result.risk_score,
                attack_type=guard_result.attack_type,
                guard_model=guard_result.guard_model,
                target_model=TARGET_MODEL,
                response=None,
                latency_ms=elapsed_ms,
            )

        # Step 3: Guard ALLOW -> Invoke Target LLM with validated conversation sequence
        target_payload = [
            {"role": msg.role, "content": msg.content}
            for msg in request.messages
        ]

        target_start = time.perf_counter()
        try:
            raw_target_response = target_service.call_target_chat(target_payload)
            target_latency_ms = round((time.perf_counter() - target_start) * 1000.0, 2)
        except ConcurrencyLimitExceeded:
            raise
        except Exception as target_exc:
            target_latency_ms = round((time.perf_counter() - target_start) * 1000.0, 2)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            is_timeout = isinstance(target_exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(target_exc).__name__.lower()
            metrics.record_decision("ERROR")
            logger.error(
                "Target LLM chat execution failure: request_id=%s conv_id=%s error_type=%s is_timeout=%s target_latency_ms=%.1f latency_ms=%.1f",
                request_id,
                conversation_id,
                type(target_exc).__name__,
                is_timeout,
                target_latency_ms,
                elapsed_ms,
            )
            return ChatResponse(
                request_id=request_id,
                conversation_id=conversation_id,
                decision="ERROR",
                risk_score=None,
                attack_type="target_timeout" if is_timeout else "error",
                guard_model=guard_result.guard_model,
                target_model=TARGET_MODEL,
                response=None,
                latency_ms=elapsed_ms,
            )

        # Step 4: Pass target output through Output Leak Sanitizer
        sanitized_response, leak_prevented = agentguard.output_leak_sanitizer(raw_target_response)
        if leak_prevented:
            logger.warning(
                "Output leak sanitizer redacted protected secret in chat: request_id=%s conv_id=%s",
                request_id,
                conversation_id,
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        metrics.record_decision("ALLOW")
        logger.info(
            "Chat execution completed successfully: request_id=%s conv_id=%s decision=ALLOW turns=%d context_latency_ms=%.1f target_latency_ms=%.1f latency_ms=%.1f",
            request_id,
            conversation_id,
            len(request.messages),
            context_latency_ms,
            target_latency_ms,
            elapsed_ms,
        )

        return ChatResponse(
            request_id=request_id,
            conversation_id=conversation_id,
            decision="ALLOW",
            risk_score=guard_result.risk_score,
            attack_type="none",
            guard_model=guard_result.guard_model,
            target_model=TARGET_MODEL,
            response=sanitized_response,
            latency_ms=elapsed_ms,
        )

    except ConcurrencyLimitExceeded:
        raise

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        metrics.record_decision("BLOCK")
        logger.error(
            "Unexpected chat failure (failing closed): request_id=%s conv_id=%s error_type=%s latency_ms=%.1f",
            request_id,
            conversation_id,
            type(exc).__name__,
            elapsed_ms,
        )
        return ChatResponse(
            request_id=request_id,
            conversation_id=conversation_id,
            decision="BLOCK",
            risk_score=1.0,
            attack_type="guard_error",
            guard_model=GUARD_MODEL,
            target_model=TARGET_MODEL,
            response=None,
            latency_ms=elapsed_ms,
        )
