"""
Execution Service Layer
Coordinates the full guarded LLM execution gateway for Backend v0.2/v0.4.
Guarantees that:
1. Target LLM is NEVER called when Guard decides BLOCK or encounters an error/timeout.
2. Target LLM is invoked ONLY after an explicit ALLOW decision.
3. Target LLM output is ALWAYS filtered through the output leak sanitizer before return.
4. Target infrastructure errors/timeouts return a safe non-BLOCK error without stack traces.
5. Latencies for Guard and Target are measured and reported separately.
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
from backend.config import GUARD_MODEL, TARGET_MODEL, MAX_TOOL_CALLS_PER_REQUEST, DLP_ENABLED, DLP_REVERSIBLE
from backend.services.dlp_service import dlp_service, DLPVault
from backend.schemas import ExecuteResponse
from backend.services.concurrency_service import ConcurrencyLimitExceeded
from backend.services.guard_service import evaluate_prompt
from backend.services.metrics_service import metrics
from backend.services.target_service import call_target
from backend.services.tool_guard_service import authorize_tool_call, detect_tool_call
from backend.services.tool_executor import execute_mock_tool
from backend.services.tool_result_guard import format_tool_context_message

logger = logging.getLogger("agentguard.execution")


def execute_prompt(prompt: str, request_id: Optional[str] = None) -> ExecuteResponse:
    """
    Executes a prompt through the complete guarded pipeline:
    1. AgentGuard v5 Security Analysis
    2. Decision evaluation (BLOCK -> stop immediately)
    3. Target LLM invocation (ALLOW only)
    4. Output Leak Sanitizer (always applied before response)
    Measures separate Guard and Target latencies.
    """
    start_time = time.perf_counter()
    if not request_id or not request_id.strip():
        request_id = str(uuid.uuid4())

    try:
        # Step 1: Run Guard security evaluation
        guard_start = time.perf_counter()
        guard_result = evaluate_prompt(prompt, request_id=request_id)
        guard_latency_ms = round((time.perf_counter() - guard_start) * 1000.0, 2)

        # Step 2: Handle BLOCK or Guard failure -> DO NOT CALL TARGET LLM
        if guard_result.decision != "ALLOW":
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.info(
                "Execution halted by Guard: request_id=%s decision=%s risk_score=%.2f attack_type=%s guard_latency_ms=%.1f latency_ms=%.1f",
                request_id,
                guard_result.decision,
                guard_result.risk_score,
                guard_result.attack_type,
                guard_latency_ms,
                elapsed_ms,
            )
            return ExecuteResponse(
                request_id=request_id,
                decision=guard_result.decision,
                risk_score=guard_result.risk_score,
                attack_type=guard_result.attack_type,
                guard_model=guard_result.guard_model,
                target_model=TARGET_MODEL,
                response=None,
                latency_ms=elapsed_ms,
            )

        # Step 3: Guard ALLOW -> Invoke Target LLM with DLP Tokenization
        dlp_vault = DLPVault()
        if DLP_ENABLED:
            masked_prompt, dlp_vault = dlp_service.tokenize(prompt, vault=dlp_vault)
        else:
            masked_prompt = prompt

        target_start = time.perf_counter()
        try:
            raw_target_response = call_target(masked_prompt)
            target_latency_ms = round((time.perf_counter() - target_start) * 1000.0, 2)
        except ConcurrencyLimitExceeded:
            raise
        except Exception as target_exc:
            target_latency_ms = round((time.perf_counter() - target_start) * 1000.0, 2)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            is_timeout = isinstance(target_exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(target_exc).__name__.lower()
            metrics.record_decision("ERROR")
            logger.error(
                "Target LLM execution error: request_id=%s error_type=%s is_timeout=%s target_latency_ms=%.1f latency_ms=%.1f",
                request_id,
                type(target_exc).__name__,
                is_timeout,
                target_latency_ms,
                elapsed_ms,
            )
            # Infrastructure failure/timeout after ALLOW is reported as ERROR, not a security BLOCK
            return ExecuteResponse(
                request_id=request_id,
                decision="ERROR",
                risk_score=0.0,
                attack_type="target_timeout" if is_timeout else "none",
                guard_model=guard_result.guard_model,
                target_model=TARGET_MODEL,
                response=None,
                latency_ms=elapsed_ms,
            )

        # Step 3b: Tool Call Detection & Controlled Execution Loop (Backend v0.5)
        current_target_response = raw_target_response
        tool_iterations = 0

        while True:
            tool_proposal = detect_tool_call(current_target_response)
            if not tool_proposal:
                break

            if tool_iterations >= MAX_TOOL_CALLS_PER_REQUEST:
                metrics.record_tool_call_limit_exceeded()
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                logger.warning(
                    "Tool call limit exceeded (%d iterations): halting tool loop for request_id=%s",
                    MAX_TOOL_CALLS_PER_REQUEST,
                    request_id,
                )
                return ExecuteResponse(
                    request_id=request_id,
                    decision="BLOCK",
                    risk_score=1.0,
                    attack_type="tool_call_limit",
                    guard_model=guard_result.guard_model,
                    target_model=TARGET_MODEL,
                    response=None,
                    latency_ms=elapsed_ms,
                )

            tool_iterations += 1
            tool_name, tool_args = tool_proposal

            # Run through Tool Authorization Gate
            auth = authorize_tool_call(tool_name, tool_args, request_id=request_id)
            if auth.decision != "ALLOW":
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                logger.warning(
                    "Target tool call proposal BLOCKED: tool=%s attack_type=%s reason=%s request_id=%s",
                    tool_name,
                    auth.attack_type,
                    auth.reason,
                    request_id,
                )
                return ExecuteResponse(
                    request_id=request_id,
                    decision="BLOCK",
                    risk_score=1.0,
                    attack_type=auth.attack_type,
                    guard_model=guard_result.guard_model,
                    target_model=TARGET_MODEL,
                    response=None,
                    latency_ms=elapsed_ms,
                )

            # ALLOW -> Execute deterministic mock tool under explicit authorization
            raw_tool_result = execute_mock_tool(tool_name, tool_args, is_authorized=True)

            # Sanitize and format tool result as UNTRUSTED DATA context
            tool_context = format_tool_context_message(tool_name, raw_tool_result)

            # Re-invoke target LLM with untrusted tool context
            next_prompt = f"{prompt}\n\n{tool_context}\n\nPlease provide your final response based on the above tool data."
            current_target_response = call_target(next_prompt)

        # Step 4: Pass target output through Output Leak Sanitizer
        sanitized_response, leak_prevented = agentguard.output_leak_sanitizer(current_target_response)
        if leak_prevented:
            logger.warning(
                "Output leak sanitizer redacted protected secret: request_id=%s",
                request_id,
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "Execution completed successfully: request_id=%s decision=ALLOW guard_latency_ms=%.1f target_latency_ms=%.1f latency_ms=%.1f",
            request_id,
            guard_latency_ms,
            target_latency_ms,
            elapsed_ms,
        )

        # Step 4b: Reversible PII Restoration
        if DLP_ENABLED and DLP_REVERSIBLE and dlp_vault.reverse_map:
            final_response = dlp_service.de_tokenize(sanitized_response, dlp_vault)
        else:
            final_response = sanitized_response

        return ExecuteResponse(
            request_id=request_id,
            decision="ALLOW",
            risk_score=guard_result.risk_score,
            attack_type="none",
            guard_model=guard_result.guard_model,
            target_model=TARGET_MODEL,
            response=final_response,
            latency_ms=elapsed_ms,
        )

    except ConcurrencyLimitExceeded:
        raise

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        fallback_request_id = request_id or str(uuid.uuid4())
        metrics.record_decision("BLOCK")
        logger.error(
            "Unexpected execution failure (failing closed): request_id=%s error_type=%s latency_ms=%.1f",
            fallback_request_id,
            type(exc).__name__,
            elapsed_ms,
        )
        return ExecuteResponse(
            request_id=fallback_request_id,
            decision="BLOCK",
            risk_score=1.0,
            attack_type="guard_error",
            guard_model=GUARD_MODEL,
            target_model=TARGET_MODEL,
            response=None,
            latency_ms=elapsed_ms,
        )
