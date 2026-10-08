"""
Guard Service Layer
Orchestrates calls to the canonical AgentGuard v5 security engine.
Maintains strict fail-closed semantics, concurrency protection, metrics, and safe diagnostic logging.
"""

import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

# Ensure workspace root is in sys.path so agentguard is importable from anywhere
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import requests
import agentguard
from backend.config import GUARD_MODEL
from backend.schemas import GuardResponse
from backend.services.concurrency_service import (
    ConcurrencyLimitExceeded,
    concurrency_manager,
)
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.service")


def evaluate_prompt(prompt: str, request_id: Optional[str] = None) -> GuardResponse:
    """
    Evaluates a user prompt through the AgentGuard v5 security engine under concurrency control.

    Returns a GuardResponse containing the decision (ALLOW/BLOCK),
    risk score, attack type, model identifier, and latency in milliseconds.
    Never exposes internal system prompts, target secrets, or raw model output.
    Fails closed on any unexpected exception or timeout.
    """
    if not request_id or not request_id.strip():
        request_id = str(uuid.uuid4())
    start_time = time.perf_counter()

    try:
        # Acquire Guard concurrency slot (raises ConcurrencyLimitExceeded if full)
        with concurrency_manager.guard_slot():
            result = agentguard.guard_check(prompt)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Extract values produced by AgentGuard v5
        decision = result.get("decision", "BLOCK")
        if decision not in ("ALLOW", "BLOCK"):
            decision = "BLOCK"

        raw_risk = result.get("risk_score", 1.0)
        try:
            risk_score = float(raw_risk)
            risk_score = max(0.0, min(1.0, risk_score))
        except (ValueError, TypeError):
            risk_score = 1.0
            decision = "BLOCK"

        attack_type = str(result.get("attack_type", "guard_error"))
        is_guard_error = (attack_type == "guard_error" or "error" in result)
        is_timeout = "timeout" in str(result.get("error", "")).lower()

        # Record metrics
        metrics.record_guard_invocation(success=not is_guard_error, is_timeout=is_timeout)
        metrics.record_decision(decision)

        # Safe diagnostic logging (strictly metadata only, no user prompt or secrets)
        logger.info(
            "Security evaluation completed: request_id=%s decision=%s risk_score=%.2f attack_type=%s latency_ms=%.1f model=%s",
            request_id,
            decision,
            risk_score,
            attack_type,
            elapsed_ms,
            GUARD_MODEL,
        )

        return GuardResponse(
            request_id=request_id,
            decision=decision,
            risk_score=risk_score,
            attack_type=attack_type,
            guard_model=GUARD_MODEL,
            latency_ms=elapsed_ms,
        )

    except ConcurrencyLimitExceeded:
        # Re-raise concurrency exception so FastAPI structured handler responds with HTTP 503
        raise

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        is_timeout = isinstance(exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(exc).__name__.lower()
        metrics.record_guard_invocation(success=False, is_timeout=is_timeout)
        metrics.record_decision("BLOCK")

        # Log safe error metadata only - never log prompt or stack traces
        logger.error(
            "Security evaluation failure (failing closed): request_id=%s exception_type=%s is_timeout=%s latency_ms=%.1f",
            request_id,
            type(exc).__name__,
            is_timeout,
            elapsed_ms,
        )

        # Fail closed
        return GuardResponse(
            request_id=request_id,
            decision="BLOCK",
            risk_score=1.0,
            attack_type="guard_timeout" if is_timeout else "guard_error",
            guard_model=GUARD_MODEL,
            latency_ms=elapsed_ms,
        )
