"""
Target LLM Service Layer
Delegates target model invocation to the canonical agentguard.call_target_llm and call_ollama implementations.
Enforces concurrency controls, metrics tracking, and timeout protections without exposing internal details.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import requests
import agentguard
from backend.config import TARGET_TIMEOUT_SECONDS
from backend.services.concurrency_service import (
    ConcurrencyLimitExceeded,
    concurrency_manager,
)
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.target")


def call_target(prompt: str) -> str:
    """
    Invokes the target LLM with the specified user prompt under concurrency control.
    Reuses the canonical AgentGuard v5 target LLM invocation logic.
    Raises exceptions on connection failure, timeout, or model errors.
    """
    logger.info("Invoking target LLM (timeout=%.1fs)...", TARGET_TIMEOUT_SECONDS)
    try:
        with concurrency_manager.target_slot():
            response = agentguard.call_target_llm(prompt, timeout=TARGET_TIMEOUT_SECONDS)
        metrics.record_target_invocation(success=True)
        return response
    except ConcurrencyLimitExceeded:
        raise
    except Exception as exc:
        is_timeout = isinstance(exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(exc).__name__.lower()
        metrics.record_target_invocation(success=False, is_timeout=is_timeout)
        raise


def call_target_chat(messages: List[Dict[str, Any]], timeout: float = None) -> str:
    """
    Invokes the target LLM with a multi-turn conversation sequence under concurrency control.
    Reuses the canonical AgentGuard v5 Ollama client.
    """
    if timeout is None:
        timeout = TARGET_TIMEOUT_SECONDS
    logger.info("Invoking target LLM chat (%d turns, timeout=%.1fs)...", len(messages), timeout)
    try:
        with concurrency_manager.target_slot():
            data = agentguard.call_ollama(
                agentguard.TARGET_MODEL,
                messages,
                timeout=timeout,
            )
        metrics.record_target_invocation(success=True)
        return data["message"]["content"]
    except ConcurrencyLimitExceeded:
        raise
    except Exception as exc:
        is_timeout = isinstance(exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(exc).__name__.lower()
        metrics.record_target_invocation(success=False, is_timeout=is_timeout)
        raise
