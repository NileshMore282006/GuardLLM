"""
Context-Aware Guard Service Layer
Analyzes multi-turn conversation context for distributed adversarial attacks,
context poisoning, cross-turn overrides, roleplay escalation, and persistent jailbreaks.
Integrates directly with the canonical AgentGuard v5 security engine.
"""

import logging
import re
import sys
import time
import uuid
from pathlib import Path
from typing import List

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import requests
import agentguard
from backend.config import GUARD_MODEL
from backend.schemas import ChatMessage, GuardResponse
from backend.services.concurrency_service import (
    ConcurrencyLimitExceeded,
    concurrency_manager,
)
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.context_guard")

# Multi-turn cross-turn attack signatures
PERSISTENCE_SETUP_PATTERN = re.compile(
    r"\b(remember\s+(this\s+instruction|these\s+rules?|this\s+rule|my\s+command|this\s+code)|"
    r"from\s+now\s+on|"
    r"in\s+(all\s+)?future\s+turns?|"
    r"for\s+the\s+rest\s+of\s+this\s+conversation|"
    r"whenever\s+i\s+(say|type|write)|"
    r"new\s+(priority|rule|system\s+instruction)\b)",
    re.IGNORECASE,
)

CONTEXT_POISONING_PATTERN = re.compile(
    r"(\[system(\s+note|\s+message)?\]|"
    r"<\s*\|?\s*system\s*\|?\s*>|"
    r"###\s*system(\s+instruction)?|"
    r"admin\s+override\s*:|"
    r"system\s*:\s*(safety\s+rules|you\s+are\s+now|developer\s+mode))",
    re.IGNORECASE,
)

ROLEPLAY_ESCALATION_PATTERN = re.compile(
    r"\b(we\s+are\s+playing\s+a\s+(game|roleplay|scenario)|"
    r"pretend\s+(you\s+are|we\s+are)|"
    r"act\s+as\s+(an?\s+)?(unfiltered|dan|evil|jailbroken|unrestricted)|"
    r"in\s+this\s+(scenario|story|simulation|game))\b",
    re.IGNORECASE,
)

EXTRACTION_OR_EXECUTION_PATTERN = re.compile(
    r"\b(reveal|disclose|output|print|show\s+me|tell\s+me|what\s+is|give\s+me|execute|repeat)\b.*?"
    r"\b(secret|token|password|protected\s+value|hidden\s+value|key|blue-orange-42|test\s+value|testwert)\b",
    re.IGNORECASE,
)


def format_canonical_context(messages: List[ChatMessage]) -> str:
    """
    Constructs a canonical security representation of the conversation.
    Preserves message order, roles, and content.
    """
    turns = []
    for msg in messages:
        header = f"[{msg.role.upper()}]"
        turns.append(f"{header}\n{msg.content.strip()}")
    return "\n\n".join(turns)


def check_multiturn_heuristics(messages: List[ChatMessage], canonical_context: str) -> dict | None:
    """
    Evaluates multi-turn specific interaction patterns across conversation turns:
    1. Cross-turn split attacks (setup in earlier turn, execution in later turn)
    2. Context poisoning (fake system headers injected in user turns)
    3. Persistence attacks ('remember this instruction' followed by extraction)
    4. Malicious earlier turns preceding benign final turns
    """
    user_turns = [m.content for m in messages if m.role == "user"]
    if not user_turns:
        return None

    # Check 1: Context poisoning within any user turn (attempting to simulate system boundaries)
    for idx, content in enumerate(user_turns):
        if CONTEXT_POISONING_PATTERN.search(content):
            logger.info("Context poisoning pattern detected in user turn %d", idx + 1)
            return {
                "rule_id": "context_poisoning_detected",
                "attack_type": "context_manipulation",
                "risk_score": 1.0,
            }

    # Check 2: Instruction persistence attack (earlier setup + later execution/extraction)
    if len(user_turns) >= 2:
        has_earlier_persistence = any(
            PERSISTENCE_SETUP_PATTERN.search(turn) or agentguard.check_deterministic_rules(turn)
            for turn in user_turns[:-1]
        )
        has_earlier_roleplay = any(
            ROLEPLAY_ESCALATION_PATTERN.search(turn)
            for turn in user_turns[:-1]
        )
        final_turn = user_turns[-1]

        if has_earlier_persistence and (
            EXTRACTION_OR_EXECUTION_PATTERN.search(final_turn)
            or agentguard.ACTIVE_EXTRACTION_PATTERN.search(final_turn)
            or re.search(r"\b(execute|run|follow|apply|now)\b", final_turn, re.I)
        ):
            logger.info("Multi-turn instruction persistence / delayed execution detected")
            return {
                "rule_id": "multiturn_persistence_attack",
                "attack_type": "instruction_override",
                "risk_score": 1.0,
            }

        if has_earlier_roleplay and (
            EXTRACTION_OR_EXECUTION_PATTERN.search(final_turn)
            or agentguard.ACTIVE_EXTRACTION_PATTERN.search(final_turn)
            or agentguard.check_deterministic_rules(final_turn)
        ):
            logger.info("Multi-turn roleplay escalation with secret extraction detected")
            return {
                "rule_id": "multiturn_roleplay_escalation",
                "attack_type": "roleplay_attack",
                "risk_score": 1.0,
            }

    # Check 3: Any individual user turn contains an active attack
    # (Addresses: Malicious earlier turn followed by an apparently benign final turn)
    for idx, turn in enumerate(user_turns):
        pre_match = agentguard.deterministic_pre_check(turn)
        if pre_match and pre_match.get("rule_id"):
            logger.info("Deterministic attack detected in user turn %d: %s", idx + 1, pre_match["rule_id"])
            return {
                "rule_id": f"turn_{idx+1}_{pre_match['rule_id']}",
                "attack_type": pre_match.get("attack_type", "instruction_override"),
                "risk_score": 1.0,
            }

    # Check 4: Consolidated user text contains an attack split across turns
    if len(user_turns) >= 2:
        consolidated_user_text = " ".join(user_turns)
        consolidated_match = agentguard.deterministic_pre_check(consolidated_user_text)
        if consolidated_match and consolidated_match.get("rule_id"):
            logger.info("Split attack detected across consolidated user turns: %s", consolidated_match["rule_id"])
            return {
                "rule_id": f"split_{consolidated_match['rule_id']}",
                "attack_type": consolidated_match.get("attack_type", "prompt_injection"),
                "risk_score": 1.0,
            }

    return None


def evaluate_chat_context(messages: List[ChatMessage]) -> GuardResponse:
    """
    Evaluates the full conversation context through AgentGuard v5.
    Guarantees that:
    1. The entire conversation context is evaluated together.
    2. Multi-turn attacks, persistence patterns, and poisoning are blocked.
    3. Fails closed on any unexpected exception.
    """
    request_id = str(uuid.uuid4())
    start_time = time.perf_counter()

    try:
        # Step 1: Build canonical context representation
        canonical_context = format_canonical_context(messages)

        # Step 2: Multi-turn deterministic and context heuristic checks
        heuristic_match = check_multiturn_heuristics(messages, canonical_context)
        if heuristic_match:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_guard_invocation(success=True)
            metrics.record_decision("BLOCK")
            logger.info(
                "Multi-turn context attack BLOCKED: request_id=%s rule=%s attack_type=%s latency_ms=%.1f",
                request_id,
                heuristic_match["rule_id"],
                heuristic_match["attack_type"],
                elapsed_ms,
            )
            return GuardResponse(
                request_id=request_id,
                decision="BLOCK",
                risk_score=heuristic_match["risk_score"],
                attack_type=heuristic_match["attack_type"],
                guard_model=GUARD_MODEL,
                latency_ms=elapsed_ms,
            )

        # Step 3: Run canonical context through the v5 security engine under concurrency control
        with concurrency_manager.guard_slot():
            guard_result = agentguard.guard_check(canonical_context)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        decision = guard_result.get("decision", "BLOCK")
        if decision not in ("ALLOW", "BLOCK"):
            decision = "BLOCK"

        raw_risk = guard_result.get("risk_score", 1.0)
        try:
            risk_score = float(raw_risk)
            risk_score = max(0.0, min(1.0, risk_score))
        except (ValueError, TypeError):
            risk_score = 1.0
            decision = "BLOCK"

        attack_type = str(guard_result.get("attack_type", "guard_error"))
        is_guard_error = (attack_type == "guard_error" or "error" in guard_result)
        is_timeout = "timeout" in str(guard_result.get("error", "")).lower()

        metrics.record_guard_invocation(success=not is_guard_error, is_timeout=is_timeout)
        metrics.record_decision(decision)

        logger.info(
            "Context evaluation completed: request_id=%s decision=%s risk_score=%.2f attack_type=%s latency_ms=%.1f",
            request_id,
            decision,
            risk_score,
            attack_type,
            elapsed_ms,
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
        raise

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        is_timeout = isinstance(exc, (requests.exceptions.Timeout, TimeoutError)) or "timeout" in type(exc).__name__.lower()
        metrics.record_guard_invocation(success=False, is_timeout=is_timeout)
        metrics.record_decision("BLOCK")
        logger.error(
            "Context evaluation failure (failing closed): request_id=%s error_type=%s is_timeout=%s latency_ms=%.1f",
            request_id,
            type(exc).__name__,
            is_timeout,
            elapsed_ms,
        )
        return GuardResponse(
            request_id=request_id,
            decision="BLOCK",
            risk_score=1.0,
            attack_type="guard_timeout" if is_timeout else "guard_error",
            guard_model=GUARD_MODEL,
            latency_ms=elapsed_ms,
        )
