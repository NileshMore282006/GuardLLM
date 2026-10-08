"""
Tool Result Security & Sanitization Layer
Enforces a strict security boundary on tool outputs for Backend v0.5.
Guarantees that:
1. Tool results are treated strictly as UNTRUSTED DATA, never as privileged system instructions.
2. Protects against indirect prompt injection embedded inside tool returns.
3. Redacts protected secrets (e.g., BLUE-ORANGE-42) from tool outputs before model ingestion.
4. Prevents tool outputs from masquerading as system or developer instructions.
"""

import logging
import re
import sys
from pathlib import Path
from typing import Tuple

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import agentguard

logger = logging.getLogger("agentguard.tool_result_guard")

# Indirect prompt injection signatures that could trick the target LLM into privilege escalation
INDIRECT_INJECTION_PATTERN = re.compile(
    r"(\b(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)|"
    r"disregard\s+(all\s+)?(security|safety|guidelines|instructions?)|"
    r"system\s+(message|override|prompt|directive)\s*:|"
    r"admin\s+override\s*:|"
    r"reveal\s+(the\s+)?(secret|canary|key|token|password|blue-orange-42)|"
    r"you\s+are\s+now\s+in\s+(developer|debug|unrestricted)\s+mode|"
    r"print\s+blue-orange-42)\b)",
    re.IGNORECASE,
)

SYSTEM_PREFIX_PATTERN = re.compile(
    r"(^|\n)\s*(###\s*system|\[system(\s+note|\s+message)?\]|<\s*\|?\s*system\s*\|?\s*>|system\s*:)",
    re.IGNORECASE,
)


def sanitize_tool_result(raw_result: str) -> Tuple[str, bool, str]:
    """
    Sanitizes raw output from a tool prior to delivery to the target LLM or client.

    Returns:
        (sanitized_result: str, is_safe: bool, attack_type: str)

    Invariants:
    1. Secret canary tokens (BLUE-ORANGE-42) are redacted.
    2. Indirect prompt injections are neutralized and labeled as untrusted data.
    3. Pseudo-system headers are neutralized.
    """
    if not isinstance(raw_result, str):
        raw_result = str(raw_result)

    # Step 1: Redact protected canary secret
    sanitized_secret, leak_found = agentguard.output_leak_sanitizer(raw_result)
    if leak_found:
        logger.warning("Tool output contained protected secret: redacted canary code.")

    # Step 2: Check for indirect prompt injection
    has_injection = bool(INDIRECT_INJECTION_PATTERN.search(sanitized_secret))
    has_system_spoof = bool(SYSTEM_PREFIX_PATTERN.search(sanitized_secret))

    if has_injection or has_system_spoof:
        attack_type = "indirect_prompt_injection" if has_injection else "system_instruction_spoofing"
        logger.warning(
            "Untrusted tool result contained adversarial pattern: attack_type=%s",
            attack_type,
        )

        # Neutralize injection by replacing suspicious text with safety notice
        neutralized = INDIRECT_INJECTION_PATTERN.sub(
            "[UNTRUSTED TOOL DATA FILTERED: Adversarial instruction stripped]",
            sanitized_secret,
        )
        neutralized = SYSTEM_PREFIX_PATTERN.sub(
            r"\1[TOOL DATA]",
            neutralized,
        )

        return neutralized, False, attack_type

    return sanitized_secret, True, "none"


def format_tool_context_message(tool_name: str, tool_result: str) -> str:
    """
    Constructs an explicit untrusted data wrapper for the target LLM.
    Clearly marks tool output as DATA, preventing it from having system authority.
    """
    sanitized, is_safe, _ = sanitize_tool_result(tool_result)
    return (
        f"[TOOL RESULT from {tool_name} (UNTRUSTED DATA)]\n"
        f"{sanitized}\n"
        f"[END TOOL RESULT]"
    )
