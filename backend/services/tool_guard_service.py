"""
Tool Authorization Gate Service Layer (Backend v0.5)
Enforces security policy and argument safety before any tool/function call is allowed to execute.
Guarantees that:
1. Unknown, ambiguous, or near-match tool names are strictly BLOCKED.
2. High-risk and critical tools are BLOCKED by default in v0.5.
3. Tool arguments are treated as UNTRUSTED user input and analyzed for prompt injection,
   encoded payloads, homoglyphs, reversed text, and secret extraction attempts.
4. Schema violations (wrong types, missing args, unknown args, oversized payloads) are BLOCKED.
5. Invariant: A tool can NEVER execute without explicit ALLOW authorization.
"""

import codecs
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure workspace root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import agentguard
from backend.config import (
    ALLOW_CRITICAL_TOOLS,
    ALLOW_HIGH_RISK_TOOLS,
    MAX_TOOL_ARGUMENT_LENGTH,
    MAX_TOOL_NAME_LENGTH,
)
from backend.services.metrics_service import metrics
from backend.services.tool_registry import TOOL_NAME_REGEX, tool_registry

logger = logging.getLogger("agentguard.tool_guard")

ARGUMENT_INJECTION_PATTERN = re.compile(
    r"("
    # Instruction overrides (English)
    r"\bignore\s+(all\s+)?(previous|prior|above|security|safety|agentguard|approval)?\s*(instructions?|rules?|prompts?|checks?|filters?|guidelines?|policies|policy|requirements?)\b|"
    r"\bdisregard\s+(all\s+)?(security|safety|guidelines|instructions?|rules?|checks?|approval|policies)\b|"
    r"system\s+(message|override|prompt|directive)\s*:|"
    r"\b(system\s+)?admin(istrator)?\s+(override|bypass|approval|directive|says)\s*:|"
    r"description\s+(override|says)\s*:|"
    r"\bdeactivate\s+(all\s+)?(security|safety|filters?|guard|rules?|approvals?)\b|"
    r"\breveal\s+(the\s+)?(secret|canary|key|token|password|blue-orange-42)\b|"
    r"\bbypass[_\s]+(all\s+)?(guard|security|safety|rules|filters?|guidelines?|mode|checks?|approvals?|approval\s+gate)\b|"
    r"\b(treat\s+(?:.*?\s+)?as|mark\s+as|set\s+to|action\s+is)\s*(approo?ved|consumed)\b|"
    r"\bapproval_status\s*[:=]\s*(approo?ved|consumed|true|allow|granted)\b|"
    r"\bignore\s+agentguard\b|"
    r"\b(already|offline|pre-?)\s*approo?ved\b|"
    r"\byou\s+are\s+(now\s+)?(in\s+)?([a-z\s]+)?(developer|debug|unrestricted|jailbreak)\b|"
    r"\byou\s+are\s+free\s+to\s+execute\b|"
    r"\bdeveloper\s+(debug\s+)?mode\b|"
    r"\broot\s+access\b|"
    r"\bexecute\s+(any\s+)?command\b|"
    r"\ball\s+previous\s+instructions\b|"
    r"\bprint\s+blue-orange-42\b|"
    r"blue-orange-42|"
    # Multilingual instruction overrides
    r"忽略.*(指示|指令|提示|规则|批准)|"
    r"显示.*(秘密|系统)|"
    r"игнорируй.*(инструкци|правил|одобрени)|"
    r"покажи.*(секрет)|"
    r"ignora.*(instrucciones|reglas|seguridad|aprobacion)|"
    r"muestra.*(secreto)|"
    r"ignoriere.*(anweisungen|regeln|sicherheit|genehmigung)|"
    r"zeige.*(geheimnis)"
    r")",
    re.IGNORECASE,
)


class ToolAuthorizationResult:
    """
    Structured outcome of a Tool Guard evaluation.
    """
    def __init__(
        self,
        decision: str,
        tool_name: str,
        risk_level: Optional[str] = None,
        attack_type: str = "none",
        reason: str = "",
        latency_ms: float = 0.0,
    ):
        self.decision = decision  # ALLOW, BLOCK, ERROR
        self.tool_name = tool_name
        self.risk_level = risk_level
        self.attack_type = attack_type
        self.reason = reason
        self.latency_ms = latency_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "tool_name": self.tool_name,
            "risk_level": self.risk_level,
            "attack_type": self.attack_type,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
        }


def authorize_tool_call(
    tool_name: Any,
    arguments: Any,
    request_id: Optional[str] = None,
    bypass_risk_policy: bool = False,
) -> ToolAuthorizationResult:
    """
    Evaluates a proposed tool call through the AgentGuard tool authorization gate.

    Pipeline:
    1. Canonical tool-name validation (rejection of homoglyphs, case variations, unknown tools).
    2. Tool risk-level policy evaluation (blocking high/critical side-effect tools by default).
    3. Argument schema validation (type safety, required args, no unexpected keys, bounds).
    4. Argument injection analysis (normalizing and detecting adversarial prompts inside arguments).
    """
    start_time = time.perf_counter()

    try:
        # Step 1: Tool Name Validation
        if not isinstance(tool_name, str) or not tool_name.strip():
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=str(tool_name),
                attack_type="malformed_tool_call",
                reason="tool_name must be a non-empty string.",
                latency_ms=elapsed_ms,
            )

        if len(tool_name) > MAX_TOOL_NAME_LENGTH:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name[:32] + "...",
                attack_type="oversized_tool_name",
                reason=f"tool_name exceeds maximum length of {MAX_TOOL_NAME_LENGTH}.",
                latency_ms=elapsed_ms,
            )

        # Strict canonical check (rejects case variations like Get_Weather, spaces, homoglyphs)
        if not TOOL_NAME_REGEX.match(tool_name):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name,
                attack_type="tool_name_obfuscation",
                reason="tool_name violates canonical format (must be lowercase alphanumeric and underscores only).",
                latency_ms=elapsed_ms,
            )

        tool_def = tool_registry.get_tool(tool_name)
        if tool_def is None:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            logger.warning("Tool authorization BLOCKED: unknown tool '%s'", tool_name)
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name,
                attack_type="unknown_tool",
                reason=f"Tool '{tool_name}' is not registered in AgentGuard registry.",
                latency_ms=elapsed_ms,
            )

        risk_level = tool_def.risk_level


        # Step 3: Argument Structure & Boundary Validation
        if not isinstance(arguments, dict):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name,
                risk_level=risk_level,
                attack_type="malformed_tool_arguments",
                reason="arguments must be a key-value dictionary.",
                latency_ms=elapsed_ms,
            )

        try:
            serialized_args = json.dumps(arguments)
        except (TypeError, ValueError):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name,
                risk_level=risk_level,
                attack_type="malformed_tool_arguments",
                reason="arguments could not be serialized to valid JSON.",
                latency_ms=elapsed_ms,
            )

        if len(serialized_args) > MAX_TOOL_ARGUMENT_LENGTH:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            metrics.record_tool_call("BLOCK")
            return ToolAuthorizationResult(
                decision="BLOCK",
                tool_name=tool_name,
                risk_level=risk_level,
                attack_type="oversized_arguments",
                reason=f"Argument payload exceeds maximum length of {MAX_TOOL_ARGUMENT_LENGTH}.",
                latency_ms=elapsed_ms,
            )

        # Disallow unknown arguments
        allowed_spec = tool_def.allowed_arguments
        for arg_key in arguments.keys():
            if arg_key not in allowed_spec:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                metrics.record_tool_call("BLOCK")
                return ToolAuthorizationResult(
                    decision="BLOCK",
                    tool_name=tool_name,
                    risk_level=risk_level,
                    attack_type="unexpected_argument",
                    reason=f"Unexpected argument '{arg_key}' is not allowed for tool '{tool_name}'.",
                    latency_ms=elapsed_ms,
                )

        # Check required arguments and type adherence
        for required_key, spec in allowed_spec.items():
            if spec.get("required", False) and required_key not in arguments:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                metrics.record_tool_call("BLOCK")
                return ToolAuthorizationResult(
                    decision="BLOCK",
                    tool_name=tool_name,
                    risk_level=risk_level,
                    attack_type="missing_required_argument",
                    reason=f"Missing required argument '{required_key}' for tool '{tool_name}'.",
                    latency_ms=elapsed_ms,
                )

            if required_key in arguments:
                val = arguments[required_key]
                if val is None:
                    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                    metrics.record_tool_call("BLOCK")
                    return ToolAuthorizationResult(
                        decision="BLOCK",
                        tool_name=tool_name,
                        risk_level=risk_level,
                        attack_type="null_argument_prohibited",
                        reason=f"Argument '{required_key}' must not be null.",
                        latency_ms=elapsed_ms,
                    )

                expected_type = spec.get("type", "str")
                if expected_type == "str":
                    if not isinstance(val, str):
                        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        metrics.record_tool_call("BLOCK")
                        return ToolAuthorizationResult(
                            decision="BLOCK",
                            tool_name=tool_name,
                            risk_level=risk_level,
                            attack_type="invalid_argument_type",
                            reason=f"Argument '{required_key}' must be a string, got {type(val).__name__}.",
                            latency_ms=elapsed_ms,
                        )
                    if not val.strip() and spec.get("required", False):
                        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        metrics.record_tool_call("BLOCK")
                        return ToolAuthorizationResult(
                            decision="BLOCK",
                            tool_name=tool_name,
                            risk_level=risk_level,
                            attack_type="empty_required_argument",
                            reason=f"Required argument '{required_key}' must not be empty or whitespace-only.",
                            latency_ms=elapsed_ms,
                        )
                    max_len = spec.get("max_length")
                    if max_len and len(val) > max_len:
                        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        metrics.record_tool_call("BLOCK")
                        return ToolAuthorizationResult(
                            decision="BLOCK",
                            tool_name=tool_name,
                            risk_level=risk_level,
                            attack_type="oversized_argument_value",
                            reason=f"Argument '{required_key}' exceeds max length of {max_len}.",
                            latency_ms=elapsed_ms,
                        )

        # Step 4: Security Inspection of Untrusted Arguments (Prompt Injection, Obfuscation, Canary Extraction)
        for arg_key, arg_val in arguments.items():
            if isinstance(arg_val, str):
                # 4a. Run argument through AgentGuard v5 Normalizer
                norm_info = agentguard.input_normalizer(arg_val)
                normalized_text = norm_info["normalized"]
                candidates = [
                    arg_val,
                    normalized_text,
                    arg_val[::-1],
                    codecs.decode(arg_val, "rot_13"),
                ] + norm_info.get("decoded_payloads", [])

                for cand in candidates:
                    # 4b. Check for Canary Secret Extraction (BLUE-ORANGE-42)
                    for secret in agentguard.DEFAULT_PROTECTED_VALUES:
                        if secret.lower() in cand.lower():
                            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                            metrics.record_tool_call("BLOCK")
                            logger.warning("Secret canary extraction detected in tool argument '%s'", arg_key)
                            return ToolAuthorizationResult(
                                decision="BLOCK",
                                tool_name=tool_name,
                                risk_level=risk_level,
                                attack_type="secret_extraction",
                                reason="Attempt to access or extract protected secret canary token.",
                                latency_ms=elapsed_ms,
                            )

                    # 4c. Check for prompt injection signatures
                    if ARGUMENT_INJECTION_PATTERN.search(cand):
                        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                        metrics.record_tool_call("BLOCK")
                        logger.warning("Prompt injection detected in tool argument '%s'", arg_key)
                        return ToolAuthorizationResult(
                            decision="BLOCK",
                            tool_name=tool_name,
                            risk_level=risk_level,
                            attack_type="prompt_injection_in_arguments",
                            reason="Adversarial instruction override detected in tool argument.",
                            latency_ms=elapsed_ms,
                        )

                # 4d. Deterministic pre-checks (covers reverse text, rot13, base64 overrides)
                pre_match = agentguard.deterministic_pre_check(
                    arg_val,
                    normalized_info=norm_info,
                    structured_info={"has_structured_data": False},
                )
                if pre_match and pre_match.get("attack_type") != "none":
                    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                    metrics.record_tool_call("BLOCK")
                    attack_type = pre_match.get("attack_type", "instruction_override")
                    logger.warning("Deterministic pre-check blocked tool argument: attack_type=%s", attack_type)
                    return ToolAuthorizationResult(
                        decision="BLOCK",
                        tool_name=tool_name,
                        risk_level=risk_level,
                        attack_type=attack_type,
                        reason=f"Security policy violation in argument: {attack_type}.",
                        latency_ms=elapsed_ms,
                    )

        # Step 4: Risk Policy & Side Effect Enforcement
        if not bypass_risk_policy:
            if risk_level == "critical" and not ALLOW_CRITICAL_TOOLS:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                metrics.record_tool_call("BLOCK")
                logger.warning("Tool authorization BLOCKED: critical tool '%s' rejected by policy", tool_name)
                return ToolAuthorizationResult(
                    decision="BLOCK",
                    tool_name=tool_name,
                    risk_level=risk_level,
                    attack_type="critical_tool_escalation",
                    reason="Critical-risk tools are prohibited from execution in Backend v0.5.",
                    latency_ms=elapsed_ms,
                )

            if risk_level == "high" and not ALLOW_HIGH_RISK_TOOLS:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                metrics.record_tool_call("BLOCK")
                logger.warning("Tool authorization BLOCKED: high-risk tool '%s' rejected by policy", tool_name)
                return ToolAuthorizationResult(
                    decision="BLOCK",
                    tool_name=tool_name,
                    risk_level=risk_level,
                    attack_type="high_risk_tool_escalation",
                    reason="High-risk tools are disabled by default in Backend v0.5.",
                    latency_ms=elapsed_ms,
                )

        # All checks passed: ALLOW
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        metrics.record_tool_call("ALLOW")
        logger.info(
            "Tool call ALLOWED: name=%s risk=%s latency_ms=%.1f",
            tool_name,
            risk_level,
            elapsed_ms,
        )
        return ToolAuthorizationResult(
            decision="ALLOW",
            tool_name=tool_name,
            risk_level=risk_level,
            attack_type="none",
            reason="Tool call satisfies authorization and argument safety policy.",
            latency_ms=elapsed_ms,
        )

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        metrics.record_tool_call("ERROR")
        logger.error(
            "Tool authorization gate error (failing closed): tool=%s error_type=%s latency_ms=%.1f",
            tool_name,
            type(exc).__name__,
            elapsed_ms,
        )
        return ToolAuthorizationResult(
            decision="ERROR",
            tool_name=str(tool_name),
            attack_type="tool_policy_error",
            reason="Internal policy evaluation failure.",
            latency_ms=elapsed_ms,
        )


def detect_tool_call(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Detects if a model response proposes a tool / function invocation.
    Supports:
    1. Structured JSON: {"tool_name": "...", "arguments": {...}}
    2. Markdown-fenced JSON blocks.
    3. ReAct Action / Action Input text patterns.

    Returns:
        (tool_name, arguments_dict) or None if no tool call was proposed.
    """
    if not isinstance(text, str) or not text.strip():
        return None

    # 1. Search for markdown code fences with json
    code_fence_pattern = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
    fence_match = code_fence_pattern.search(text)
    candidates = []
    if fence_match:
        candidates.append(fence_match.group(1))

    # 2. Check full text if stripped starts and ends with braces
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)

    # 3. Check for standalone JSON substring containing "tool_name"
    raw_json_match = re.search(r'(\{\s*"tool_name"\s*:\s*".*?"\s*,\s*"arguments"\s*:\s*\{.*?\}\s*\})', text, re.DOTALL)
    if raw_json_match:
        candidates.append(raw_json_match.group(1))

    for item in candidates:
        if not item:
            continue
        try:
            data = json.loads(item)
            if isinstance(data, dict):
                t_name = data.get("tool_name") or data.get("tool") or data.get("action")
                args = data.get("arguments") or data.get("action_input") or data.get("args") or {}
                if isinstance(t_name, str) and t_name.strip():
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {"query": args}
                    if not isinstance(args, dict):
                        args = {}
                    return t_name.strip(), args
        except Exception:
            continue

    # 4. Action / Action Input text format
    action_match = re.search(r"Action\s*:\s*([a-zA-Z0-9_-]+)", text, re.IGNORECASE)
    if action_match:
        t_name = action_match.group(1).strip()
        args: Dict[str, Any] = {}
        input_match = re.search(r"Action Input\s*:\s*(\{.*?\})", text, re.DOTALL | re.IGNORECASE)
        if input_match:
            try:
                parsed_args = json.loads(input_match.group(1))
                if isinstance(parsed_args, dict):
                    args = parsed_args
            except Exception:
                args = {}
        else:
            input_line = re.search(r"Action Input\s*:\s*([^\n\r]+)", text, re.IGNORECASE)
            if input_line:
                args = {"query": input_line.group(1).strip()}
        return t_name, args

    return None
