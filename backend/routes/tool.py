"""
Tool API Route (Backend v0.5)
Defines POST /api/v1/tool/execute endpoint for authorized mock tool execution.
Guarantees that:
1. Target LLM / clients can never directly execute tools.
2. Every tool invocation passes through AgentGuard Tool Authorization Gate.
3. Blocked, malformed, or unauthorized calls NEVER reach the executor (result is None).
4. Safe telemetry (request_id, decision, risk_level, attack_type, latency_ms) is returned.
"""

import logging
import time
import uuid
from fastapi import APIRouter, Request, status
from backend.schemas import ToolCallRequest, ToolCallResponse
from backend.services.approval_service import execute_with_approval_token
from backend.services.audit_service import audit_service
from backend.services.identity_service import Principal, resolve_principal
from backend.services.policy_service import policy_service
from backend.services.tool_executor import execute_mock_tool
from backend.services.tool_guard_service import authorize_tool_call
from backend.services.tool_registry import tool_registry
from backend.services.tool_result_guard import sanitize_tool_result

logger = logging.getLogger("agentguard.tool_route")

router = APIRouter(tags=["Tool Execution"])


@router.post(
    "/api/v1/tool/execute",
    response_model=ToolCallResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute tool with AgentGuard v0.6 authorization and approval gate",
    description=(
        "Evaluates a proposed tool call through the AgentGuard Tool Authorization Gate.\n\n"
        "1. If an approval_id is supplied, validates action binding, one-time use, and executes if APPROVED.\n"
        "2. Canonical tool-name validation (rejects unknown, homoglyph, and near-match names).\n"
        "3. Risk policy enforcement (blocks high-risk and critical tools unless approved).\n"
        "4. Argument schema validation (types, required fields, bounds, unknown args).\n"
        "5. Argument prompt injection inspection (normalizer, pre-checks, canary detection).\n"
        "6. If ALLOWED, executes deterministic mock tool and sanitizes output.\n"
        "7. If BLOCKED or on ERROR, execution is prevented and result is None."
    ),
    responses={
        200: {
            "description": "Tool authorization and execution evaluation completed (ALLOW, BLOCK, ERROR, or PENDING_APPROVAL).",
            "model": ToolCallResponse,
        },
        422: {
            "description": "Validation error: invalid tool request payload schema.",
        },
        429: {
            "description": "Rate limit exceeded.",
        },
        503: {
            "description": "Inference/execution concurrency limit exceeded.",
        },
    },
)
def execute_tool_endpoint(payload: ToolCallRequest, request: Request) -> ToolCallResponse:
    """
    HTTP route handler for safe tool call authorization and mock execution.
    """
    start_time = time.perf_counter()
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    principal = resolve_principal(request=request)

    # Branch A: Explicit Approval ID Provided (Human Approval Execution Path)
    if payload.approval_id:
        outcome = execute_with_approval_token(
            approval_id=payload.approval_id,
            tool_name=payload.tool_name,
            arguments=payload.arguments,
            request_id=request_id,
            conversation_id=payload.conversation_id,
            executing_principal=principal,
        )
        return ToolCallResponse(
            request_id=request_id,
            decision=outcome["decision"],
            tool_name=payload.tool_name,
            result=outcome.get("result"),
            latency_ms=outcome.get("latency_ms", 0.0),
            risk_level=outcome.get("risk_level"),
            attack_type=outcome.get("attack_type"),
            approval_id=payload.approval_id,
            approval_status=outcome.get("approval_status"),
        )

    # Branch B: Standard Gateway Evaluation (Tool Authorization Gate)
    auth_result = authorize_tool_call(
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        request_id=request_id,
    )

    # Step 2: Handle BLOCK or ERROR decision -> NEVER CALL EXECUTOR
    if auth_result.decision != "ALLOW":
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "Tool execution rejected: request_id=%s decision=%s tool=%s attack_type=%s latency_ms=%.1f",
            request_id,
            auth_result.decision,
            payload.tool_name,
            auth_result.attack_type,
            elapsed_ms,
        )
        audit_service.log_event(
            action="tool_block",
            request_id=request_id,
            principal=principal,
            resource_type="tool",
            resource_id=payload.tool_name,
            decision=auth_result.decision,
            attack_type=auth_result.attack_type,
            tool_name=payload.tool_name,
        )
        return ToolCallResponse(
            request_id=request_id,
            decision=auth_result.decision,
            tool_name=payload.tool_name,
            result=None,
            latency_ms=elapsed_ms,
            risk_level=auth_result.risk_level,
            attack_type=auth_result.attack_type,
            approval_id=None,
            approval_status="PENDING_APPROVAL" if auth_result.risk_level in ("high", "critical") else "DENIED",
        )

    # Step 2.5: Evaluate dynamic security policy
    tool_def = tool_registry.get_tool(payload.tool_name)
    risk_level = tool_def.risk_level if tool_def else auth_result.risk_level or "low"
    pol_eval = policy_service.evaluate_policy(
        principal_id=principal.principal_id,
        tool_name=payload.tool_name,
        risk_level=risk_level,
    )

    if pol_eval.action == "DENY":
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        audit_service.log_event(
            action="policy_block",
            request_id=request_id,
            principal=principal,
            resource_type="policy",
            resource_id=pol_eval.policy_id,
            decision="BLOCK",
            policy_id=pol_eval.policy_id,
            policy_version=pol_eval.policy_version,
            tool_name=payload.tool_name,
            attack_type="policy_denied",
        )
        return ToolCallResponse(
            request_id=request_id,
            decision="BLOCK",
            tool_name=payload.tool_name,
            result=None,
            latency_ms=elapsed_ms,
            risk_level=risk_level,
            attack_type="policy_denied",
            approval_id=None,
            approval_status="DENIED",
        )
    elif pol_eval.action == "REQUIRE_APPROVAL":
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        return ToolCallResponse(
            request_id=request_id,
            decision="PENDING_APPROVAL",
            tool_name=payload.tool_name,
            result=None,
            latency_ms=elapsed_ms,
            risk_level=risk_level,
            attack_type="approval_required",
            approval_id=None,
            approval_status="PENDING_APPROVAL",
        )

    # Step 3: ALLOW -> Execute Deterministic Mock Tool
    try:
        raw_result = execute_mock_tool(
            tool_name=payload.tool_name,
            arguments=payload.arguments,
            is_authorized=True,
        )

        # Step 4: Sanitize Tool Result (Indirect Injection, Canary Secrets, System Spoofing)
        sanitized_result, is_safe, result_attack_type = sanitize_tool_result(raw_result)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        audit_service.log_event(
            action="tool_execution",
            request_id=request_id,
            principal=principal,
            resource_type="tool",
            resource_id=payload.tool_name,
            decision="ALLOW",
            tool_name=payload.tool_name,
        )

        return ToolCallResponse(
            request_id=request_id,
            decision="ALLOW",
            tool_name=payload.tool_name,
            result=sanitized_result,
            latency_ms=elapsed_ms,
            risk_level=auth_result.risk_level,
            attack_type="none" if is_safe else result_attack_type,
            approval_id=None,
            approval_status="NOT_REQUIRED",
        )

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.error(
            "Tool execution error: request_id=%s tool=%s error_type=%s latency_ms=%.1f",
            request_id,
            payload.tool_name,
            type(exc).__name__,
            elapsed_ms,
        )
        return ToolCallResponse(
            request_id=request_id,
            decision="ERROR",
            tool_name=payload.tool_name,
            result=None,
            latency_ms=elapsed_ms,
            risk_level=auth_result.risk_level,
            attack_type="tool_policy_error",
            approval_id=None,
            approval_status="ERROR",
        )
