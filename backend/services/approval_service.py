"""
Approval Service Layer (Backend v0.6)
Orchestrates human approval lifecycle, risk evaluation, cryptographic action binding,
canonical argument hashing, and safe one-time execution for high-risk tools.

CENTRAL SECURITY INVARIANTS:
1. THE MODEL MUST NEVER BE ABLE TO APPROVE ITS OWN HIGH-RISK ACTION.
   Model output text, conversation turns, prompt instructions, tool arguments, or tool results
   can NEVER transition an approval request to APPROVED.
2. CRYPTOGRAPHIC & STRUCTURAL ACTION BINDING:
   Every approval is strictly bound to:
   - Tool canonical name
   - Canonicalized SHA-256 argument hash
   - Request and conversation session context
   - Risk classification
   Any modification to arguments or tool after approval invalidates the authorization.
3. ONE-TIME EXECUTION (REPLAY RESISTANT):
   An approval can execute AT MOST ONCE. After execution: APPROVED -> CONSUMED.
   Any subsequent execution attempt with the same approval ID is blocked and flagged as a replay attack.
4. SAFE TELEMETRY & NO SENSITIVE DATA EXPOSURE:
   Raw arguments, canary secrets, system prompts, and internal reasoning are NEVER exposed
   in approval summaries, responses, or audit logs.
"""

import hashlib
import json
import logging
import re
import secrets
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
    APPROVAL_TTL_SECONDS,
    MEDIUM_RISK_REQUIRE_APPROVAL,
)
from backend.services.approval_store import (
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalRecord,
    ApprovalReplayError,
    ApprovalStatus,
    InvalidApprovalStateError,
    approval_store,
)
from backend.services.audit_service import audit_service
from backend.services.authorization_service import ForbiddenError
from backend.services.identity_service import Principal
from backend.services.metrics_service import metrics
from backend.services.policy_service import policy_service
from backend.services.tool_executor import execute_mock_tool
from backend.services.tool_guard_service import authorize_tool_call
from backend.services.tool_registry import tool_registry
from backend.services.tool_result_guard import sanitize_tool_result

logger = logging.getLogger("agentguard.approval_service")

# Cryptographic approval ID format: appr_ followed by 32 hex chars (128 bits entropy)
APPROVAL_ID_REGEX = re.compile(r"^appr_[a-f0-9]{32}$")


class ActionBindingMismatchError(Exception):
    """Raised when current action arguments or tool do not match the approved hash/binding."""
    pass


def generate_approval_id() -> str:
    """
    Generates a cryptographically strong, non-predictable unique approval ID.
    Entropy: 128 bits (32 hex characters).
    """
    return f"appr_{secrets.token_hex(16)}"


def validate_approval_id_format(approval_id: str) -> bool:
    """
    Validates whether an approval ID conforms strictly to the expected format.
    Rejects malformed, empty, or malicious ID strings.
    """
    if not isinstance(approval_id, str):
        return False
    return bool(APPROVAL_ID_REGEX.match(approval_id.strip()))


def canonicalize_arguments(arguments: Dict[str, Any]) -> str:
    """
    Produces a deterministic canonical representation of tool arguments.
    Enforces sorted keys and compact separators to guarantee consistent SHA-256 hashes.
    """
    if not isinstance(arguments, dict):
        return "{}"
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_arguments_hash(arguments: Dict[str, Any]) -> str:
    """
    Computes SHA-256 hash of canonicalized arguments.
    """
    canonical_repr = canonicalize_arguments(arguments)
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


def generate_safe_arguments_summary(arguments: Dict[str, Any]) -> str:
    """
    Creates a sanitized, redacted, human-readable summary of tool arguments for UI/API review.
    Guarantees that canary secrets, passwords, long raw texts, or sensitive tokens are not leaked.
    """
    if not isinstance(arguments, dict) or not arguments:
        return "none"

    summary_parts = []
    sensitive_keys = {"password", "secret", "token", "key", "auth", "credential", "private"}

    for key, val in sorted(arguments.items()):
        # Check for sensitive key names
        if any(sens in key.lower() for sens in sensitive_keys):
            summary_parts.append(f"{key}: [REDACTED]")
            continue

        if isinstance(val, str):
            # Check for canary secret
            has_canary = False
            for secret in agentguard.DEFAULT_PROTECTED_VALUES:
                if secret.lower() in val.lower():
                    has_canary = True
                    break
            if has_canary:
                summary_parts.append(f"{key}: [REDACTED_SECRET]")
                continue

            # Mask email address: u***@domain.com
            if "@" in val and "." in val and " " not in val:
                parts = val.split("@", 1)
                user = parts[0]
                masked_user = user[0] + "***" if len(user) > 1 else "***"
                summary_parts.append(f"{key}: {masked_user}@{parts[1]}")
            elif key.lower() in ("body", "content", "payload", "code", "text", "raw_text"):
                summary_parts.append(f"{key}: [{len(val)} chars]")
            else:
                # Truncate strings to safe length
                safe_val = val.strip()
                if len(safe_val) > 40:
                    safe_val = safe_val[:37] + "..."
                summary_parts.append(f"{key}: '{safe_val}'")
        else:
            summary_parts.append(f"{key}: {repr(val)}")

    return "; ".join(summary_parts)


def requires_approval(risk_level: Optional[str]) -> bool:
    """
    Risk-based approval policy evaluation.
    - LOW: No approval required by default.
    - MEDIUM: Configurable (default false or depends on policy).
    - HIGH: Approval strictly required.
    - CRITICAL: Approval strictly required (never automatic).
    - Unknown or missing: Fail closed (requires approval or blocked).
    """
    if not risk_level or not isinstance(risk_level, str):
        return True  # Fail closed

    norm_risk = risk_level.strip().lower()
    if norm_risk == "low":
        return False
    elif norm_risk == "medium":
        return MEDIUM_RISK_REQUIRE_APPROVAL
    elif norm_risk in ("high", "critical"):
        return True
    else:
        # Unknown risk: fail closed
        return True


def create_approval_request(
    tool_name: str,
    arguments: Dict[str, Any],
    request_id: str,
    conversation_id: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    principal: Optional[Principal] = None,
    principal_id: Optional[str] = None,
) -> Tuple[str, Optional[ApprovalRecord], str]:
    """
    Evaluates tool call and creates an approval request if required by risk policy.

    Returns:
        Tuple of (decision, approval_record, reason)
        - If low-risk: ("ALLOW", None, "low_risk_no_approval_required")
        - If invalid/injection: ("BLOCK", None, "validation_error_or_injection")
        - If high/critical risk: ("PENDING_APPROVAL", ApprovalRecord, "high_risk_requires_approval")
    """
    p_id = principal.principal_id if principal else (principal_id or "user-demo")

    # Step 1: Tool Guard Validation (canonical name, argument types, bounds, prompt injection)
    auth_result = authorize_tool_call(
        tool_name,
        arguments,
        request_id=request_id,
        bypass_risk_policy=True,
    )
    if auth_result.decision != "ALLOW":
        logger.warning(
            "Approval creation rejected by Tool Guard: tool=%s decision=%s attack_type=%s reason=%s",
            tool_name,
            auth_result.decision,
            auth_result.attack_type,
            auth_result.reason,
        )
        audit_service.log_event(
            action="tool_block",
            request_id=request_id,
            principal=principal,
            principal_id=p_id,
            resource_type="tool",
            resource_id=tool_name,
            decision="BLOCK",
            attack_type=auth_result.attack_type,
            tool_name=tool_name,
        )
        return "BLOCK", None, auth_result.attack_type or auth_result.reason

    # Step 2: Risk Classification & Policy Resolution
    tool_def = tool_registry.get_tool(tool_name)
    if tool_def is None:
        audit_service.log_event(
            action="tool_block",
            request_id=request_id,
            principal=principal,
            principal_id=p_id,
            resource_type="tool",
            resource_id=tool_name,
            decision="BLOCK",
            attack_type="unknown_tool",
            tool_name=tool_name,
        )
        return "BLOCK", None, "unknown_tool"

    risk_level = tool_def.risk_level

    # Evaluate dynamic security policy for this principal, tool, and risk level
    pol_eval = policy_service.evaluate_policy(
        principal_id=p_id,
        tool_name=tool_name,
        risk_level=risk_level,
    )

    if pol_eval.action == "DENY":
        logger.warning(
            "Action blocked by policy: tool=%s principal=%s policy_id=%s reason=%s",
            tool_name,
            p_id,
            pol_eval.policy_id,
            pol_eval.reason,
        )
        audit_service.log_event(
            action="policy_block",
            request_id=request_id,
            principal=principal,
            principal_id=p_id,
            resource_type="policy",
            resource_id=pol_eval.policy_id,
            decision="BLOCK",
            attack_type="policy_denied",
            policy_id=pol_eval.policy_id,
            policy_version=pol_eval.policy_version,
            tool_name=tool_name,
        )
        return "BLOCK", None, "policy_denied"

    if pol_eval.action == "ALLOW":
        # HARD INVARIANT: Critical actions can NEVER automatically execute, even if an ALLOW policy exists.
        if risk_level == "critical":
            needs_approval = True
        else:
            needs_approval = False
    elif pol_eval.action == "REQUIRE_APPROVAL":
        needs_approval = True
    else:
        # Default security policy fallback
        needs_approval = requires_approval(risk_level)

    if not needs_approval:
        # Low risk or allowed by policy: no approval required
        return "ALLOW", None, "no_approval_required"

    # Step 3: High or Critical Risk -> Create Safe Approval Request
    approval_id = generate_approval_id()
    arg_hash = compute_arguments_hash(arguments)
    safe_summary = generate_safe_arguments_summary(arguments)

    p_tenant = getattr(principal, "tenant_id", "default")
    reason = pol_eval.reason or f"Action requires approval due to {risk_level} risk level."

    record = approval_store.create_approval(
        approval_id=approval_id,
        request_id=request_id,
        tool_name=tool_name,
        risk_level=risk_level,
        reason=reason,
        arguments_summary=safe_summary,
        arguments_hash=arg_hash,
        canonical_arguments=arguments,
        conversation_id=conversation_id,
        principal_id=p_id,
        policy_id=pol_eval.policy_id,
        policy_version=pol_eval.policy_version,
        ttl_seconds=ttl_seconds or APPROVAL_TTL_SECONDS,
        tenant_id=p_tenant,
    )

    audit_service.log_event(
        action="approval_create",
        request_id=request_id,
        principal=principal,
        principal_id=p_id,
        tenant_id=p_tenant,
        resource_type="approval",
        resource_id=approval_id,
        decision="PENDING_APPROVAL",
        policy_id=pol_eval.policy_id,
        policy_version=pol_eval.policy_version,
        approval_id=approval_id,
        tool_name=tool_name,
    )

    return "PENDING_APPROVAL", record, reason


def verify_action_binding(
    record: ApprovalRecord,
    tool_name: str,
    arguments: Dict[str, Any],
    conversation_id: Optional[str] = None,
    executing_principal: Optional[Principal] = None,
) -> Tuple[bool, str]:
    """
    Cryptographically verifies that the action being executed matches the exact approved action,
    including tool, canonical argument hash, conversation context, identity, and policy version.
    """
    # 1. Check tool name
    if record.tool_name != tool_name:
        metrics.record_approval_binding_failure()
        logger.warning(
            "Approval binding mismatch on tool_name: approved=%s attempted=%s",
            record.tool_name,
            tool_name,
        )
        return False, "tool_name_mismatch"

    # 2. Check argument hash
    current_hash = compute_arguments_hash(arguments)
    if record.arguments_hash != current_hash:
        metrics.record_approval_binding_failure()
        logger.warning(
            "Approval binding mismatch on argument hash: approved_hash=%s attempted_hash=%s",
            record.arguments_hash,
            current_hash,
        )
        return False, "argument_hash_mismatch"

    # 3. Check conversation binding if specified
    if record.conversation_id and conversation_id:
        if record.conversation_id != conversation_id:
            metrics.record_approval_binding_failure()
            logger.warning(
                "Approval binding mismatch on conversation_id: approved=%s attempted=%s",
                record.conversation_id,
                conversation_id,
            )
            return False, "conversation_id_mismatch"

    # 4. Check principal binding (prevent approval transfer)
    if executing_principal is not None:
        if not (executing_principal.has_role("admin") or executing_principal.principal_id == record.principal_id):
            metrics.record_approval_binding_failure()
            logger.warning(
                "Approval binding mismatch on principal: approved=%s attempted=%s",
                record.principal_id,
                executing_principal.principal_id,
            )
            return False, "principal_mismatch"

    # 5. Check policy version binding
    if record.policy_id:
        pol = policy_service.get_policy(record.policy_id)
        if pol is None or pol.deleted or not pol.enabled or pol.version != record.policy_version:
            metrics.record_approval_binding_failure()
            logger.warning(
                "Approval binding mismatch on policy: id=%s approved_ver=%s current_ver=%s",
                record.policy_id,
                record.policy_version,
                getattr(pol, "version", None),
            )
            return False, "policy_version_mismatch"

    # 6. Check tenant ownership binding
    if executing_principal is not None:
        executing_tenant = getattr(executing_principal, "tenant_id", "default")
        is_global_admin = getattr(executing_principal, "global_admin", False) or (
            hasattr(executing_principal, "has_role") and executing_principal.has_role("global_admin")
        )
        if not is_global_admin and record.tenant_id != executing_tenant:
            metrics.record_approval_binding_failure()
            logger.warning(
                "Approval tenant isolation violation: approved_tenant=%s attempted_tenant=%s",
                record.tenant_id,
                executing_tenant,
            )
            return False, "tenant_mismatch"

    return True, "binding_verified"


def approve_and_execute(
    approval_id: str,
    approving_principal: Optional[Principal] = None,
) -> Dict[str, Any]:
    """
    Explicit approval and one-time execution flow:
    1. Validates approving principal has operator or admin role (user cannot self-approve).
    2. Validates approval exists and status is PENDING_APPROVAL.
    3. Verifies TTL (not expired).
    4. Re-validates bound policy version.
    5. Transitions to APPROVED.
    6. Atomically transitions APPROVED -> CONSUMED.
    7. Executes associated mock tool exactly once.
    8. Sanitizes output for leaks.
    9. Emits persistent audit events.
    10. Returns safe execution payload.
    """
    start_time = time.perf_counter()

    if not validate_approval_id_format(approval_id):
        raise ValueError(f"Invalid approval ID format: '{approval_id}'.")

    # Step 1: Principal Authorization Check (normal user CANNOT approve high-risk actions)
    if approving_principal is not None:
        if not (approving_principal.has_role("operator") or approving_principal.has_role("admin")):
            audit_service.log_event(
                action="authz_failure",
                principal=approving_principal,
                resource_type="approval",
                resource_id=approval_id,
                decision="BLOCK",
                error_code="FORBIDDEN",
                approval_id=approval_id,
            )
            logger.warning(
                "Unauthorized approval attempt: principal='%s' roles=%s cannot approve high-risk action.",
                approving_principal.principal_id,
                approving_principal.roles,
            )
            raise ForbiddenError(
                "Principals with role 'user' cannot approve high-risk actions. Operator or Admin role required."
            )

    # Step 2: Retrieve approval record and check tenant & policy re-validation
    record_peek = approval_store.get_approval(approval_id)
    if record_peek is None:
        raise ApprovalNotFoundError(f"Approval '{approval_id}' not found.")

    if approving_principal is not None:
        approving_tenant = getattr(approving_principal, "tenant_id", "default")
        is_global_admin = getattr(approving_principal, "global_admin", False) or (
            hasattr(approving_principal, "has_role") and approving_principal.has_role("global_admin")
        )
        if not is_global_admin and record_peek.tenant_id != approving_tenant:
            raise ApprovalNotFoundError(f"Approval '{approval_id}' not found.")

    if record_peek.policy_id:
        pol = policy_service.get_policy(record_peek.policy_id)
        if pol is None or pol.deleted or not pol.enabled or pol.version != record_peek.policy_version:
            metrics.record_approval_binding_failure()
            audit_service.log_event(
                action="approval_binding_failure",
                principal=approving_principal,
                resource_type="approval",
                resource_id=approval_id,
                decision="BLOCK",
                error_code="POLICY_CONFLICT",
                attack_type="policy_version_mismatch",
                approval_id=approval_id,
            )
            raise ActionBindingMismatchError(
                f"Policy binding mismatch: Policy '{record_peek.policy_id}' version changed or was deleted."
            )

    # Step 3: Mark Approved (verifies state and expiration)
    record = approval_store.mark_approved(approval_id)

    # Step 4: Atomic Consumption for One-Time Execution
    approval_store.consume_for_execution(approval_id)

    # Step 5: Execute Mock Tool
    try:
        raw_result = execute_mock_tool(
            record.tool_name,
            record.canonical_arguments,
            is_authorized=True,
        )
        sanitized_result, is_safe, result_attack_type = sanitize_tool_result(raw_result)
        metrics.record_approval_execution_success()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        audit_service.log_event(
            action="approval_approve",
            request_id=record.request_id,
            principal=approving_principal,
            resource_type="approval",
            resource_id=approval_id,
            decision="ALLOW",
            approval_id=approval_id,
            tool_name=record.tool_name,
        )

        audit_service.log_event(
            action="tool_execution",
            request_id=record.request_id,
            principal=approving_principal,
            resource_type="tool",
            resource_id=record.tool_name,
            decision="ALLOW",
            approval_id=approval_id,
            tool_name=record.tool_name,
        )

        return {
            "request_id": record.request_id,
            "approval_id": approval_id,
            "decision": "ALLOW",
            "approval_status": ApprovalStatus.CONSUMED.value,
            "tool_name": record.tool_name,
            "result": sanitized_result,
            "risk_level": record.risk_level,
            "latency_ms": elapsed_ms,
        }
    except Exception as exc:
        metrics.record_approval_execution_failure()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.error(
            "Approved tool execution failed: approval_id=%s tool=%s error=%s",
            approval_id,
            record.tool_name,
            type(exc).__name__,
        )
        audit_service.log_event(
            action="tool_execution",
            request_id=record.request_id,
            principal=approving_principal,
            resource_type="tool",
            resource_id=record.tool_name,
            decision="ERROR",
            approval_id=approval_id,
            tool_name=record.tool_name,
            error_code="EXECUTION_ERROR",
        )
        return {
            "request_id": record.request_id,
            "approval_id": approval_id,
            "decision": "ERROR",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": record.tool_name,
            "result": None,
            "risk_level": record.risk_level,
            "latency_ms": elapsed_ms,
        }


def deny_approval(
    approval_id: str,
    reason: str = "",
    denying_principal: Optional[Principal] = None,
) -> Dict[str, Any]:
    """
    Explicit denial flow:
    Transitions PENDING_APPROVAL -> DENIED.
    The tool is NEVER executed. Repeated denial is idempotent.
    """
    if not validate_approval_id_format(approval_id):
        raise ValueError(f"Invalid approval ID format: '{approval_id}'.")

    record_peek = approval_store.get_approval(approval_id)
    if record_peek is None:
        raise ApprovalNotFoundError(f"Approval '{approval_id}' not found.")

    if denying_principal is not None:
        denying_tenant = getattr(denying_principal, "tenant_id", "default")
        is_global_admin = getattr(denying_principal, "global_admin", False) or (
            hasattr(denying_principal, "has_role") and denying_principal.has_role("global_admin")
        )
        if not is_global_admin and record_peek.tenant_id != denying_tenant:
            raise ApprovalNotFoundError(f"Approval '{approval_id}' not found.")

        if not (denying_principal.has_role("operator") or denying_principal.has_role("admin") or is_global_admin):
            audit_service.log_event(
                action="authz_failure",
                principal=denying_principal,
                resource_type="approval",
                resource_id=approval_id,
                decision="BLOCK",
                error_code="FORBIDDEN",
                approval_id=approval_id,
            )
            raise ForbiddenError(
                "Principals with role 'user' cannot deny approval requests. Operator or Admin role required."
            )

    record = approval_store.mark_denied(approval_id, reason=reason)

    audit_service.log_event(
        action="approval_deny",
        request_id=record.request_id,
        principal=denying_principal,
        resource_type="approval",
        resource_id=approval_id,
        decision="BLOCK",
        approval_id=approval_id,
        tool_name=record.tool_name,
    )

    return {
        "request_id": record.request_id,
        "approval_id": approval_id,
        "decision": "BLOCK",
        "approval_status": ApprovalStatus.DENIED.value,
        "tool_name": record.tool_name,
        "result": None,
        "risk_level": record.risk_level,
    }


def execute_with_approval_token(
    approval_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    request_id: str,
    conversation_id: Optional[str] = None,
    executing_principal: Optional[Principal] = None,
) -> Dict[str, Any]:
    """
    Validates an approval ID presented at execution time (e.g. POST /api/v1/tool/execute).
    Guarantees:
    - Approval ID is valid format and exists.
    - Status is APPROVED.
    - Not expired.
    - Not already consumed (replay attack protection).
    - Arguments, tool, and principal match the approved binding.
    - Policy version has not changed.
    - Transitions to CONSUMED and executes tool exactly once.
    """
    start_time = time.perf_counter()

    if not validate_approval_id_format(approval_id):
        logger.warning("Invalid approval ID format: %s", approval_id)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "invalid_approval_id",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    record = approval_store.get_approval(approval_id)
    if not record:
        logger.warning("Approval ID not found: %s", approval_id)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_not_found",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Check expiration
    if record.status == ApprovalStatus.EXPIRED.value or record.is_expired():
        metrics.record_approval_expired()
        logger.warning("Execution attempt on expired approval: %s", approval_id)
        audit_service.log_event(
            action="approval_expire",
            request_id=request_id,
            principal=executing_principal,
            resource_type="approval",
            resource_id=approval_id,
            decision="BLOCK",
            approval_id=approval_id,
            tool_name=tool_name,
            attack_type="approval_expired",
        )
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.EXPIRED.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_expired",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Check replay (already consumed)
    if record.status == ApprovalStatus.CONSUMED.value:
        metrics.record_approval_replay_attempt()
        logger.warning("Replay attempt blocked on approval: %s", approval_id)
        audit_service.log_event(
            action="approval_replay",
            request_id=request_id,
            principal=executing_principal,
            resource_type="approval",
            resource_id=approval_id,
            decision="BLOCK",
            approval_id=approval_id,
            tool_name=tool_name,
            attack_type="approval_replay",
        )
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.CONSUMED.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_replay",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Check denial
    if record.status == ApprovalStatus.DENIED.value:
        logger.warning("Execution attempt on denied approval: %s", approval_id)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.DENIED.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_denied",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Check status: must be APPROVED
    if record.status == ApprovalStatus.PENDING_APPROVAL.value:
        logger.warning("Execution attempt on pending approval (not yet approved): %s", approval_id)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "PENDING_APPROVAL",
            "approval_status": ApprovalStatus.PENDING_APPROVAL.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_pending",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    if record.status != ApprovalStatus.APPROVED.value:
        logger.warning("Invalid approval status '%s' for execution: %s", record.status, approval_id)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "invalid_approval_state",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Verify Action Binding (tool, args, context, principal, policy)
    is_bound, bind_reason = verify_action_binding(
        record,
        tool_name,
        arguments,
        conversation_id,
        executing_principal=executing_principal,
    )
    if not is_bound:
        logger.warning("Action binding mismatch: approval=%s reason=%s", approval_id, bind_reason)
        audit_service.log_event(
            action="approval_binding_failure",
            request_id=request_id,
            principal=executing_principal,
            resource_type="approval",
            resource_id=approval_id,
            decision="BLOCK",
            approval_id=approval_id,
            tool_name=tool_name,
            attack_type=f"approval_binding_mismatch_{bind_reason}",
        )
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": f"approval_binding_mismatch_{bind_reason}",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Atomically Consume Approval Record
    try:
        approval_store.consume_for_execution(approval_id)
    except (ApprovalReplayError, ApprovalExpiredError, InvalidApprovalStateError) as err:
        logger.warning("Failed to consume approval '%s': %s", approval_id, err)
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "BLOCK",
            "approval_status": record.status,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "approval_consumption_failed",
            "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }

    # Execute Mock Tool Exactly Once
    try:
        raw_result = execute_mock_tool(tool_name, arguments, is_authorized=True)
        sanitized_result, is_safe, result_attack_type = sanitize_tool_result(raw_result)
        metrics.record_approval_execution_success()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        audit_service.log_event(
            action="tool_execution",
            request_id=request_id,
            principal=executing_principal,
            resource_type="tool",
            resource_id=tool_name,
            decision="ALLOW",
            approval_id=approval_id,
            tool_name=tool_name,
        )

        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "ALLOW",
            "approval_status": ApprovalStatus.CONSUMED.value,
            "tool_name": tool_name,
            "result": sanitized_result,
            "risk_level": record.risk_level,
            "attack_type": "none" if is_safe else result_attack_type,
            "latency_ms": elapsed_ms,
        }
    except Exception as exc:
        metrics.record_approval_execution_failure()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.error("Tool execution failed post-approval: %s", exc)
        audit_service.log_event(
            action="tool_execution",
            request_id=request_id,
            principal=executing_principal,
            resource_type="tool",
            resource_id=tool_name,
            decision="ERROR",
            approval_id=approval_id,
            tool_name=tool_name,
            error_code="EXECUTION_ERROR",
        )
        return {
            "request_id": request_id,
            "approval_id": approval_id,
            "decision": "ERROR",
            "approval_status": ApprovalStatus.ERROR.value,
            "tool_name": tool_name,
            "result": None,
            "attack_type": "tool_execution_error",
            "latency_ms": elapsed_ms,
        }

