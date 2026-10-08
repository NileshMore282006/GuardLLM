"""
In-Memory Approval Store (Backend v0.6)
Manages approval records and enforces security boundaries for high-risk tool authorizations.

SECURITY INVARIANTS:
1. In-memory only: Approvals disappear on server restart. This is for local development and testing.
   Production requires a durable, secure, access-controlled approval store.
2. Approval state machine: Enforces strict valid state transitions. Terminal and expired states cannot be resurrected.
3. One-time execution: Once an approval is consumed, it CANNOT be reused (APPROVED -> CONSUMED).
4. TTL enforcement: Expired approvals automatically transition to EXPIRED and refuse execution.
5. Thread-safe: All state transitions and lookups are guarded by a re-entrant lock.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.config import APPROVAL_TTL_SECONDS
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.approval_store")


class ApprovalStatus(str, Enum):
    """
    Explicit authorization and lifecycle states for human approval requests.
    """
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    CONSUMED = "CONSUMED"
    ERROR = "ERROR"


class ApprovalStoreError(Exception):
    """Base exception for approval store errors."""
    pass


class ApprovalNotFoundError(ApprovalStoreError):
    """Raised when an approval ID is not found in the store."""
    pass


class InvalidApprovalStateError(ApprovalStoreError):
    """Raised when an invalid state transition is requested."""
    pass


class ApprovalExpiredError(ApprovalStoreError):
    """Raised when attempting to act upon an expired approval."""
    pass


class ApprovalReplayError(ApprovalStoreError):
    """Raised when an approval is replayed after already being consumed."""
    pass


@dataclass
class ApprovalRecord:
    """
    Internal representation of a human approval request.
    Guarantees structural binding to the tool, arguments, context, identity, policy, and risk level.
    """
    approval_id: str
    request_id: str
    tool_name: str
    risk_level: str
    reason: str
    arguments_summary: str
    arguments_hash: str
    canonical_arguments: Dict[str, Any]
    status: str = ApprovalStatus.PENDING_APPROVAL.value
    conversation_id: Optional[str] = None
    principal_id: str = "user-demo"
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    approved_at: Optional[float] = None
    denied_at: Optional[float] = None
    expired_at: Optional[float] = None
    consumed_at: Optional[float] = None
    execution_count: int = 0
    tenant_id: str = "default"

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Checks if current time exceeds expires_at."""
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def to_safe_dict(self) -> Dict[str, Any]:
        """
        Returns safe telemetry dictionary without raw sensitive arguments.
        """
        return {
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "conversation_id": self.conversation_id,
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "tool_name": self.tool_name,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "arguments_summary": self.arguments_summary,
            "arguments_hash": self.arguments_hash,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approved_at": self.approved_at,
            "denied_at": self.denied_at,
            "expired_at": self.expired_at,
            "consumed_at": self.consumed_at,
            "execution_count": self.execution_count,
        }


class ApprovalStore:
    """
    Thread-safe in-memory approval storage engine with tenant isolation.
    """

    def __init__(self, default_ttl_seconds: int = APPROVAL_TTL_SECONDS):
        self._lock = threading.RLock()
        self._approvals: Dict[str, ApprovalRecord] = {}
        self._default_ttl = default_ttl_seconds

    def create_approval(
        self,
        approval_id: str,
        request_id: str,
        tool_name: str,
        risk_level: str,
        reason: str,
        arguments_summary: str,
        arguments_hash: str,
        canonical_arguments: Dict[str, Any],
        conversation_id: Optional[str] = None,
        principal_id: str = "user-demo",
        policy_id: Optional[str] = None,
        policy_version: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        tenant_id: Optional[str] = "default",
    ) -> ApprovalRecord:
        """
        Creates and stores a new approval request in PENDING_APPROVAL state bound to a tenant.
        """
        with self._lock:
            now = time.time()
            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
            record = ApprovalRecord(
                approval_id=approval_id,
                request_id=request_id,
                conversation_id=conversation_id,
                principal_id=principal_id,
                tenant_id=tenant_id or "default",
                policy_id=policy_id,
                policy_version=policy_version,
                tool_name=tool_name,
                risk_level=risk_level,
                reason=reason,
                arguments_summary=arguments_summary,
                arguments_hash=arguments_hash,
                canonical_arguments=canonical_arguments,
                status=ApprovalStatus.PENDING_APPROVAL.value,
                created_at=now,
                expires_at=now + ttl,
            )
            self._approvals[approval_id] = record
            metrics.record_approval_created()
            logger.info(
                "Approval created: approval_id=%s tool=%s tenant=%s risk=%s principal=%s expires_in=%ds",
                approval_id,
                tool_name,
                record.tenant_id,
                risk_level,
                principal_id,
                ttl,
            )
            return record

    def get_approval(self, approval_id: str, tenant_id: Optional[str] = None) -> Optional[ApprovalRecord]:
        """
        Retrieves an approval record by ID with automatic TTL expiration check and tenant isolation.
        """
        with self._lock:
            record = self._approvals.get(approval_id)
            if not record:
                return None

            if tenant_id is not None and record.tenant_id != tenant_id:
                # Safe 404 behavior: do not leak existence in another tenant
                return None

            # Automatic TTL check
            if record.status == ApprovalStatus.PENDING_APPROVAL.value and record.is_expired():
                record.status = ApprovalStatus.EXPIRED.value
                record.expired_at = time.time()
                metrics.record_approval_expired()
                logger.info("Approval expired by TTL: approval_id=%s", approval_id)

            return record

    def mark_approved(self, approval_id: str, tenant_id: Optional[str] = None) -> ApprovalRecord:
        """
        Transitions status from PENDING_APPROVAL to APPROVED.
        Fails if expired, already consumed, denied, or cross-tenant.
        """
        with self._lock:
            record = self.get_approval(approval_id, tenant_id=tenant_id)
            if not record:
                raise ApprovalNotFoundError(f"Approval ID '{approval_id}' not found.")

            if record.status == ApprovalStatus.EXPIRED.value or record.is_expired():
                if record.status != ApprovalStatus.EXPIRED.value:
                    record.status = ApprovalStatus.EXPIRED.value
                    record.expired_at = time.time()
                    metrics.record_approval_expired()
                raise ApprovalExpiredError(f"Approval '{approval_id}' has expired and cannot be approved.")

            if record.status == ApprovalStatus.CONSUMED.value:
                metrics.record_approval_replay_attempt()
                raise ApprovalReplayError(f"Approval '{approval_id}' has already been consumed.")

            if record.status == ApprovalStatus.DENIED.value:
                raise InvalidApprovalStateError(f"Approval '{approval_id}' was already denied.")

            if record.status != ApprovalStatus.PENDING_APPROVAL.value:
                raise InvalidApprovalStateError(
                    f"Cannot approve from status '{record.status}'. Expected PENDING_APPROVAL."
                )

            record.status = ApprovalStatus.APPROVED.value
            record.approved_at = time.time()
            metrics.record_approval_approved()
            logger.info("Approval granted: approval_id=%s tool=%s tenant=%s", approval_id, record.tool_name, record.tenant_id)
            return record

    def mark_denied(self, approval_id: str, reason: str = "", tenant_id: Optional[str] = None) -> ApprovalRecord:
        """
        Transitions status to DENIED. Idempotent if already DENIED.
        """
        with self._lock:
            record = self.get_approval(approval_id, tenant_id=tenant_id)
            if not record:
                raise ApprovalNotFoundError(f"Approval ID '{approval_id}' not found.")

            if record.status == ApprovalStatus.CONSUMED.value:
                raise InvalidApprovalStateError(f"Approval '{approval_id}' was already executed/consumed.")

            if record.status == ApprovalStatus.DENIED.value:
                # Idempotent repeat denial
                return record

            record.status = ApprovalStatus.DENIED.value
            record.denied_at = time.time()
            if reason:
                record.reason = f"{record.reason} (Denied: {reason})"
            metrics.record_approval_denied()
            logger.info("Approval denied: approval_id=%s tool=%s tenant=%s", approval_id, record.tool_name, record.tenant_id)
            return record

    def mark_cancelled(self, approval_id: str, tenant_id: Optional[str] = None) -> ApprovalRecord:
        """
        Transitions status from PENDING_APPROVAL to CANCELLED.
        """
        with self._lock:
            record = self.get_approval(approval_id, tenant_id=tenant_id)
            if not record:
                raise ApprovalNotFoundError(f"Approval ID '{approval_id}' not found.")

            if record.status != ApprovalStatus.PENDING_APPROVAL.value:
                raise InvalidApprovalStateError(
                    f"Cannot cancel approval in state '{record.status}'."
                )

            record.status = ApprovalStatus.CANCELLED.value
            metrics.record_approval_cancelled()
            logger.info("Approval cancelled: approval_id=%s tenant=%s", approval_id, record.tenant_id)
            return record

    def consume_for_execution(self, approval_id: str, tenant_id: Optional[str] = None) -> ApprovalRecord:
        """
        Atomic transition: APPROVED -> CONSUMED.
        Enforces that ONE approval translates to AT MOST ONE tool execution.
        Subsequent calls will fail with ApprovalReplayError.
        Enforces tenant isolation: Approval from tenant A cannot authorize execution in tenant B.
        """
        with self._lock:
            record = self.get_approval(approval_id, tenant_id=tenant_id)
            if not record:
                raise ApprovalNotFoundError(f"Approval ID '{approval_id}' not found.")

            if record.status == ApprovalStatus.CONSUMED.value:
                metrics.record_approval_replay_attempt()
                logger.warning("Replay attack detected on consumed approval: approval_id=%s", approval_id)
                raise ApprovalReplayError(
                    f"One-time approval '{approval_id}' has already been consumed. Replay blocked."
                )

            if record.status == ApprovalStatus.EXPIRED.value or record.is_expired():
                if record.status != ApprovalStatus.EXPIRED.value:
                    record.status = ApprovalStatus.EXPIRED.value
                    record.expired_at = time.time()
                    metrics.record_approval_expired()
                raise ApprovalExpiredError(f"Approval '{approval_id}' has expired.")

            if record.status != ApprovalStatus.APPROVED.value:
                raise InvalidApprovalStateError(
                    f"Approval '{approval_id}' cannot be executed. Current status: '{record.status}'. Expected APPROVED."
                )

            # Atomic consumption
            record.status = ApprovalStatus.CONSUMED.value
            record.consumed_at = time.time()
            record.execution_count += 1
            logger.info(
                "Approval consumed for execution: approval_id=%s tenant=%s execution_count=%d",
                approval_id,
                record.tenant_id,
                record.execution_count,
            )
            return record

    def list_approvals(self, tenant_id: Optional[str] = None) -> List[ApprovalRecord]:
        """Returns approval records optionally scoped to tenant."""
        with self._lock:
            now = time.time()
            results = []
            for record in self._approvals.values():
                if record.status == ApprovalStatus.PENDING_APPROVAL.value and record.is_expired(now):
                    record.status = ApprovalStatus.EXPIRED.value
                    record.expired_at = now
                if tenant_id is not None and record.tenant_id != tenant_id:
                    continue
                results.append(record)
            return results

    def is_healthy(self) -> bool:
        """Verifies approval store accessibility for readiness probe."""
        with self._lock:
            return isinstance(self._approvals, dict)

    def clear(self):
        """Clears all approval records (for testing)."""
        with self._lock:
            self._approvals.clear()


# Global approval store singleton
approval_store = ApprovalStore()
