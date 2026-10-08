"""
AgentGuard Policy Administration Service (Backend v0.7)
Deterministic policy administration with versioning, soft deletion, and audit trail.

HARD SECURITY INVARIANTS:
1. Guard BLOCK can NEVER be overridden by any policy (even explicit ALLOW).
2. Prompt injection, secret canary extraction, and argument validation errors can NEVER be overridden.
3. Unknown tools can NEVER be authorized or made executable by policy.
4. Critical destructive actions (e.g. 'delete_record') cannot bypass human approval under any policy.
5. Model text, prompt injections, or tool arguments can NEVER modify or create policies.

POLICY PRECEDENCE:
1. Explicit matching DENY policy.
2. Explicit matching REQUIRE_APPROVAL policy.
3. Explicit matching ALLOW policy.
4. Default security policy (fallback).
"""

import logging
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.services.audit_service import audit_service
from backend.services.identity_service import Principal
from backend.services.tool_registry import tool_registry

logger = logging.getLogger("agentguard.policy")

VALID_ACTIONS = {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical", "*"}


class PolicyError(Exception):
    """Base exception for policy errors."""
    def __init__(self, message: str, code: str = "POLICY_INVALID", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class PolicyNotFoundError(PolicyError):
    """Raised when policy does not exist or has been deleted."""
    def __init__(self, message: str = "Policy not found."):
        super().__init__(message=message, code="POLICY_NOT_FOUND", status_code=404)


class PolicyInvalidError(PolicyError):
    """Raised when policy definition or payload fails validation."""
    def __init__(self, message: str = "Invalid policy definition."):
        super().__init__(message=message, code="POLICY_INVALID", status_code=400)


class PolicyConflictError(PolicyError):
    """Raised when policy conflict or duplicate occurs."""
    def __init__(self, message: str = "Policy conflict."):
        super().__init__(message=message, code="POLICY_CONFLICT", status_code=409)


@dataclass
class Policy:
    """
    Explicit data structure representing an authorized security policy rule.
    """
    policy_id: str
    name: str
    description: str
    enabled: bool
    priority: int
    principal_scope: List[str]  # e.g. ["user-demo"] or ["*"]
    tool_scope: List[str]       # e.g. ["send_email"] or ["*"]
    risk_levels: List[str]      # e.g. ["high"] or ["*"]
    action: str                 # ALLOW, DENY, REQUIRE_APPROVAL
    version: int = 1
    created_by: str = "admin-demo"
    updated_by: str = "admin-demo"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    deleted: bool = False
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyEvaluationResult:
    """
    Result of deterministic policy resolution.
    """
    action: str  # ALLOW, DENY, REQUIRE_APPROVAL, or DEFAULT
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    reason: Optional[str] = None


class PolicyService:
    """
    Thread-safe in-memory store and evaluation engine for security policies.
    """

    def __init__(self):
        self._policies: Dict[str, Policy] = {}
        self._lock = threading.Lock()

    def _validate_policy_fields(
        self,
        name: str,
        description: str,
        action: str,
        principal_scope: List[str],
        tool_scope: List[str],
        risk_levels: List[str],
        priority: int,
    ) -> None:
        """Validates all policy fields strictly and deterministically."""
        if not name or not isinstance(name, str) or len(name.strip()) == 0 or len(name) > 100:
            raise PolicyInvalidError("Policy name must be a non-empty string under 100 characters.")

        if description is not None and len(description) > 500:
            raise PolicyInvalidError("Policy description must be under 500 characters.")

        if action not in VALID_ACTIONS:
            raise PolicyInvalidError(f"Invalid policy action '{action}'. Permitted actions: {sorted(VALID_ACTIONS)}")

        if not isinstance(principal_scope, list) or len(principal_scope) == 0:
            raise PolicyInvalidError("principal_scope must be a non-empty list of principal IDs or ['*'].")

        if not isinstance(tool_scope, list) or len(tool_scope) == 0:
            raise PolicyInvalidError("tool_scope must be a non-empty list of tool names or ['*'].")

        # Validate tool scope against tool registry (if not wildcard)
        if "*" not in tool_scope:
            for t in tool_scope:
                if tool_registry.get_tool(t) is None:
                    raise PolicyInvalidError(f"Unknown tool in tool_scope: '{t}'.")

        if not isinstance(risk_levels, list) or len(risk_levels) == 0:
            raise PolicyInvalidError("risk_levels must be a non-empty list of risk levels or ['*'].")

        for r in risk_levels:
            if r.lower() not in VALID_RISK_LEVELS:
                raise PolicyInvalidError(f"Invalid risk level '{r}'. Permitted: {sorted(VALID_RISK_LEVELS)}")

        if not isinstance(priority, int) or priority < 0 or priority > 10000:
            raise PolicyInvalidError("Policy priority must be an integer between 0 and 10000.")

    def create_policy(
        self,
        name: str,
        description: str,
        action: str,
        principal_scope: List[str],
        tool_scope: List[str],
        risk_levels: List[str],
        priority: int = 100,
        enabled: bool = True,
        principal: Optional[Any] = None,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Policy:
        """
        Creates a new security policy with version 1 and tenant binding.
        Records a persistent audit event.
        """
        self._validate_policy_fields(
            name=name,
            description=description,
            action=action,
            principal_scope=principal_scope,
            tool_scope=tool_scope,
            risk_levels=risk_levels,
            priority=priority,
        )

        creator_id = getattr(principal, "principal_id", "admin-demo") if principal else "admin-demo"
        p_tenant = getattr(principal, "tenant_id", None) if principal else None
        effective_tenant = tenant_id or p_tenant or "default"
        policy_id = f"pol_{secrets.token_hex(8)}"
        now = time.time()

        policy = Policy(
            policy_id=policy_id,
            name=name.strip(),
            description=description.strip() if description else "",
            enabled=enabled,
            priority=priority,
            principal_scope=[p.strip() for p in principal_scope],
            tool_scope=[t.strip() for t in tool_scope],
            risk_levels=[r.strip().lower() for r in risk_levels],
            action=action,
            version=1,
            created_by=creator_id,
            updated_by=creator_id,
            created_at=now,
            updated_at=now,
            deleted=False,
            tenant_id=effective_tenant,
        )

        with self._lock:
            self._policies[policy_id] = policy

        logger.info(
            "Security policy created: id=%s name='%s' tenant=%s action=%s version=1 created_by=%s",
            policy_id,
            policy.name,
            effective_tenant,
            policy.action,
            creator_id,
        )

        # Audit event
        audit_service.log_event(
            action="policy_create",
            request_id=request_id,
            principal=principal,
            tenant_id=effective_tenant,
            resource_type="policy",
            resource_id=policy_id,
            decision="ALLOW",
            policy_id=policy_id,
            policy_version=1,
        )

        return policy

    def get_policy(self, policy_id: str, tenant_id: Optional[str] = None) -> Optional[Policy]:
        """
        Retrieves a policy by ID, ignoring deleted policies and enforcing tenant isolation.
        """
        with self._lock:
            policy = self._policies.get(policy_id)
            if policy is None or policy.deleted:
                return None
            if tenant_id is not None and policy.tenant_id != tenant_id:
                # Do not leak other tenant's resource existence
                return None
            return policy

    def list_policies(
        self,
        include_disabled: bool = True,
        include_deleted: bool = False,
        tenant_id: Optional[str] = None,
    ) -> List[Policy]:
        """Lists policies sorted by priority descending, optionally filtered by tenant."""
        with self._lock:
            policies = list(self._policies.values())

        filtered = []
        for p in policies:
            if p.deleted and not include_deleted:
                continue
            if not p.enabled and not include_disabled:
                continue
            if tenant_id is not None and p.tenant_id != tenant_id:
                continue
            filtered.append(p)

        # Sort by priority descending, then creation time ascending
        filtered.sort(key=lambda p: (-p.priority, p.created_at))
        return filtered

    def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        action: Optional[str] = None,
        principal_scope: Optional[List[str]] = None,
        tool_scope: Optional[List[str]] = None,
        risk_levels: Optional[List[str]] = None,
        priority: Optional[int] = None,
        enabled: Optional[bool] = None,
        principal: Optional[Any] = None,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Policy:
        """
        Updates an existing policy, incrementing its version counter.
        Enforces tenant isolation (cannot modify policies from other tenants).
        Records an audit event with the incremented version.
        """
        updater_id = getattr(principal, "principal_id", "admin-demo") if principal else "admin-demo"
        effective_tenant = tenant_id or (getattr(principal, "tenant_id", None) if principal else None)

        with self._lock:
            existing = self._policies.get(policy_id)
            if existing is None or existing.deleted:
                raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

            if effective_tenant is not None and existing.tenant_id != effective_tenant:
                raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

            new_name = name if name is not None else existing.name
            new_desc = description if description is not None else existing.description
            new_act = action if action is not None else existing.action
            new_pscope = principal_scope if principal_scope is not None else existing.principal_scope
            new_tscope = tool_scope if tool_scope is not None else existing.tool_scope
            new_rlevels = risk_levels if risk_levels is not None else existing.risk_levels
            new_prio = priority if priority is not None else existing.priority
            new_enabled = enabled if enabled is not None else existing.enabled

            self._validate_policy_fields(
                name=new_name,
                description=new_desc,
                action=new_act,
                principal_scope=new_pscope,
                tool_scope=new_tscope,
                risk_levels=new_rlevels,
                priority=new_prio,
            )

            new_version = existing.version + 1
            now = time.time()

            updated = Policy(
                policy_id=existing.policy_id,
                name=new_name.strip(),
                description=new_desc.strip(),
                enabled=new_enabled,
                priority=new_prio,
                principal_scope=[p.strip() for p in new_pscope],
                tool_scope=[t.strip() for t in new_tscope],
                risk_levels=[r.strip().lower() for r in new_rlevels],
                action=new_act,
                version=new_version,
                created_by=existing.created_by,
                updated_by=updater_id,
                created_at=existing.created_at,
                updated_at=now,
                deleted=False,
                tenant_id=existing.tenant_id,
            )
            self._policies[policy_id] = updated

        logger.info(
            "Security policy updated: id=%s version=%d updated_by=%s",
            policy_id,
            new_version,
            updater_id,
        )

        audit_service.log_event(
            action="policy_update",
            request_id=request_id,
            principal=principal,
            tenant_id=existing.tenant_id,
            resource_type="policy",
            resource_id=policy_id,
            decision="ALLOW",
            policy_id=policy_id,
            policy_version=new_version,
        )

        return updated

    def delete_policy(
        self,
        policy_id: str,
        principal: Optional[Any] = None,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Policy:
        """
        Soft deletes a policy so historical audit logs preserve reference integrity.
        Enforces tenant isolation.
        Records an audit event.
        """
        deleter_id = getattr(principal, "principal_id", "admin-demo") if principal else "admin-demo"
        effective_tenant = tenant_id or (getattr(principal, "tenant_id", None) if principal else None)

        with self._lock:
            existing = self._policies.get(policy_id)
            if existing is None or existing.deleted:
                raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

            if effective_tenant is not None and existing.tenant_id != effective_tenant:
                raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

            new_version = existing.version + 1
            now = time.time()

            soft_deleted = Policy(
                policy_id=existing.policy_id,
                name=existing.name,
                description=existing.description,
                enabled=False,
                priority=existing.priority,
                principal_scope=existing.principal_scope,
                tool_scope=existing.tool_scope,
                risk_levels=existing.risk_levels,
                action=existing.action,
                version=new_version,
                created_by=existing.created_by,
                updated_by=deleter_id,
                created_at=existing.created_at,
                updated_at=now,
                deleted=True,
                tenant_id=existing.tenant_id,
            )
            self._policies[policy_id] = soft_deleted

        logger.info("Security policy soft-deleted: id=%s version=%d", policy_id, new_version)

        audit_service.log_event(
            action="policy_delete",
            request_id=request_id,
            principal=principal,
            tenant_id=existing.tenant_id,
            resource_type="policy",
            resource_id=policy_id,
            decision="ALLOW",
            policy_id=policy_id,
            policy_version=new_version,
        )

        return soft_deleted

    def evaluate_policy(
        self,
        principal_id: str,
        tool_name: str,
        risk_level: str,
        tenant_id: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluates active policies deterministically against the current context:
        - principal_id
        - tool_name
        - risk_level
        - tenant_id (tenant-bound evaluation)

        Evaluation Precedence:
        1. Explicit DENY
        2. Explicit REQUIRE_APPROVAL
        3. Explicit ALLOW
        4. Fallback to default security policy (DEFAULT)
        """
        effective_tenant = tenant_id or "default"
        with self._lock:
            active_policies = [
                p for p in self._policies.values()
                if p.enabled and not p.deleted and p.tenant_id == effective_tenant
            ]

        matching: List[Policy] = []
        for p in active_policies:
            # Check principal scope
            p_match = ("*" in p.principal_scope) or (principal_id in p.principal_scope)
            # Check tool scope
            t_match = ("*" in p.tool_scope) or (tool_name in p.tool_scope)
            # Check risk levels
            r_match = ("*" in p.risk_levels) or (risk_level.lower() in p.risk_levels)

            if p_match and t_match and r_match:
                matching.append(p)

        if not matching:
            return PolicyEvaluationResult(action="DEFAULT")

        # Separate by action precedence
        denies = [p for p in matching if p.action == "DENY"]
        approvals = [p for p in matching if p.action == "REQUIRE_APPROVAL"]
        allows = [p for p in matching if p.action == "ALLOW"]

        # 1. Explicit DENY wins first
        if denies:
            denies.sort(key=lambda p: -p.priority)
            winner = denies[0]
            return PolicyEvaluationResult(
                action="DENY",
                policy_id=winner.policy_id,
                policy_version=winner.version,
                reason=f"Explicit DENY policy '{winner.name}' (id={winner.policy_id}) matched.",
            )

        # 2. Explicit REQUIRE_APPROVAL wins second
        if approvals:
            approvals.sort(key=lambda p: -p.priority)
            winner = approvals[0]
            return PolicyEvaluationResult(
                action="REQUIRE_APPROVAL",
                policy_id=winner.policy_id,
                policy_version=winner.version,
                reason=f"Explicit REQUIRE_APPROVAL policy '{winner.name}' (id={winner.policy_id}) matched.",
            )

        # 3. Explicit ALLOW wins third
        if allows:
            allows.sort(key=lambda p: -p.priority)
            winner = allows[0]
            return PolicyEvaluationResult(
                action="ALLOW",
                policy_id=winner.policy_id,
                policy_version=winner.version,
                reason=f"Explicit ALLOW policy '{winner.name}' (id={winner.policy_id}) matched.",
            )

        return PolicyEvaluationResult(action="DEFAULT")

    def is_healthy(self) -> bool:
        """Verifies policy store accessibility for readiness probe."""
        with self._lock:
            return isinstance(self._policies, dict)

    def reset_for_testing(self):
        """Clears all policies for unit and benchmark tests."""
        with self._lock:
            self._policies.clear()


# Singleton policy service instance
policy_service = PolicyService()
