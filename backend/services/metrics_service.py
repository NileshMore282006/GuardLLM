"""
Metrics Service Layer
In-process, memory-only operational metrics collector for Backend v0.5.
Tracks requests, security decisions, errors, rate limits, concurrency blocks, timeouts, and tool call authorization.
Resets on application restart. Never records prompts, conversations, or secrets.
"""

import threading
import time
from typing import Any, Dict


class MetricsCollector:
    """
    Thread-safe in-memory metrics collector.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        """
        Resets all metrics counters to initial state.
        """
        with getattr(self, "_lock", threading.Lock()):
            self._start_time = time.time()
            self._total_requests = 0
            self._requests_by_endpoint: Dict[str, int] = {
                "/health": 0,
                "/ready": 0,
                "/metrics": 0,
                "/api/v1/guard": 0,
                "/api/v1/execute": 0,
                "/api/v1/chat": 0,
                "/api/v1/tool/execute": 0,
                "/api/v1/approvals": 0,
            }
            self._requests_by_status: Dict[str, int] = {}
            self._allow_count = 0
            self._block_count = 0
            self._error_count = 0
            self._rate_limited_count = 0
            self._concurrency_rejected_count = 0
            self._guard_invocation_count = 0
            self._guard_failure_count = 0
            self._guard_timeout_count = 0
            self._target_invocation_count = 0
            self._target_failure_count = 0
            self._target_timeout_count = 0

            # Tool security metrics (v0.5)
            self._tool_calls_total = 0
            self._tool_calls_allowed = 0
            self._tool_calls_blocked = 0
            self._tool_calls_error = 0
            self._unauthorized_tool_executions = 0
            self._tool_call_limit_exceeded = 0

            # Human approval & high-risk action metrics (v0.6)
            self._approval_requests_created = 0
            self._approval_requests_approved = 0
            self._approval_requests_denied = 0
            self._approval_requests_expired = 0
            self._approval_requests_cancelled = 0
            self._approval_execution_success = 0
            self._approval_execution_failure = 0
            self._approval_replay_attempts = 0
            self._approval_binding_failures = 0
            self._unauthorized_high_risk_tool_executions = 0

    def record_request(self, endpoint: str, status_code: int):
        with self._lock:
            self._total_requests += 1
            ep = endpoint.split("?")[0]
            self._requests_by_endpoint[ep] = self._requests_by_endpoint.get(ep, 0) + 1
            code_str = str(status_code)
            self._requests_by_status[code_str] = self._requests_by_status.get(code_str, 0) + 1

    def record_decision(self, decision: str):
        with self._lock:
            dec = str(decision).upper()
            if dec == "ALLOW":
                self._allow_count += 1
            elif dec == "BLOCK":
                self._block_count += 1
            elif dec == "ERROR":
                self._error_count += 1

    def record_rate_limited(self):
        with self._lock:
            self._rate_limited_count += 1

    def record_concurrency_rejected(self):
        with self._lock:
            self._concurrency_rejected_count += 1

    def record_guard_invocation(self, success: bool = True, is_timeout: bool = False):
        with self._lock:
            self._guard_invocation_count += 1
            if not success:
                self._guard_failure_count += 1
            if is_timeout:
                self._guard_timeout_count += 1

    def record_target_invocation(self, success: bool = True, is_timeout: bool = False):
        with self._lock:
            self._target_invocation_count += 1
            if not success:
                self._target_failure_count += 1
            if is_timeout:
                self._target_timeout_count += 1

    def record_tool_call(self, decision: str):
        with self._lock:
            self._tool_calls_total += 1
            dec = str(decision).upper()
            if dec == "ALLOW":
                self._tool_calls_allowed += 1
            elif dec == "BLOCK":
                self._tool_calls_blocked += 1
            else:
                self._tool_calls_error += 1

    def record_unauthorized_tool_execution(self):
        with self._lock:
            self._unauthorized_tool_executions += 1

    def record_tool_limit_exceeded(self):
        with self._lock:
            self._tool_call_limit_exceeded += 1

    def record_approval_created(self):
        with self._lock:
            self._approval_requests_created += 1

    def record_approval_approved(self):
        with self._lock:
            self._approval_requests_approved += 1

    def record_approval_denied(self):
        with self._lock:
            self._approval_requests_denied += 1

    def record_approval_expired(self):
        with self._lock:
            self._approval_requests_expired += 1

    def record_approval_cancelled(self):
        with self._lock:
            self._approval_requests_cancelled += 1

    def record_approval_execution_success(self):
        with self._lock:
            self._approval_execution_success += 1

    def record_approval_execution_failure(self):
        with self._lock:
            self._approval_execution_failure += 1

    def record_approval_replay_attempt(self):
        with self._lock:
            self._approval_replay_attempts += 1

    def record_approval_binding_failure(self):
        with self._lock:
            self._approval_binding_failures += 1

    def record_unauthorized_high_risk_tool_execution(self):
        with self._lock:
            self._unauthorized_high_risk_tool_executions += 1

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            uptime = round(time.time() - self._start_time, 2)
            return {
                "uptime_seconds": uptime,
                "total_requests": self._total_requests,
                "requests_by_endpoint": dict(self._requests_by_endpoint),
                "requests_by_status": dict(self._requests_by_status),
                "decisions": {
                    "allow": self._allow_count,
                    "block": self._block_count,
                    "error": self._error_count,
                },
                "rate_limited_count": self._rate_limited_count,
                "concurrency_rejected_count": self._concurrency_rejected_count,
                "guard": {
                    "invocations": self._guard_invocation_count,
                    "failures": self._guard_failure_count,
                    "timeouts": self._guard_timeout_count,
                },
                "target": {
                    "invocations": self._target_invocation_count,
                    "failures": self._target_failure_count,
                    "timeouts": self._target_timeout_count,
                },
                "timeouts": {
                    "guard_timeouts": self._guard_timeout_count,
                    "target_timeouts": self._target_timeout_count,
                    "total_timeouts": self._guard_timeout_count + self._target_timeout_count,
                },
                "tools": {
                    "total_calls": self._tool_calls_total,
                    "allowed": self._tool_calls_allowed,
                    "blocked": self._tool_calls_blocked,
                    "error": self._tool_calls_error,
                    "unauthorized_executions": self._unauthorized_tool_executions,
                    "limit_exceeded": self._tool_call_limit_exceeded,
                },
                "approvals": {
                    "approval_requests_created": self._approval_requests_created,
                    "approval_requests_approved": self._approval_requests_approved,
                    "approval_requests_denied": self._approval_requests_denied,
                    "approval_requests_expired": self._approval_requests_expired,
                    "approval_requests_cancelled": self._approval_requests_cancelled,
                    "approval_execution_success": self._approval_execution_success,
                    "approval_execution_failure": self._approval_execution_failure,
                    "approval_replay_attempts": self._approval_replay_attempts,
                    "approval_binding_failures": self._approval_binding_failures,
                    "unauthorized_high_risk_tool_executions": self._unauthorized_high_risk_tool_executions,
                },
                "approval_requests_created": self._approval_requests_created,
                "approval_requests_approved": self._approval_requests_approved,
                "approval_requests_denied": self._approval_requests_denied,
                "approval_requests_expired": self._approval_requests_expired,
                "approval_requests_cancelled": self._approval_requests_cancelled,
                "approval_execution_success": self._approval_execution_success,
                "approval_execution_failure": self._approval_execution_failure,
                "approval_replay_attempts": self._approval_replay_attempts,
                "approval_binding_failures": self._approval_binding_failures,
                "unauthorized_high_risk_tool_executions": self._unauthorized_high_risk_tool_executions,
            }


# Global metrics collector singleton
metrics = MetricsCollector()
