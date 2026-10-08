"""
AgentGuard Multi-Dimensional Abuse Resistance & Rate Limiter (v0.9)
In-process, sliding-window rate limiter providing multi-tiered defense against:
1. Global client IP abuse
2. Authentication brute-force & credential stuffing (auth_failure tracking)
3. Endpoint category abuse (approvals, credentials, policies, audit)
4. Cross-tenant shared resource exhaustion (tenant-level rate limits)

SECURITY INVARIANTS:
1. Thread-safe with bounded in-memory sliding window bookkeeping.
2. Clients CANNOT spoof identity for rate limiting (uses verified context, trusted proxy IP).
3. Sliding window delay (HTTP 429 + Retry-After) rather than permanent lockouts to prevent DoS.
4. Clean abstraction for future distributed Redis / Memcached in v1.0.
5. Fails open on bookkeeping error without crashing service; never logs prompts or secrets.
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

from backend.config import (
    APPROVAL_RATE_LIMIT_REQUESTS,
    AUDIT_RATE_LIMIT_REQUESTS,
    AUTH_FAILURE_RATE_LIMIT_REQUESTS,
    CREDENTIAL_RATE_LIMIT_REQUESTS,
    POLICY_RATE_LIMIT_REQUESTS,
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    TENANT_RATE_LIMIT_REQUESTS,
)

logger = logging.getLogger("agentguard.rate_limiter")


class InMemoryRateLimiter:
    """
    Thread-safe in-process sliding window rate limiter with category and tenant support.
    """

    def __init__(
        self,
        enabled: bool = RATE_LIMIT_ENABLED,
        max_requests: int = RATE_LIMIT_REQUESTS,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
    ):
        self.enabled = enabled
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._max_tracked_keys = 20000

    def check_rate_limit(
        self,
        client_key: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
    ) -> Tuple[bool, Optional[int]]:
        """
        Checks whether client_key has exceeded the quota.
        Returns (is_allowed: bool, retry_after_seconds: Optional[int]).
        """
        if not self.enabled:
            return True, None

        effective_limit = limit if limit is not None else self.max_requests
        effective_window = window if window is not None else self.window_seconds

        now = time.time()
        cutoff = now - effective_window

        try:
            with self._lock:
                # Memory exhaustion protection: prune if dictionary grows too large
                if len(self._requests) > self._max_tracked_keys:
                    self._prune_expired_keys(cutoff)

                timestamps = self._requests.get(client_key, [])
                active_timestamps = [t for t in timestamps if t > cutoff]

                if len(active_timestamps) >= effective_limit:
                    oldest = active_timestamps[0]
                    retry_after = max(1, int(oldest + effective_window - now))
                    self._requests[client_key] = active_timestamps
                    logger.warning(
                        "Rate limit exceeded: key=%s count=%d limit=%d window=%ds retry_after=%ds",
                        client_key,
                        len(active_timestamps),
                        effective_limit,
                        effective_window,
                        retry_after,
                    )
                    return False, retry_after

                active_timestamps.append(now)
                self._requests[client_key] = active_timestamps
                return True, None

        except Exception as exc:
            logger.error(
                "Rate limiter error (failing open): key=%s error=%s",
                client_key,
                type(exc).__name__,
            )
            return True, None

    def check_category_rate_limit(
        self,
        category: str,
        client_ip: str,
        principal_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Tuple[bool, Optional[int]]:
        """
        Enforces specific category rate limits based on verified attributes.
        """
        if not self.enabled:
            return True, None

        effective_limit = limit
        if effective_limit is None:
            category_limits = {
                "auth_failure": AUTH_FAILURE_RATE_LIMIT_REQUESTS,
                "approvals": APPROVAL_RATE_LIMIT_REQUESTS,
                "credentials": CREDENTIAL_RATE_LIMIT_REQUESTS,
                "policies": POLICY_RATE_LIMIT_REQUESTS,
                "audit": AUDIT_RATE_LIMIT_REQUESTS,
            }
            effective_limit = category_limits.get(category, self.max_requests)

        # Composite key preventing unverified header spoofing
        if category == "auth_failure":
            key = f"cat:auth_fail:{client_ip}"
        elif category == "audit":
            key = f"cat:audit:{tenant_id or 'anon'}:{client_ip}"
        else:
            key = f"cat:{category}:{principal_id or 'anon'}:{client_ip}"

        return self.check_rate_limit(key, limit=effective_limit, window=self.window_seconds)

    def record_auth_failure(self, client_ip: str) -> Tuple[bool, Optional[int]]:
        """
        Records an authentication failure for a client IP and verifies if limit exceeded.
        """
        return self.check_category_rate_limit("auth_failure", client_ip)

    def check_tenant_rate_limit(self, tenant_id: str) -> Tuple[bool, Optional[int]]:
        """
        Enforces tenant-wide rate limits to prevent single-tenant resource exhaustion.
        """
        if not self.enabled or not tenant_id:
            return True, None

        key = f"tenant:{tenant_id}"
        return self.check_rate_limit(
            key,
            limit=TENANT_RATE_LIMIT_REQUESTS,
            window=self.window_seconds,
        )

    def _prune_expired_keys(self, cutoff: float) -> None:
        """Evicts keys with no active timestamps to prevent unbounded memory growth."""
        keys_to_delete = [
            k for k, stamps in self._requests.items()
            if not stamps or stamps[-1] <= cutoff
        ]
        for k in keys_to_delete:
            del self._requests[k]

    def reset(self) -> None:
        """Clears all stored rate limiter records."""
        with self._lock:
            self._requests.clear()


# Global rate limiter singleton
rate_limiter = InMemoryRateLimiter()
