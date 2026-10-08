"""
Concurrency Control Service Layer (v0.9)
Manages concurrent inference capacity and tenant-scoped concurrency to protect local Ollama resources.
Provides strict semaphore guards for Guard, Target LLM, and tenant-scoped executions.
Rejects excess concurrent requests with ConcurrencyLimitExceeded (HTTP 503).
"""

import logging
import threading
from contextlib import contextmanager
from typing import Dict, Generator, Optional

from backend.config import (
    MAX_CONCURRENT_GUARD_REQUESTS,
    MAX_CONCURRENT_TARGET_REQUESTS,
    MAX_TENANT_CONCURRENT_REQUESTS,
)
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.concurrency")


class ConcurrencyLimitExceeded(Exception):
    """
    Raised when active requests exceed the configured concurrency limit for inference.
    """

    def __init__(self, resource: str, limit: int):
        self.resource = resource
        self.limit = limit
        self.code = "CONCURRENCY_LIMIT"
        super().__init__(
            f"Concurrency limit reached for {resource} (max {limit}). Service is busy."
        )


class ConcurrencyManager:
    """
    Thread-safe concurrency controller managing Guard, Target, and tenant inference slots.
    """

    def __init__(
        self,
        max_guard: int = MAX_CONCURRENT_GUARD_REQUESTS,
        max_target: int = MAX_CONCURRENT_TARGET_REQUESTS,
        max_per_tenant: int = MAX_TENANT_CONCURRENT_REQUESTS,
    ):
        self.max_guard = max_guard
        self.max_target = max_target
        self.max_per_tenant = max_per_tenant
        self._guard_semaphore = threading.Semaphore(max_guard)
        self._target_semaphore = threading.Semaphore(max_target)
        self._tenant_counts: Dict[str, int] = {}
        self._tenant_lock = threading.Lock()

    @contextmanager
    def guard_slot(self, timeout: float = 0.0) -> Generator[None, None, None]:
        """
        Acquires a concurrency slot for Guard evaluation.
        Raises ConcurrencyLimitExceeded immediately if all slots are occupied.
        """
        acquired = self._guard_semaphore.acquire(blocking=True, timeout=timeout)
        if not acquired:
            metrics.record_concurrency_rejected()
            logger.warning(
                "Guard concurrency limit exceeded (max=%d). Rejecting request.",
                self.max_guard,
            )
            raise ConcurrencyLimitExceeded("Guard", self.max_guard)

        try:
            yield
        finally:
            self._guard_semaphore.release()

    @contextmanager
    def target_slot(self, timeout: float = 0.0) -> Generator[None, None, None]:
        """
        Acquires a concurrency slot for Target model execution.
        Raises ConcurrencyLimitExceeded immediately if all slots are occupied.
        """
        acquired = self._target_semaphore.acquire(blocking=True, timeout=timeout)
        if not acquired:
            metrics.record_concurrency_rejected()
            logger.warning(
                "Target concurrency limit exceeded (max=%d). Rejecting request.",
                self.max_target,
            )
            raise ConcurrencyLimitExceeded("Target", self.max_target)

        try:
            yield
        finally:
            self._target_semaphore.release()

    @contextmanager
    def tenant_slot(self, tenant_id: Optional[str]) -> Generator[None, None, None]:
        """
        Acquires a tenant concurrency slot preventing one tenant from exhausting shared inference capacity.
        """
        if not tenant_id:
            yield
            return

        with self._tenant_lock:
            current = self._tenant_counts.get(tenant_id, 0)
            if current >= self.max_per_tenant:
                metrics.record_concurrency_rejected()
                logger.warning(
                    "Tenant concurrency limit exceeded: tenant=%s max=%d. Rejecting request.",
                    tenant_id,
                    self.max_per_tenant,
                )
                raise ConcurrencyLimitExceeded(f"Tenant[{tenant_id}]", self.max_per_tenant)
            self._tenant_counts[tenant_id] = current + 1

        try:
            yield
        finally:
            with self._tenant_lock:
                if tenant_id in self._tenant_counts:
                    self._tenant_counts[tenant_id] = max(0, self._tenant_counts[tenant_id] - 1)


# Global concurrency manager singleton
concurrency_manager = ConcurrencyManager()
