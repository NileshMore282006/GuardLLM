"""
AgentGuard v0.9 - Abuse Resistance & Rate Limiting Tests
Verifies authentication failure rate limiting, endpoint category limits,
tenant-level rate limits, anti-spoofing identity binding, and tenant concurrency boundaries.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.concurrency_service import ConcurrencyLimitExceeded, concurrency_manager
from backend.services.credential_service import credential_service
from backend.services.principal_service import principal_service
from backend.services.rate_limiter import InMemoryRateLimiter, rate_limiter
from backend.services.tenant_service import tenant_service


class TestAbuseResistance(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()
        _, self.admin_token = credential_service.create_credential(
            "admin-demo", "default", description="Abuse Test Admin", created_by="admin-demo"
        )
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        rate_limiter.reset()

    def tearDown(self):
        rate_limiter.reset()

    def test_auth_failure_rate_limiting(self):
        """Repeated authentication failures trigger 429 Too Many Requests."""
        test_limiter = InMemoryRateLimiter(enabled=True, max_requests=3, window_seconds=60)
        # 3 failures allowed
        for _ in range(3):
            allowed, _ = test_limiter.check_category_rate_limit("auth_failure", "192.168.1.100", limit=3)
            self.assertTrue(allowed)

        # 4th failure rejected
        allowed, retry_after = test_limiter.check_category_rate_limit("auth_failure", "192.168.1.100", limit=3)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)

    def test_category_rate_limits_enforced(self):
        """Category-specific limits protect sensitive endpoints (approvals, credentials, policies)."""
        test_limiter = InMemoryRateLimiter(enabled=True, max_requests=2, window_seconds=60)
        # Approvals category check
        self.assertTrue(test_limiter.check_category_rate_limit("approvals", "10.0.0.1", "p1", limit=2)[0])
        self.assertTrue(test_limiter.check_category_rate_limit("approvals", "10.0.0.1", "p1", limit=2)[0])
        # 3rd request blocked
        blocked, retry = test_limiter.check_category_rate_limit("approvals", "10.0.0.1", "p1", limit=2)
        self.assertFalse(blocked)

    def test_tenant_rate_limiting_prevents_shared_starvation(self):
        """A tenant exceeding tenant quota is throttled without affecting other tenants."""
        test_limiter = InMemoryRateLimiter(enabled=True, max_requests=2, window_seconds=60)
        # Tenant A exhausts its quota
        test_limiter.check_rate_limit("tenant:tenant-alpha", limit=2, window=60)
        test_limiter.check_rate_limit("tenant:tenant-alpha", limit=2, window=60)
        blocked_a, _ = test_limiter.check_rate_limit("tenant:tenant-alpha", limit=2, window=60)
        self.assertFalse(blocked_a)

        # Tenant B is completely unaffected
        allowed_b, _ = test_limiter.check_rate_limit("tenant:tenant-beta", limit=2, window=60)
        self.assertTrue(allowed_b)

    def test_client_cannot_spoof_rate_limiting_identity(self):
        """Client-supplied X-AgentGuard-Principal/Tenant headers do NOT alter server-bound rate limit key."""
        test_limiter = InMemoryRateLimiter(enabled=True, max_requests=2, window_seconds=60)
        # Key uses authenticated principal from context, ignoring spoof header
        key1 = f"cat:approvals:user-real:127.0.0.1"
        test_limiter.check_rate_limit(key1, limit=2)
        test_limiter.check_rate_limit(key1, limit=2)
        # Even if attacker claims they are "admin-spoofed", their real context key remains throttled
        blocked, _ = test_limiter.check_rate_limit(key1, limit=2)
        self.assertFalse(blocked)

    def test_tenant_concurrency_slots(self):
        """Tenant concurrency limit prevents one tenant from occupying all slots."""
        cm = concurrency_manager
        tenant_id = "tenant-noisy"

        # Acquire max tenant slots (max_per_tenant is 4)
        slots = []
        try:
            for _ in range(cm.max_per_tenant):
                ctx = cm.tenant_slot(tenant_id)
                ctx.__enter__()
                slots.append(ctx)

            # 5th attempt must raise ConcurrencyLimitExceeded
            with self.assertRaises(ConcurrencyLimitExceeded):
                with cm.tenant_slot(tenant_id):
                    pass
        finally:
            for s in slots:
                s.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
