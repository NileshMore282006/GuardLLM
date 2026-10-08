"""
AgentGuard Test Suite
Configures high rate limits and defaults suitable for automated test suites.
"""
import os

os.environ.setdefault("AGENTGUARD_RATE_LIMIT_REQUESTS", "50000")

from backend.services.rate_limiter import rate_limiter

rate_limiter.max_requests = 50000
