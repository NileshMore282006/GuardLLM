"""
Unit and Security Tests for AgentGuard v0.7: Identity and Principal Abstraction
Covers:
1. Valid principal resolution
2. Missing principal handling (enforced vs default mode)
3. Unknown / guessed principal rejection (INVALID_PRINCIPAL)
4. Inactive / disabled principal rejection (PRINCIPAL_DISABLED)
5. Immunity to client role self-assignment (X-AgentGuard-Role)
6. Principal immutability
"""

import os
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.identity_service import (
    AuthenticationRequiredError,
    InvalidPrincipalError,
    Principal,
    PrincipalDisabledError,
    identity_registry,
    resolve_principal,
)


class TestIdentitySecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        identity_registry.reset()

    def test_valid_principal_resolution(self):
        """Valid local development principals must be resolved correctly."""
        p_user = resolve_principal(principal_id="user-demo")
        self.assertEqual(p_user.principal_id, "user-demo")
        self.assertEqual(p_user.principal_type, "user")
        self.assertIn("user", p_user.roles)
        self.assertTrue(p_user.active)

        p_admin = resolve_principal(principal_id="admin-demo")
        self.assertEqual(p_admin.principal_id, "admin-demo")
        self.assertIn("admin", p_admin.roles)

        p_operator = resolve_principal(principal_id="operator-demo")
        self.assertIn("operator", p_operator.roles)

    def test_missing_principal_default_mode(self):
        """When identity is disabled, missing principal header falls back to default principal."""
        with patch("backend.services.identity_service.IDENTITY_ENABLED", False):
            p = resolve_principal()
            self.assertEqual(p.principal_id, "user-demo")
            self.assertIn("user", p.roles)

    def test_missing_principal_enforced_mode(self):
        """When identity is enabled, missing principal header raises AuthenticationRequiredError."""
        with patch("backend.services.identity_service.IDENTITY_ENABLED", True):
            with self.assertRaises(AuthenticationRequiredError) as ctx:
                resolve_principal()
            self.assertEqual(ctx.exception.code, "AUTHENTICATION_REQUIRED")

    def test_unknown_principal_rejected(self):
        """Unknown or guessed principal must be rejected with INVALID_PRINCIPAL."""
        with self.assertRaises(InvalidPrincipalError) as ctx:
            resolve_principal(principal_id="attacker-admin-999")
        self.assertEqual(ctx.exception.code, "INVALID_PRINCIPAL")

    def test_disabled_principal_rejected(self):
        """Disabled principal must be rejected with PRINCIPAL_DISABLED."""
        with self.assertRaises(PrincipalDisabledError) as ctx:
            resolve_principal(principal_id="disabled-demo")
        self.assertEqual(ctx.exception.code, "PRINCIPAL_DISABLED")

    def test_client_cannot_self_assign_role(self):
        """
        SECURITY INVARIANT:
        The client must NEVER be able to grant itself privileges by passing role headers.
        """
        headers = {
            "X-AgentGuard-Principal": "user-demo",
            "X-AgentGuard-Role": "admin",  # Malicious attempt to elevate to admin
        }
        # Attempt an admin-only operation (create policy)
        resp = self.client.post(
            "/api/v1/policies",
            json={
                "name": "Malicious Privilege Policy",
                "action": "ALLOW",
                "principal_scope": ["*"],
                "tool_scope": ["*"],
                "risk_levels": ["*"],
            },
            headers=headers,
        )
        # Must be rejected with 403 Forbidden because server resolves roles from registry
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json().get("error", {}).get("code"), "FORBIDDEN")

    def test_principal_immutability(self):
        """Principal objects must be immutable and cannot be tampered with in memory."""
        p = resolve_principal(principal_id="user-demo")
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            p.roles = ("admin",)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            p.principal_id = "admin-demo"

    def test_api_unknown_principal_error(self):
        """HTTP API returns safe 401 when an unknown principal is passed."""
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"X-AgentGuard-Principal": "nonexistent-user"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json().get("error", {}).get("code"), "INVALID_PRINCIPAL")

    def test_api_disabled_principal_error(self):
        """HTTP API returns safe 403 when a disabled principal is passed."""
        resp = self.client.post(
            "/api/v1/guard",
            json={"prompt": "Hello"},
            headers={"X-AgentGuard-Principal": "disabled-demo"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json().get("error", {}).get("code"), "PRINCIPAL_DISABLED")


if __name__ == "__main__":
    unittest.main()
