"""
Unit and Integration Tests for AgentGuard v0.7 Authorization Security (RBAC)

Verifies:
- Deterministic RBAC enforcement without model dependency
- User denied admin and operator operations
- Operator permissions (read policies, read all audits, approve/deny actions)
- Admin permissions (create/update/delete policies, audit verify)
- Unknown permissions fail closed
- Ownership checks on user-scoped resources
- API endpoint RBAC enforcement via FastAPI TestClient
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.authorization_service import (
    ForbiddenError,
    check_permission,
    require_permission,
    require_role,
)
from backend.services.identity_service import Principal, resolve_principal


class TestAuthorizationSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.user = Principal(
            principal_id="user-demo",
            principal_type="user",
            roles=("user",),
            tenant_id="default",
            active=True,
        )
        self.operator = Principal(
            principal_id="operator-demo",
            principal_type="user",
            roles=("operator",),
            tenant_id="default",
            active=True,
        )
        self.admin = Principal(
            principal_id="admin-demo",
            principal_type="admin",
            roles=("admin",),
            tenant_id="default",
            active=True,
        )
        self.disabled_user = Principal(
            principal_id="disabled-demo",
            principal_type="user",
            roles=("admin",),
            tenant_id="default",
            active=False,
        )

    def test_user_denied_admin_operations(self):
        """Standard user principal must be denied policy administration and audit verification."""
        self.assertFalse(check_permission(self.user, "policy:admin"))
        self.assertFalse(check_permission(self.user, "audit:verify"))
        self.assertFalse(check_permission(self.user, "approval:approve"))
        self.assertFalse(check_permission(self.user, "approval:deny"))
        self.assertFalse(check_permission(self.user, "policy:read"))

        with self.assertRaises(ForbiddenError):
            require_permission(self.user, "policy:admin")

        with self.assertRaises(ForbiddenError):
            require_permission(self.user, "audit:verify")

    def test_user_permitted_low_risk_operations(self):
        """User principal is permitted low-risk capabilities and own approval inspection."""
        self.assertTrue(check_permission(self.user, "guard:submit"))
        self.assertTrue(check_permission(self.user, "execute:low_risk"))
        self.assertTrue(check_permission(self.user, "approval:create"))
        self.assertTrue(check_permission(self.user, "approval:inspect_own", target_principal_id="user-demo"))
        self.assertTrue(check_permission(self.user, "audit:read_own", target_principal_id="user-demo"))

    def test_user_cannot_inspect_other_principals_resources(self):
        """User principal cannot inspect approvals or audit events belonging to other principals."""
        self.assertFalse(check_permission(self.user, "approval:inspect_own", target_principal_id="other-user"))
        self.assertFalse(check_permission(self.user, "audit:read_own", target_principal_id="other-user"))
        with self.assertRaises(ForbiddenError):
            require_permission(self.user, "approval:inspect_own", target_principal_id="other-user")

    def test_operator_permissions(self):
        """Operator principal can inspect all approvals, approve/deny, read policies, and read audit events, but cannot mutate policies."""
        self.assertTrue(check_permission(self.operator, "guard:submit"))
        self.assertTrue(check_permission(self.operator, "approval:approve"))
        self.assertTrue(check_permission(self.operator, "approval:deny"))
        self.assertTrue(check_permission(self.operator, "approval:inspect_all"))
        self.assertTrue(check_permission(self.operator, "policy:read"))
        self.assertTrue(check_permission(self.operator, "audit:read_all"))

        # Operator CANNOT mutate policies or verify audit chain
        self.assertFalse(check_permission(self.operator, "policy:admin"))
        self.assertFalse(check_permission(self.operator, "audit:verify"))
        with self.assertRaises(ForbiddenError):
            require_permission(self.operator, "policy:admin")

    def test_admin_permissions(self):
        """Admin principal has all capabilities."""
        self.assertTrue(check_permission(self.admin, "guard:submit"))
        self.assertTrue(check_permission(self.admin, "policy:read"))
        self.assertTrue(check_permission(self.admin, "policy:admin"))
        self.assertTrue(check_permission(self.admin, "audit:read_all"))
        self.assertTrue(check_permission(self.admin, "audit:verify"))
        self.assertTrue(check_permission(self.admin, "approval:approve"))

    def test_unknown_capability_fails_closed(self):
        """Any unrecognized capability must fail closed even for admin."""
        self.assertFalse(check_permission(self.admin, "system:root"))
        self.assertFalse(check_permission(self.admin, "arbitrary_permission"))
        with self.assertRaises(ForbiddenError):
            require_permission(self.admin, "unknown:action")

    def test_inactive_principal_fails_closed(self):
        """Inactive principal must be denied all permissions even if configured with admin role."""
        self.assertFalse(check_permission(self.disabled_user, "policy:admin"))
        self.assertFalse(check_permission(self.disabled_user, "guard:submit"))
        with self.assertRaises(ForbiddenError):
            require_permission(self.disabled_user, "guard:submit")

    def test_require_role_enforcement(self):
        """require_role enforces deterministic membership in allowed roles."""
        require_role(self.admin, ["admin"])
        require_role(self.operator, ["operator", "admin"])
        with self.assertRaises(ForbiddenError):
            require_role(self.user, ["operator", "admin"])

    def test_api_policy_crud_enforces_admin_role(self):
        """User and Operator must be rejected with 403 FORBIDDEN when attempting policy creation."""
        policy_payload = {
            "name": "Test Deny Policy",
            "action": "DENY",
            "tool_scope": ["get_weather"],
            "priority": 50,
        }

        # User attempt
        res = self.client.post(
            "/api/v1/policies",
            json=policy_payload,
            headers={"X-AgentGuard-Principal": "user-demo"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()["error"]["code"], "FORBIDDEN")

        # Operator attempt
        res = self.client.post(
            "/api/v1/policies",
            json=policy_payload,
            headers={"X-AgentGuard-Principal": "operator-demo"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()["error"]["code"], "FORBIDDEN")

        # Admin attempt succeeds
        res = self.client.post(
            "/api/v1/policies",
            json=policy_payload,
            headers={"X-AgentGuard-Principal": "admin-demo"},
        )
        self.assertEqual(res.status_code, 201)
        created_id = res.json()["policy_id"]

        # Cleanup
        self.client.delete(
            f"/api/v1/policies/{created_id}",
            headers={"X-AgentGuard-Principal": "admin-demo"},
        )

    def test_api_policy_read_enforces_operator_or_admin(self):
        """Standard user cannot read policy definitions; operator and admin can."""
        res_user = self.client.get(
            "/api/v1/policies",
            headers={"X-AgentGuard-Principal": "user-demo"},
        )
        self.assertEqual(res_user.status_code, 403)
        self.assertEqual(res_user.json()["error"]["code"], "FORBIDDEN")

        res_op = self.client.get(
            "/api/v1/policies",
            headers={"X-AgentGuard-Principal": "operator-demo"},
        )
        self.assertEqual(res_op.status_code, 200)

        res_admin = self.client.get(
            "/api/v1/policies",
            headers={"X-AgentGuard-Principal": "admin-demo"},
        )
        self.assertEqual(res_admin.status_code, 200)


if __name__ == "__main__":
    unittest.main()
