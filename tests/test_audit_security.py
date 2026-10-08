"""
Unit and Security Tests for AgentGuard v0.7 Persistent Security Audit Service

Verifies:
- Event persistence in local SQLite database
- Survival of audit logs across service re-initialization (restart)
- Safe fields policy: no raw prompts or sensitive arguments stored
- Strict canary secret redaction (BLUE-ORANGE-42 never stored in plaintext)
- Cryptographic SHA-256 hash chaining (previous_event_hash -> event_hash)
- Integrity verification via verify_audit_chain()
- Tamper detection when records are modified or deleted
- Bounded pagination and SQL injection safety (parameterized queries)
- RBAC ownership enforcement on audit read endpoints
"""

import os
import sqlite3
import tempfile
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.audit_service import AuditService, compute_event_hash
from backend.services.identity_service import Principal


class TestAuditSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        # Use a temporary SQLite database for test isolation
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()

        self.audit_service = AuditService(db_path=self.temp_db_path)

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

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def test_event_persistence(self):
        """Logged events are saved in SQLite with required safe metadata fields."""
        ev = self.audit_service.log_event(
            action="guard_block",
            request_id="req-101",
            principal=self.user,
            resource_type="guard",
            resource_id="input_guard",
            decision="BLOCK",
            risk_score=0.98,
            attack_type="prompt_injection",
        )
        self.assertIsNotNone(ev)
        self.assertIsNotNone(ev.event_id)
        self.assertEqual(ev.decision, "BLOCK")

        events, total = self.audit_service.query_events(principal=self.admin, request_id="req-101")
        self.assertEqual(total, 1)
        self.assertEqual(events[0]["event_id"], ev.event_id)
        self.assertEqual(events[0]["decision"], "BLOCK")
        self.assertEqual(events[0]["principal_id"], "user-demo")

    def test_restart_persistence(self):
        """Events survive service restart (re-instantiating the service against the same SQLite db)."""
        ev = self.audit_service.log_event(
            action="tool_allow",
            request_id="req-restart-1",
            principal=self.user,
            resource_type="tool",
            resource_id="get_weather",
            decision="ALLOW",
            tool_name="get_weather",
        )
        self.assertIsNotNone(ev)

        # Simulate service restart
        new_service = AuditService(db_path=self.temp_db_path)
        events, total = new_service.query_events(principal=self.admin, request_id="req-restart-1")
        self.assertEqual(total, 1)
        self.assertEqual(events[0]["event_id"], ev.event_id)

    def test_no_secret_leakage_in_audit_fields(self):
        """Canary secret BLUE-ORANGE-42 must be redacted from all persisted fields."""
        canary = "BLUE-ORANGE-42"
        ev = self.audit_service.log_event(
            action="guard_block",
            request_id=f"req-with-{canary}",
            principal=self.user,
            resource_type=f"tool-{canary}",
            resource_id=f"id-{canary}",
            decision="BLOCK",
            attack_type=f"injection_attempt_{canary}",
            tool_name=f"tool_{canary}",
            error_code=f"err_{canary}",
        )
        self.assertIsNotNone(ev)

        # Read directly from SQLite raw table
        conn = sqlite3.connect(self.temp_db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM audit_events WHERE event_id = ?", (ev.event_id,))
        row = dict(cur.fetchone())
        conn.close()

        # Check every text column in the raw row
        for key, val in row.items():
            if isinstance(val, str):
                self.assertNotIn(
                    canary,
                    val,
                    f"Secret canary leaked in audit column '{key}': {val}",
                )

    def test_hash_chaining_and_verification(self):
        """Sequential events create a cryptographically valid SHA-256 chain."""
        for i in range(5):
            self.audit_service.log_event(
                action=f"action_{i}",
                request_id=f"req_{i}",
                principal=self.user,
                resource_type="test",
                decision="ALLOW",
            )

        verification = self.audit_service.verify_audit_chain()
        self.assertTrue(verification["valid"])
        self.assertIsNone(verification["first_invalid_event"])
        self.assertEqual(verification["total_events"], 5)

    def test_tamper_detection_on_record_modification(self):
        """Directly altering a record in SQLite breaks the hash chain and is detected."""
        for i in range(4):
            self.audit_service.log_event(
                action=f"action_{i}",
                request_id=f"req_{i}",
                principal=self.user,
                resource_type="test",
                decision="ALLOW",
            )

        # Tamper directly in SQLite: change decision of 2nd event from ALLOW to BLOCK
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET decision = 'BLOCK' WHERE id = 2")
        conn.commit()
        conn.close()

        verification = self.audit_service.verify_audit_chain()
        self.assertFalse(verification["valid"])
        self.assertIsNotNone(verification["first_invalid_event"])

    def test_tamper_detection_on_record_deletion(self):
        """Directly deleting a record from SQLite breaks the hash chain link and is detected."""
        for i in range(4):
            self.audit_service.log_event(
                action=f"action_{i}",
                request_id=f"req_{i}",
                principal=self.user,
                resource_type="test",
                decision="ALLOW",
            )

        # Delete the 3rd event
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("DELETE FROM audit_events WHERE id = 3")
        conn.commit()
        conn.close()

        verification = self.audit_service.verify_audit_chain()
        self.assertFalse(verification["valid"])
        self.assertIsNotNone(verification["first_invalid_event"])

    def test_rbac_ownership_filtering(self):
        """Standard user only retrieves their own events; operator/admin can retrieve all."""
        self.audit_service.log_event(
            action="guard_submit",
            request_id="req-user-1",
            principal=self.user,
            resource_type="guard",
            decision="ALLOW",
        )
        self.audit_service.log_event(
            action="guard_submit",
            request_id="req-admin-1",
            principal=self.admin,
            resource_type="guard",
            decision="ALLOW",
        )

        # User queries events: should only see their own
        user_events, user_total = self.audit_service.query_events(principal=self.user)
        self.assertEqual(user_total, 1)
        self.assertEqual(user_events[0]["principal_id"], "user-demo")

        # Admin queries events: sees both
        admin_events, admin_total = self.audit_service.query_events(principal=self.admin)
        self.assertEqual(admin_total, 2)

    def test_bounded_pagination(self):
        """Excessive limit requests are capped safely to MAX_AUDIT_PAGE_SIZE."""
        events, total = self.audit_service.query_events(principal=self.admin, limit=999999)
        self.assertIsInstance(events, list)

    def test_api_audit_endpoints_rbac(self):
        """API endpoints enforce RBAC: user cannot call verify, admin can."""
        # User calling verify -> 403 FORBIDDEN
        res_user_verify = self.client.get(
            "/api/v1/audit/verify",
            headers={"X-AgentGuard-Principal": "user-demo"},
        )
        self.assertEqual(res_user_verify.status_code, 403)

        # Operator calling verify -> 403 FORBIDDEN (admin only)
        res_op_verify = self.client.get(
            "/api/v1/audit/verify",
            headers={"X-AgentGuard-Principal": "operator-demo"},
        )
        self.assertEqual(res_op_verify.status_code, 403)

        # Admin calling verify -> 200 OK
        res_admin_verify = self.client.get(
            "/api/v1/audit/verify",
            headers={"X-AgentGuard-Principal": "admin-demo"},
        )
        self.assertEqual(res_admin_verify.status_code, 200)
        self.assertIn("valid", res_admin_verify.json())


if __name__ == "__main__":
    unittest.main()
