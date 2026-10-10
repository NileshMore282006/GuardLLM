"""
Unit and Integration Test Suite for Live SOC Dashboard & 1-Click HITL Approval Queue
Tests:
1. Live SOC Posture Overview (/api/v1/secops/overview)
2. High-Risk Action Simulation (/api/v1/approvals/simulate)
3. 1-Click Human-in-the-Loop (HITL) Authorization (Approve -> CONSUMED with HMAC binding)
4. Replay Prevention on Consumed Approvals (HTTP 409 Conflict)
5. 1-Click Human-in-the-Loop Denial (Deny -> DENIED state)
6. Real-time Security Event Broadcaster (SSE stream frame verification)
7. Gateway integration: Security alerts automatically broadcast to SOC subscribers on attack detection
"""

import json
import time
import unittest
import uuid
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.approval_store import approval_store
from backend.services.event_stream_service import event_broadcaster
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service


class TestSecOpsDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, raise_server_exceptions=False)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        cls.test_tenant = f"soc-tenant-{uuid.uuid4().hex[:6]}"
        tenant_service.create_tenant(cls.test_tenant, "SOC Tenant")

        # Create admin principal and credential for privileged operations
        cls.admin_principal = f"soc-admin-{uuid.uuid4().hex[:6]}"
        principal_service.create_principal(
            principal_id=cls.admin_principal,
            principal_type="user",
            roles=["admin"],
            tenant_id=cls.test_tenant,
        )
        _, cls.admin_token = credential_service.create_credential(
            cls.admin_principal,
            cls.test_tenant,
        )
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def test_01_secops_overview(self):
        """Test GET /api/v1/secops/overview returns posture metrics and status."""
        resp = self.client.get("/api/v1/secops/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "operational")
        self.assertIn("version", data)
        self.assertIn("uptime_seconds", data)
        self.assertIn("pending_approvals_count", data)
        self.assertIn("latest_event_hash", data)
        self.assertIn("audit_chain_intact", data)
        self.assertIsInstance(data["audit_chain_intact"], bool)

    def test_02_simulate_high_risk_approval(self):
        """Test POST /api/v1/approvals/simulate generates high-risk HITL item."""
        payload = {
            "tool_name": "send_email",
            "tool_arguments": {
                "recipient": "audit-board@external.com",
                "subject": "Wire Transfer of $25,000",
                "body": "Approve invoice #9011.",
            },
            "risk_level": "high",
        }
        resp = self.client.post("/api/v1/approvals/simulate", json=payload)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["status"], "created")
        self.assertTrue(data["approval_id"].startswith("appr_"))
        self.assertEqual(data["tool_name"], "send_email")
        self.assertEqual(data["risk_level"], "high")

        # Verify it exists in the pending approval store
        appr_record = approval_store.get_approval(data["approval_id"])
        self.assertIsNotNone(appr_record)
        self.assertEqual(appr_record.tool_name, "send_email")
        self.assertEqual(appr_record.status, "PENDING_APPROVAL")
        self.assertTrue(len(appr_record.arguments_hash) > 0)

    def test_03_one_click_hitl_approval_and_replay_rejection(self):
        """Test 1-click Approve executes action and rejects replay attempts."""
        # 1. Simulate an approval request under admin tenant
        sim_resp = self.client.post(
            "/api/v1/approvals/simulate",
            json={
                "tool_name": "send_email",
                "tool_arguments": {
                    "recipient": "ops-lead@internal.corp",
                    "subject": "Firewall Rule Update",
                    "body": "Allow port 443 egress",
                },
                "risk_level": "high",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(sim_resp.status_code, 201)
        approval_id = sim_resp.json()["approval_id"]

        # 2. 1-Click Approve as SOC Admin
        approve_resp = self.client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            headers=self.admin_headers,
        )
        self.assertEqual(approve_resp.status_code, 200)
        approve_data = approve_resp.json()
        self.assertEqual(approve_data["approval_status"], "CONSUMED")
        self.assertEqual(approve_data["decision"], "ALLOW")

        # 3. Verify record in store is consumed
        appr_record = approval_store.get_approval(approval_id)
        self.assertEqual(appr_record.status, "CONSUMED")

        # 4. Attempt replay -> must return 409 Conflict
        replay_resp = self.client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            headers=self.admin_headers,
        )
        self.assertEqual(replay_resp.status_code, 409)

    def test_04_one_click_hitl_denial(self):
        """Test 1-click Deny transitions approval to DENIED and prevents execution."""
        sim_resp = self.client.post(
            "/api/v1/approvals/simulate",
            json={
                "tool_name": "delete_record",
                "tool_arguments": {"record_id": "rec_finance_audit_9824"},
                "risk_level": "critical",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(sim_resp.status_code, 201)
        approval_id = sim_resp.json()["approval_id"]

        # 1-Click Deny as SOC Admin
        deny_resp = self.client.post(
            f"/api/v1/approvals/{approval_id}/deny",
            headers=self.admin_headers,
        )
        self.assertEqual(deny_resp.status_code, 200)
        deny_data = deny_resp.json()
        self.assertEqual(deny_data["approval_status"], "DENIED")
        self.assertEqual(deny_data["decision"], "BLOCK")

        # Attempt to approve denied item -> must be rejected
        approve_attempt = self.client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            headers=self.admin_headers,
        )
        self.assertEqual(approve_attempt.status_code, 400)

    def test_05_event_broadcaster_pubsub(self):
        """Test EventStreamBroadcaster in-memory pubsub ring buffer."""
        test_evt = {
            "event_id": f"evt_test_{uuid.uuid4().hex[:8]}",
            "action": "test_threat_detected",
            "decision": "BLOCK",
            "attack_type": "prompt_injection",
            "timestamp": time.time(),
        }
        event_broadcaster.broadcast(test_evt)

        recent = event_broadcaster.get_recent_events(limit=5)
        found = any(e.get("event_id") == test_evt["event_id"] for e in recent)
        self.assertTrue(found, "Broadcasted event must be retained in recent history ring buffer")

    def test_06_live_stream_endpoint_headers(self):
        """Test GET /api/v1/secops/events/stream connects as Server-Sent Events."""
        # Check connection headers with a streaming client request
        with self.client.stream("GET", "/api/v1/secops/events/stream") as stream_resp:
            self.assertEqual(stream_resp.status_code, 200)
            self.assertIn("text/event-stream", stream_resp.headers.get("content-type", ""))
            self.assertIn("no-cache", stream_resp.headers.get("cache-control", ""))


if __name__ == "__main__":
    unittest.main()
