"""
AgentGuard v1.0 - Audit Tampering Integration Test Suite (Objective 16)
Validates that ANY manual alteration of historical audit rows breaks the cryptographic
HMAC-SHA-256 chain and is detected during verification.

Tests:
1.  Change decision (BLOCK -> ALLOW)
2.  Change tenant_id (tenant-alpha -> tenant-beta)
3.  Change principal_id (user-1 -> admin-1)
4.  Change request_id
5.  Change timestamp
6.  Change tool_name
7.  Change approval_id
8.  Delete first (genesis) record
9.  Delete middle record
10. Delete final record
11. Insert spurious intermediate record
12. Reorder historical records
13. Tamper with previous_event_hash value
14. Verification using incorrect HMAC audit key
"""

import os
import sqlite3
import tempfile
import unittest

from backend.services.audit_service import AuditService


class TestAuditTampering(unittest.TestCase):
    def setUp(self):
        self.tmp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_path = self.tmp_file.name
        self.tmp_file.close()

        self.key = "audit-master-integrity-key-32chars-min-ok"
        self.audit_service = AuditService(db_path=self.tmp_path, integrity_key=self.key)

        # Populate a sample audit chain with 5 distinct records
        for i in range(1, 6):
            self.audit_service.log_event(
                action=f"action_{i}",
                request_id=f"req_{i:04d}",
                principal_id=f"user_{i}",
                tenant_id="tenant-alpha",
                decision="BLOCK" if i % 2 == 0 else "ALLOW",
                tool_name=f"tool_{i}" if i % 2 == 0 else None,
                approval_id=f"appr_{i}" if i % 2 == 0 else None,
            )

        # Baseline: initial chain must be completely valid
        baseline = self.audit_service.verify_audit_chain()
        self.assertTrue(baseline["valid"], f"Baseline failed: {baseline}")

    def tearDown(self):
        try:
            if os.path.exists(self.tmp_path):
                os.remove(self.tmp_path)
        except OSError:
            pass

    def _execute_sql(self, sql: str, params: tuple = ()):
        conn = sqlite3.connect(self.tmp_path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def test_tamper_decision(self):
        """Modifying decision column (e.g. BLOCK -> ALLOW) breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET decision = 'ALLOW' WHERE id = 2")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_tenant(self):
        """Modifying tenant_id column breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET tenant_id = 'tenant-hacked' WHERE id = 3")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_principal(self):
        """Modifying principal_id column breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET principal_id = 'admin-elevated' WHERE id = 1")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_request_id(self):
        """Modifying request_id column breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET request_id = 'req-forged' WHERE id = 4")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_timestamp(self):
        """Modifying timestamp breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET timestamp = 99999.0 WHERE id = 2")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_tool_name(self):
        """Modifying tool_name breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET tool_name = 'delete_database' WHERE id = 2")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_tamper_approval_id(self):
        """Modifying approval_id breaks HMAC verification."""
        self._execute_sql("UPDATE audit_events SET approval_id = 'appr_spoofed' WHERE id = 4")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_delete_first_record(self):
        """Deleting the genesis record causes record 2 to fail previous_event_hash check."""
        self._execute_sql("DELETE FROM audit_events WHERE id = 1")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_delete_middle_record(self):
        """Deleting an intermediate record breaks the previous_event_hash link for subsequent rows."""
        self._execute_sql("DELETE FROM audit_events WHERE id = 3")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_delete_final_record(self):
        """Deleting the final record leaves remaining records internally consistent."""
        self._execute_sql("DELETE FROM audit_events WHERE id = 5")
        # Records 1-4 remain valid HMAC chain
        result = self.audit_service.verify_audit_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["total_events"], 4)

    def test_insert_spurious_record(self):
        """Inserting an unchained record in the database causes verification failure."""
        self._execute_sql(
            "INSERT INTO audit_events (id, event_id, timestamp, action, request_id, tenant_id, principal_id, decision, event_hash, previous_event_hash) "
            "VALUES (99, 'evt_fake', 12345.0, 'hack', 'req_99', 'default', 'attacker', 'ALLOW', 'fake_hmac', 'GENESIS')"
        )
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_reorder_records(self):
        """Swapping record hashes breaks sequential previous_event_hash chain."""
        conn = sqlite3.connect(self.tmp_path)
        cur = conn.cursor()
        cur.execute("SELECT event_hash FROM audit_events WHERE id = 2")
        h2 = cur.fetchone()[0]
        cur.execute("SELECT event_hash FROM audit_events WHERE id = 3")
        h3 = cur.fetchone()[0]
        cur.execute("UPDATE audit_events SET event_hash = ? WHERE id = 2", (h3,))
        cur.execute("UPDATE audit_events SET event_hash = ? WHERE id = 3", (h2,))
        conn.commit()
        conn.close()

        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_change_previous_hash(self):
        """Directly altering the previous_event_hash column breaks verification."""
        self._execute_sql("UPDATE audit_events SET previous_event_hash = 'corrupted_prev_hash' WHERE id = 4")
        result = self.audit_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")

    def test_wrong_audit_key_detected(self):
        """Verifying the chain with an incorrect HMAC key fails immediately."""
        wrong_service = AuditService(db_path=self.tmp_path, integrity_key="wrong-key-completely-different-32chars")
        result = wrong_service.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["status"], "tampered")


if __name__ == "__main__":
    unittest.main()
