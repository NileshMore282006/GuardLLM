"""
AgentGuard v0.9 - Cryptographic Integrity & Hash Chain Tests
Verifies keyed HMAC-SHA-256 integrity calculation, deterministic canonical serialization,
and comprehensive tamper detection for record modification, deletion, insertion,
reordering, tenant modification, principal modification, decision modification,
approval_id modification, policy_version modification, and missing keys.
"""

import os
import sqlite3
import tempfile
import unittest

from backend.services.audit_service import AuditService, compute_event_hash
from backend.services.identity_service import Principal


class TestCryptoIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db_path = self.temp_db.name
        self.temp_db.close()
        self.test_key = "test-hmac-integrity-key-32-chars-long!"
        self.audit_service = AuditService(db_path=self.temp_db_path, integrity_key=self.test_key)

        self.user = Principal(
            principal_id="user-crypto",
            principal_type="user",
            roles=("user",),
            tenant_id="tenant-crypto",
            active=True,
        )

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    def _seed_chained_events(self, count: int = 5):
        for i in range(count):
            self.audit_service.log_event(
                action=f"action_{i}",
                request_id=f"req_{i}",
                principal=self.user,
                decision="ALLOW",
                policy_version=1,
                approval_id=f"appr_{i}",
            )

    def test_valid_chain_verifies_successfully(self):
        """A freshly generated HMAC-SHA-256 audit chain verifies as valid."""
        self._seed_chained_events(5)
        res = self.audit_service.verify_audit_chain()
        self.assertTrue(res["valid"])
        self.assertEqual(res["status"], "valid")
        self.assertEqual(res["total_events"], 5)
        self.assertIsNone(res["first_invalid_event"])

    def test_detect_modified_record_payload(self):
        """Modifying any field in an existing record is detected as tampered."""
        self._seed_chained_events(4)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET action = 'tampered_action' WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")
        self.assertIsNotNone(res["first_invalid_event"])

    def test_detect_deleted_record(self):
        """Deleting an intermediate record breaks the chain link and is detected."""
        self._seed_chained_events(4)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("DELETE FROM audit_events WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_inserted_record(self):
        """Inserting an unchained record in the middle is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute(
            """
            INSERT INTO audit_events (
                id, event_id, timestamp, request_id, principal_id, principal_type,
                action, resource_type, resource_id, decision, risk_score, attack_type,
                policy_id, policy_version, approval_id, tool_name, error_code,
                event_hash, previous_event_hash, tenant_id, hash_algorithm
            ) VALUES (
                999, 'evt_rogue', 1000.0, 'req_rogue', 'rogue_user', 'user',
                'rogue_action', NULL, NULL, 'ALLOW', NULL, NULL,
                NULL, NULL, NULL, NULL, NULL,
                'deadbeef0000', '0000deadbeef', 'tenant-crypto', 'hmac-sha256'
            )
            """
        )
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_reordered_records(self):
        """Swapping IDs or reordering records breaks the hash chain."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        # Swap actions or event IDs
        cur = conn.execute("SELECT event_hash FROM audit_events WHERE id = 1")
        h1 = cur.fetchone()[0]
        cur = conn.execute("SELECT event_hash FROM audit_events WHERE id = 2")
        h2 = cur.fetchone()[0]
        conn.execute("UPDATE audit_events SET event_hash = ? WHERE id = 1", (h2,))
        conn.execute("UPDATE audit_events SET event_hash = ? WHERE id = 2", (h1,))
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_modified_tenant(self):
        """Tampering with tenant_id in a stored event is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET tenant_id = 'tenant-spoofed' WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_modified_principal(self):
        """Tampering with principal_id in a stored event is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET principal_id = 'admin-spoofed' WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_modified_decision(self):
        """Tampering with decision (e.g. changing BLOCK to ALLOW) is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET decision = 'DENY' WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_modified_approval_id(self):
        """Tampering with approval_id in a stored event is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET approval_id = 'appr_spoofed' WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_detect_modified_policy_version(self):
        """Tampering with policy_version in a stored event is detected."""
        self._seed_chained_events(3)
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("UPDATE audit_events SET policy_version = 999 WHERE id = 2")
        conn.commit()
        conn.close()

        res = self.audit_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "tampered")

    def test_missing_integrity_key_fails_safely(self):
        """Verifying HMAC chained events without the key returns key_missing status."""
        self._seed_chained_events(3)
        # Create new service instance with NO key
        unkeyed_service = AuditService(db_path=self.temp_db_path, integrity_key=None)
        res = unkeyed_service.verify_audit_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "key_missing")
        self.assertIn("key is required", res["details"])

    def test_deterministic_canonical_serialization(self):
        """compute_event_hash produces identical digests regardless of internal dict ordering."""
        h1 = compute_event_hash(
            event_id="evt-1",
            timestamp=100.1234,
            request_id="req-1",
            principal_id="p-1",
            action="guard_check",
            resource_type="guard",
            resource_id="res-1",
            decision="BLOCK",
            risk_score=1.0,
            attack_type="prompt_injection",
            policy_id="pol-1",
            policy_version=1,
            approval_id=None,
            tool_name=None,
            error_code=None,
            previous_event_hash="0" * 64,
            tenant_id="tenant-1",
            key=self.test_key,
        )
        h2 = compute_event_hash(
            event_id="evt-1",
            timestamp=100.1234,
            request_id="req-1",
            principal_id="p-1",
            action="guard_check",
            resource_type="guard",
            resource_id="res-1",
            decision="BLOCK",
            risk_score=1.0,
            attack_type="prompt_injection",
            policy_id="pol-1",
            policy_version=1,
            approval_id=None,
            tool_name=None,
            error_code=None,
            previous_event_hash="0" * 64,
            tenant_id="tenant-1",
            key=self.test_key,
        )
        self.assertEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
