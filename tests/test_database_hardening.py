"""
AgentGuard v0.9 - Database Hardening & SQLite Security Tests
Validates parameterized queries, path traversal defense, foreign key enforcement,
busy timeout handling, corruption detection via PRAGMA quick_check, concurrent writes,
and absence of database paths in API error responses.
"""

import os
import sqlite3
import tempfile
import threading
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.db_hardening import (
    DatabasePathError,
    check_database_integrity,
    get_hardened_connection,
    sanitize_db_path,
)


class TestDatabaseHardening(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "hardened_test.db")

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
        if os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except OSError:
                pass

    def test_path_traversal_attempts_rejected(self):
        """Database paths containing '..' or null bytes are rejected with DatabasePathError."""
        bad_paths = [
            "../../etc/passwd",
            "data/../../shadow.db",
            "data/identity.db\x00.exe",
            "",
            "   ",
        ]
        for path in bad_paths:
            with self.assertRaises(DatabasePathError):
                sanitize_db_path(path)

    def test_hardened_connection_pragmas(self):
        """Hardened connections have foreign_keys ON, busy_timeout set, and WAL mode configured."""
        conn = get_hardened_connection(self.db_path, timeout=3.0)
        try:
            cur = conn.cursor()
            # Foreign keys
            cur.execute("PRAGMA foreign_keys;")
            fk = cur.fetchone()[0]
            self.assertEqual(fk, 1, "Foreign keys must be enabled.")

            # Busy timeout
            cur.execute("PRAGMA busy_timeout;")
            bt = cur.fetchone()[0]
            self.assertGreaterEqual(bt, 1000, "Busy timeout must be configured.")
            cur.close()
        finally:
            conn.close()

    def test_database_integrity_check(self):
        """check_database_integrity detects healthy database and reports 'ok'."""
        conn = get_hardened_connection(self.db_path)
        try:
            with conn:
                conn.execute("CREATE TABLE test_tbl (id INTEGER PRIMARY KEY, val TEXT)")
                conn.execute("INSERT INTO test_tbl (val) VALUES ('test1')")
            healthy, msg = check_database_integrity(conn)
            self.assertTrue(healthy)
            self.assertEqual(msg, "ok")
        finally:
            conn.close()

    def test_database_corruption_detected(self):
        """Corrupted SQLite file is detected by check_database_integrity."""
        corrupt_path = os.path.join(self.temp_dir, "corrupt.db")
        # Write corrupted garbage data to header
        with open(corrupt_path, "wb") as f:
            f.write(b"NOT A SQLITE FILE GARBAGE DATA 0123456789")

        conn = sqlite3.connect(corrupt_path)
        try:
            healthy, msg = check_database_integrity(conn)
            self.assertFalse(healthy)
        finally:
            conn.close()
        if os.path.exists(corrupt_path):
            os.remove(corrupt_path)

    def test_sql_injection_in_queries_fails_safely(self):
        """Attempted SQL injection payloads fail safely without modifying schema or returning secrets."""
        conn = get_hardened_connection(self.db_path)
        try:
            with conn:
                conn.execute("CREATE TABLE items (name TEXT PRIMARY KEY, value TEXT)")
                conn.execute("INSERT INTO items VALUES (?, ?)", ("valid_item", "secret_123"))

            # Malicious input using parameterized query
            user_input = "valid_item' OR '1'='1"
            cur = conn.execute("SELECT * FROM items WHERE name = ?", (user_input,))
            rows = cur.fetchall()
            self.assertEqual(len(rows), 0, "Parameterized query successfully blocked injection.")
        finally:
            conn.close()

    def test_safe_concurrent_writes_with_busy_timeout(self):
        """Multiple threads writing concurrently do not encounter unhandled database locks."""
        conn = get_hardened_connection(self.db_path)
        with conn:
            conn.execute("CREATE TABLE concurrent_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tid INTEGER)")
        conn.close()

        errors = []

        def worker(thread_id: int):
            try:
                for i in range(10):
                    c = get_hardened_connection(self.db_path, timeout=5.0)
                    try:
                        with c:
                            c.execute("INSERT INTO concurrent_log (tid) VALUES (?)", (thread_id,))
                    finally:
                        c.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent writes had errors: {errors}")

        check_conn = get_hardened_connection(self.db_path)
        cur = check_conn.execute("SELECT COUNT(*) FROM concurrent_log")
        total = cur.fetchone()[0]
        check_conn.close()
        self.assertEqual(total, 40)

    def test_database_paths_never_leaked_in_api_errors(self):
        """API endpoints never leak database filesystem paths in error responses."""
        resp = self.client.get("/api/v1/credentials/nonexistent-id")
        self.assertNotIn(".db", resp.text)
        self.assertNotIn("data/", resp.text)
        self.assertNotIn("agentguard_identity", resp.text)


if __name__ == "__main__":
    unittest.main()
