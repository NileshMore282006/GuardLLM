"""
AgentGuard Database Hardening Layer (v0.9)
Provides hardened SQLite connection management, path validation against traversal,
foreign key enforcement, WAL mode, busy timeouts, and integrity verification.

SECURITY INVARIANTS:
1. All queries MUST be parameterized. Raw SQL concatenation with user input is forbidden.
2. Foreign key enforcement is strictly enabled on every connection (PRAGMA foreign_keys = ON).
3. Busy timeout is configured to mitigate concurrency locks (PRAGMA busy_timeout = 5000).
4. WAL mode is enabled for safe concurrent reading and writing where supported.
5. Database paths are validated against directory traversal ('..') and illegal characters.
6. Database integrity checks (PRAGMA quick_check) are available for readiness probes.
7. Corrupted production databases are NEVER automatically deleted or silently recreated.
8. Database filesystem paths are NEVER exposed to API clients or in exception responses.
"""

import logging
import os
import sqlite3
from typing import Optional, Tuple

from backend.config import (
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_WAL_MODE,
)

logger = logging.getLogger("agentguard.db_hardening")


class DatabaseSecurityError(Exception):
    """Base exception for database security and validation errors."""
    def __init__(self, message: str = "Database operation rejected."):
        super().__init__(message)
        self.code = "DATABASE_ERROR"
        self.message = message


class DatabasePathError(DatabaseSecurityError):
    """Raised when a database path is invalid or attempts directory traversal."""
    def __init__(self, message: str = "Invalid or unauthorized database path."):
        super().__init__(message)
        self.code = "DATABASE_PATH_ERROR"


class DatabaseCorruptionError(DatabaseSecurityError):
    """Raised when database integrity check fails."""
    def __init__(self, message: str = "Database integrity check failed."):
        super().__init__(message)
        self.code = "DATABASE_CORRUPT"


def sanitize_db_path(db_path: str, allow_memory: bool = True) -> str:
    """
    Validates and sanitizes a SQLite database path.
    Prevents directory traversal, null bytes, and unauthorized file access.
    """
    if not db_path or not db_path.strip():
        raise DatabasePathError("Database path cannot be empty.")

    clean_path = db_path.strip()

    if allow_memory and clean_path == ":memory:":
        return ":memory:"

    if "\x00" in clean_path:
        raise DatabasePathError("Database path contains forbidden null bytes.")

    # Normalize path and check for '..' traversal components
    normalized = os.path.normpath(clean_path)
    parts = normalized.split(os.sep)
    if ".." in parts:
        raise DatabasePathError("Directory traversal ('..') is strictly forbidden in database paths.")

    return normalized


def get_hardened_connection(
    db_path: str,
    timeout: Optional[float] = None,
    enforce_foreign_keys: bool = True,
    wal_mode: Optional[bool] = None,
) -> sqlite3.Connection:
    """
    Creates and returns a hardened SQLite connection with security PRAGMAs configured:
    - Path validated against traversal
    - row_factory set to sqlite3.Row
    - PRAGMA foreign_keys = ON
    - PRAGMA busy_timeout = SQLITE_BUSY_TIMEOUT_MS
    - PRAGMA journal_mode = WAL (when enabled and file-based)
    - PRAGMA synchronous = NORMAL (when WAL)
    """
    safe_path = sanitize_db_path(db_path)
    busy_timeout = int(timeout * 1000) if timeout else SQLITE_BUSY_TIMEOUT_MS
    use_wal = SQLITE_WAL_MODE if wal_mode is None else wal_mode

    # Ensure parent directory exists for file-based databases
    if safe_path != ":memory:":
        parent = os.path.dirname(safe_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(safe_path, timeout=busy_timeout / 1000.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    try:
        cur = conn.cursor()

        # Enforce foreign keys
        if enforce_foreign_keys:
            cur.execute("PRAGMA foreign_keys = ON;")

        # Set busy timeout
        cur.execute(f"PRAGMA busy_timeout = {busy_timeout};")

        # Enable WAL mode for non-memory databases if configured
        if safe_path != ":memory:" and use_wal:
            try:
                cur.execute("PRAGMA journal_mode = WAL;")
                cur.execute("PRAGMA synchronous = NORMAL;")
            except Exception as wal_exc:
                logger.warning("Could not enable WAL mode on '%s': %s", safe_path, wal_exc)

        cur.close()
    except Exception as exc:
        conn.close()
        logger.error("Failed to apply hardening PRAGMAs to database: %s", type(exc).__name__)
        raise DatabaseSecurityError("Failed to initialize hardened database connection.") from exc

    return conn


def check_database_integrity(conn: sqlite3.Connection) -> Tuple[bool, str]:
    """
    Executes PRAGMA quick_check to verify SQLite database file integrity.
    Returns (is_healthy, status_message).
    """
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA quick_check;")
        rows = cur.fetchall()
        cur.close()

        if not rows:
            return False, "No integrity check output returned."

        status_result = rows[0][0]
        if status_result == "ok":
            return True, "ok"
        else:
            logger.error("Database integrity corruption detected: %s", status_result)
            return False, f"Integrity check failed: {status_result}"

    except Exception as exc:
        logger.error("Database integrity check exception: %s", type(exc).__name__)
        return False, f"Integrity check error: {type(exc).__name__}"


def ensure_schema_migrations_table(conn: sqlite3.Connection) -> None:
    """Ensures the schema_migrations tracking table exists."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
