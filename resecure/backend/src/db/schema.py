"""
CalmStacks ReSecure Persistence Layer - Schema Initializer & Migration Runner
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.db.schema
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Optional

from .connection import DatabaseConnectionManager, get_connection_manager

logger = logging.getLogger("resecure.db.schema")

# Required tables for schema verification
EXPECTED_TABLES = [
    "files",
    "manifests",
    "chunks",
    "recovery_jobs",
    "corruption_events",
    "format_validations",
]

# Required indexes for schema verification
EXPECTED_INDEXES = [
    "idx_files_root_sha256",
    "idx_manifests_file_id",
    "idx_chunks_manifest_index",
    "idx_jobs_file_status",
    "idx_corruption_job_id",
    "idx_validation_filename",
]

# Inlined fallback SQL in case disk file is displaced
EMBEDDED_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    root_sha256 TEXT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    file_path TEXT,
    file_format TEXT DEFAULT 'BINARY'
        CHECK (file_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_files_root_sha256 ON files(root_sha256);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);

CREATE TRIGGER IF NOT EXISTS trg_files_updated_at
AFTER UPDATE ON files
FOR EACH ROW
WHEN (NEW.updated_at = OLD.updated_at)
BEGIN
    UPDATE files SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE file_id = OLD.file_id;
END;

CREATE TABLE IF NOT EXISTS manifests (
    manifest_id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    total_chunks INTEGER NOT NULL CHECK (total_chunks > 0),
    chunk_size INTEGER NOT NULL CHECK (chunk_size > 0),
    redundancy_percent INTEGER NOT NULL
        CHECK (redundancy_percent >= 5 AND redundancy_percent <= 100),
    parity_chunks INTEGER NOT NULL CHECK (parity_chunks >= 0),
    hmac_signature TEXT NOT NULL,
    key_id TEXT,
    raw_manifest_json TEXT NOT NULL,
    parity_file_path TEXT,
    manifest_version TEXT NOT NULL DEFAULT '1.0.0',
    algorithm TEXT NOT NULL DEFAULT 'Reed-Solomon-GF256',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_manifests_file_id ON manifests(file_id);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    chunk_sha256 TEXT NOT NULL,
    is_parity INTEGER NOT NULL DEFAULT 0 CHECK (is_parity IN (0, 1)),
    live_sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'HEALTHY'
        CHECK (status IN ('HEALTHY', 'CORRUPTED', 'MISSING', 'OVERSIZED')),
    last_verified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (manifest_id, chunk_index, is_parity)
);

CREATE INDEX IF NOT EXISTS idx_chunks_manifest_index ON chunks(manifest_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_chunks_status ON chunks(status);

CREATE TABLE IF NOT EXISTS recovery_jobs (
    job_id TEXT PRIMARY KEY,
    file_id TEXT REFERENCES files(file_id) ON DELETE SET NULL,
    manifest_id TEXT REFERENCES manifests(manifest_id) ON DELETE SET NULL,
    job_type TEXT NOT NULL
        CHECK (job_type IN ('VERIFY', 'RECOVER', 'REPAIR', 'PROTECT', 'VALIDATE')),
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'PROCESSING', 'COMPLETED', 'FAILED', 'UNRECOVERABLE')),
    corrupted_chunks_count INTEGER NOT NULL DEFAULT 0 CHECK (corrupted_chunks_count >= 0),
    recovered_chunks_count INTEGER NOT NULL DEFAULT 0 CHECK (recovered_chunks_count >= 0),
    original_sha256 TEXT,
    recovered_sha256 TEXT,
    sha256_match INTEGER CHECK (sha256_match IN (0, 1) OR sha256_match IS NULL),
    output_path TEXT,
    error_code TEXT,
    error_message TEXT,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT,
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
    progress_pct REAL NOT NULL DEFAULT 0.0 CHECK (progress_pct >= 0.0 AND progress_pct <= 100.0),
    source_path TEXT,
    parity_consumed INTEGER NOT NULL DEFAULT 0 CHECK (parity_consumed >= 0),
    verdict TEXT
        CHECK (verdict IS NULL OR verdict IN ('PRISTINE', 'RECOVERABLE', 'VERIFIED_EXACT', 'UNRECOVERABLE_EXACT', 'STRUCTURALLY_SALVAGED', 'INTEGRITY_VIOLATION'))
);

CREATE INDEX IF NOT EXISTS idx_jobs_file_status ON recovery_jobs(file_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON recovery_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_started_at ON recovery_jobs(started_at);

CREATE TABLE IF NOT EXISTS corruption_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES recovery_jobs(job_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),
    expected_sha256 TEXT NOT NULL,
    actual_sha256 TEXT,
    corruption_type TEXT NOT NULL
        CHECK (corruption_type IN ('MODIFIED', 'MISSING', 'TRUNCATED', 'BIT_FLIP', 'ZERO_FILL', 'HEADER_WIPE', 'INJECTION')),
    byte_length INTEGER DEFAULT NULL,
    detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_corruption_job_id ON corruption_events(job_id);
CREATE INDEX IF NOT EXISTS idx_corruption_type ON corruption_events(corruption_type);

CREATE TABLE IF NOT EXISTS format_validations (
    validation_id TEXT PRIMARY KEY,
    file_id TEXT REFERENCES files(file_id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    detected_format TEXT NOT NULL
        CHECK (detected_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY', 'UNKNOWN')),
    is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
    details_json TEXT NOT NULL DEFAULT '{}',
    format_verdict TEXT DEFAULT 'FORMAT_VALID'
        CHECK (format_verdict IS NULL OR format_verdict IN ('FORMAT_VALID', 'FORMAT_INVALID', 'STRUCTURALLY_SALVAGED')),
    repair_log_json TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_validation_filename ON format_validations(filename);
CREATE INDEX IF NOT EXISTS idx_validation_file_id ON format_validations(file_id);
CREATE INDEX IF NOT EXISTS idx_validation_format ON format_validations(detected_format);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


def find_schema_sql_path() -> Optional[Path]:
    """Locate the resecure_schema.sql file on disk."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "database" / "resecure_schema.sql",
        Path(__file__).resolve().parent.parent.parent.parent.parent / "database" / "resecure_schema.sql",
        Path(__file__).resolve().parent.parent.parent.parent.parent / "resecure" / "database" / "resecure_schema.sql",
        Path.cwd() / "resecure" / "database" / "resecure_schema.sql",
        Path.cwd() / "database" / "resecure_schema.sql",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def get_schema_sql() -> str:
    """Returns the SQL statements string, loading from file if present, else fallback."""
    path = find_schema_sql_path()
    if path and path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning("Could not read %s, using embedded schema: %s", path, e)
    return EMBEDDED_SCHEMA_SQL


def run_migrations(conn: sqlite3.Connection) -> None:
    """Runs incremental schema migrations safely."""
    cursor = conn.cursor()
    cursor.execute("SELECT version FROM schema_migrations")
    applied = {row[0] for row in cursor.fetchall()}

    if "v1.1.0_pdf_support" not in applied:
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='files'")
        files_row = cursor.fetchone()
        if files_row and "'PDF'" not in files_row[0]:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("""
            CREATE TABLE IF NOT EXISTS files_new (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL CHECK (file_size >= 0),
                root_sha256 TEXT NOT NULL CHECK (length(root_sha256) = 64),
                mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                file_path TEXT,
                file_format TEXT DEFAULT 'BINARY'
                    CHECK (file_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY')),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            """)
            conn.execute("INSERT INTO files_new SELECT * FROM files;")
            conn.execute("DROP TABLE files;")
            conn.execute("ALTER TABLE files_new RENAME TO files;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_files_root_sha256 ON files(root_sha256);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);")

            conn.execute("""
            CREATE TABLE IF NOT EXISTS format_validations_new (
                validation_id TEXT PRIMARY KEY,
                file_id TEXT REFERENCES files(file_id) ON DELETE SET NULL,
                filename TEXT NOT NULL,
                detected_format TEXT NOT NULL
                    CHECK (detected_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY', 'UNKNOWN')),
                is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),
                error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
                warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0),
                details_json TEXT NOT NULL DEFAULT '{}',
                format_verdict TEXT DEFAULT 'FORMAT_VALID'
                    CHECK (format_verdict IS NULL OR format_verdict IN ('FORMAT_VALID', 'FORMAT_INVALID', 'STRUCTURALLY_SALVAGED')),
                repair_log_json TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            """)
            conn.execute("INSERT INTO format_validations_new SELECT * FROM format_validations;")
            conn.execute("DROP TABLE format_validations;")
            conn.execute("ALTER TABLE format_validations_new RENAME TO format_validations;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_format_val_file_id ON format_validations(file_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_format_val_created_at ON format_validations(created_at);")
            conn.execute("PRAGMA foreign_keys=ON")

        conn.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES ('v1.1.0_pdf_support');")
        conn.commit()


def init_db(
    conn: Optional[sqlite3.Connection] = None,
    manager: Optional[DatabaseConnectionManager] = None,
) -> None:
    """
    Initializes the database by executing the idempotent schema DDL statements
    and records initial schema migration version.
    """
    sql = get_schema_sql()
    
    # Ensure schema_migrations table is part of the execution
    migration_table_ddl = """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    """

    if conn is not None:
        conn.executescript(sql)
        conn.executescript(migration_table_ddl)
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES ('v1.0.0_initial_schema');"
        )
        run_migrations(conn)
        conn.commit()
    else:
        mgr = manager or get_connection_manager()
        with mgr.connection() as c:
            c.executescript(sql)
            c.executescript(migration_table_ddl)
            c.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES ('v1.0.0_initial_schema');"
            )
            run_migrations(c)
            c.commit()


def verify_schema(conn: sqlite3.Connection) -> dict[str, Any]:
    """
    Verifies that all expected tables and indexes exist in the connected SQLite database.
    Returns a dictionary reporting existence status and any missing items.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = {row[0] for row in cursor.fetchall()}

    cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
    existing_indexes = {row[0] for row in cursor.fetchall()}
    cursor.close()

    missing_tables = [t for t in EXPECTED_TABLES if t not in existing_tables]
    missing_indexes = [idx for idx in EXPECTED_INDEXES if idx not in existing_indexes]

    is_valid = len(missing_tables) == 0 and len(missing_indexes) == 0
    return {
        "is_valid": is_valid,
        "existing_tables": sorted(list(existing_tables)),
        "missing_tables": missing_tables,
        "existing_indexes": sorted(list(existing_indexes)),
        "missing_indexes": missing_indexes,
    }


def reset_db(
    conn: Optional[sqlite3.Connection] = None,
    manager: Optional[DatabaseConnectionManager] = None,
) -> None:
    """
    Drops all ReSecure tables (for test isolation) and reapplies the schema.
    """
    drop_sql = """
    PRAGMA foreign_keys = OFF;
    DROP TABLE IF EXISTS corruption_events;
    DROP TABLE IF EXISTS format_validations;
    DROP TABLE IF EXISTS recovery_jobs;
    DROP TABLE IF EXISTS chunks;
    DROP TABLE IF EXISTS manifests;
    DROP TABLE IF EXISTS files;
    DROP TABLE IF EXISTS schema_migrations;
    PRAGMA foreign_keys = ON;
    """
    if conn is not None:
        conn.executescript(drop_sql)
        init_db(conn=conn)
    else:
        mgr = manager or get_connection_manager()
        with mgr.connection() as c:
            c.executescript(drop_sql)
            init_db(conn=c)
