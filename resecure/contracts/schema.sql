-- ============================================================================
-- CalmStacks Machine-Readable Relational Database Schema Contract
-- System: ReSecure (MVP v1.0)
-- File: resecure/contracts/schema.sql
-- Engine: SQLite 3.35+ (Local-Only, Portable Relational DDL)
-- Description: Core persistence schema for file metadata, authenticated manifests,
--              chunk health records, recovery jobs, corruption events, and format validations.
-- Idempotency: All DDL statements use IF NOT EXISTS
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

-- ----------------------------------------------------------------------------
-- 1. Files Table
-- Tracks protected and audited files with root cryptographic hashes
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,                                      -- UUID identifier
    filename TEXT NOT NULL,                                       -- Base file name
    file_size INTEGER NOT NULL CHECK (file_size >= 0),            -- Exact byte length
    root_sha256 TEXT NOT NULL,                                    -- Pristine 64-character lowercase SHA-256 hash
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',   -- MIME classification
    file_path TEXT,                                               -- Canonical file path
    file_format TEXT DEFAULT 'BINARY'                             -- Format: TEXT, CSV, JSON, PNG, JPEG, BINARY
        CHECK (file_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_files_root_sha256 ON files(root_sha256);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);

-- Trigger to update updated_at on files modifications
CREATE TRIGGER IF NOT EXISTS trg_files_updated_at
AFTER UPDATE ON files
FOR EACH ROW
WHEN (NEW.updated_at = OLD.updated_at)
BEGIN
    UPDATE files SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE file_id = OLD.file_id;
END;

-- ----------------------------------------------------------------------------
-- 2. Manifests Table
-- Stores metadata and HMAC authentication signatures for Reed-Solomon parity
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS manifests (
    manifest_id TEXT PRIMARY KEY,                                  -- UUID identifier
    file_id TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    total_chunks INTEGER NOT NULL CHECK (total_chunks > 0),        -- Count of original data chunks (K)
    chunk_size INTEGER NOT NULL CHECK (chunk_size > 0),            -- Fixed chunk size in bytes (e.g. 65536)
    redundancy_percent INTEGER NOT NULL                            -- Configured redundancy (5% to 100%)
        CHECK (redundancy_percent >= 5 AND redundancy_percent <= 100),
    parity_chunks INTEGER NOT NULL CHECK (parity_chunks >= 0),    -- Count of parity chunks (M)
    hmac_signature TEXT NOT NULL,                                 -- 64-char lowercase HMAC-SHA256 signature
    key_id TEXT,                                                  -- Optional identifier of HMAC secret key
    raw_manifest_json TEXT NOT NULL,                              -- Complete canonical JSON manifest payload
    parity_file_path TEXT,                                        -- Path to .rsparity file
    manifest_version TEXT NOT NULL DEFAULT '1.0.0',               -- Semantic schema version
    algorithm TEXT NOT NULL DEFAULT 'Reed-Solomon-GF256',         -- FEC algorithm
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_manifests_file_id ON manifests(file_id);

-- ----------------------------------------------------------------------------
-- 3. Chunks Table
-- Granular chunk catalog, byte offsets, and integrity state
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,                                     -- UUID identifier
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),         -- 0-based chunk sequence index
    offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),       -- Byte offset in original file
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),            -- Actual byte count in chunk
    chunk_sha256 TEXT NOT NULL,                                    -- Pristine chunk SHA-256 hash
    is_parity INTEGER NOT NULL DEFAULT 0 CHECK (is_parity IN (0, 1)), -- 0 for data chunk, 1 for parity chunk
    live_sha256 TEXT,                                              -- Live computed SHA-256 during audit
    status TEXT NOT NULL DEFAULT 'HEALTHY'                         -- HEALTHY, CORRUPTED, MISSING, OVERSIZED
        CHECK (status IN ('HEALTHY', 'CORRUPTED', 'MISSING', 'OVERSIZED')),
    last_verified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (manifest_id, chunk_index, is_parity)
);

CREATE INDEX IF NOT EXISTS idx_chunks_manifest_index ON chunks(manifest_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_chunks_status ON chunks(status);

-- ----------------------------------------------------------------------------
-- 4. Recovery Jobs Table
-- State machine for verification, recovery, repair, and protection jobs
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recovery_jobs (
    job_id TEXT PRIMARY KEY,                                       -- UUID identifier
    file_id TEXT REFERENCES files(file_id) ON DELETE SET NULL,
    manifest_id TEXT REFERENCES manifests(manifest_id) ON DELETE SET NULL,
    job_type TEXT NOT NULL                                         -- Job operation type
        CHECK (job_type IN ('VERIFY', 'RECOVER', 'REPAIR', 'PROTECT', 'VALIDATE')),
    status TEXT NOT NULL DEFAULT 'PENDING'                         -- Execution lifecycle status
        CHECK (status IN ('PENDING', 'RUNNING', 'PROCESSING', 'COMPLETED', 'FAILED', 'UNRECOVERABLE')),
    corrupted_chunks_count INTEGER NOT NULL DEFAULT 0 CHECK (corrupted_chunks_count >= 0),
    recovered_chunks_count INTEGER NOT NULL DEFAULT 0 CHECK (recovered_chunks_count >= 0),
    original_sha256 TEXT,                                          -- Original root SHA-256 from manifest
    recovered_sha256 TEXT,                                         -- Recovered file root SHA-256
    sha256_match INTEGER CHECK (sha256_match IN (0, 1) OR sha256_match IS NULL), -- 1 if matched, 0 if mismatch
    output_path TEXT,                                              -- Path to recovered / output file
    error_code TEXT,                                               -- Structured error code (e.g. ERR_EXCEEDS_REDUNDANCY)
    error_message TEXT,                                            -- Diagnostic error message
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT,                                             -- Timestamp of completion
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0), -- Total execution time in ms
    progress_pct REAL NOT NULL DEFAULT 0.0 CHECK (progress_pct >= 0.0 AND progress_pct <= 100.0),
    source_path TEXT,                                              -- Target source file path
    parity_consumed INTEGER NOT NULL DEFAULT 0 CHECK (parity_consumed >= 0), -- Parity chunks consumed
    verdict TEXT                                                   -- High-level operational verdict
        CHECK (verdict IS NULL OR verdict IN ('PRISTINE', 'RECOVERABLE', 'VERIFIED_EXACT', 'UNRECOVERABLE_EXACT', 'STRUCTURALLY_SALVAGED', 'INTEGRITY_VIOLATION'))
);

CREATE INDEX IF NOT EXISTS idx_jobs_file_status ON recovery_jobs(file_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON recovery_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_started_at ON recovery_jobs(started_at);

-- ----------------------------------------------------------------------------
-- 5. Corruption Events Table
-- Detailed forensic audit ledger of every detected chunk corruption or loss
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS corruption_events (
    event_id TEXT PRIMARY KEY,                                     -- UUID identifier
    job_id TEXT NOT NULL REFERENCES recovery_jobs(job_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),         -- Affected chunk index
    offset_bytes INTEGER NOT NULL CHECK (offset_bytes >= 0),       -- Starting byte offset of corruption
    expected_sha256 TEXT NOT NULL,                                 -- Expected chunk SHA-256 from manifest
    actual_sha256 TEXT,                                            -- Actual live SHA-256 (or NULL if missing)
    corruption_type TEXT NOT NULL                                  -- Nature of detected corruption
        CHECK (corruption_type IN ('MODIFIED', 'MISSING', 'TRUNCATED', 'BIT_FLIP', 'ZERO_FILL', 'HEADER_WIPE', 'INJECTION')),
    byte_length INTEGER DEFAULT NULL,                              -- Length of corrupted region if known
    detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_corruption_job_id ON corruption_events(job_id);
CREATE INDEX IF NOT EXISTS idx_corruption_type ON corruption_events(corruption_type);

-- ----------------------------------------------------------------------------
-- 6. Format Validations Table
-- Deep syntactic and heuristic structural repair findings for supported formats
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS format_validations (
    validation_id TEXT PRIMARY KEY,                                -- UUID identifier
    file_id TEXT REFERENCES files(file_id) ON DELETE SET NULL,      -- Associated file (nullable)
    filename TEXT NOT NULL,                                        -- Target file name
    detected_format TEXT NOT NULL                                  -- Detected file format
        CHECK (detected_format IN ('TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', 'BINARY', 'UNKNOWN')),
    is_valid INTEGER NOT NULL CHECK (is_valid IN (0, 1)),          -- 1 if valid, 0 if invalid
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),   -- Number of syntax/format errors
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0), -- Number of warnings/anomalies
    details_json TEXT NOT NULL DEFAULT '{}',                       -- Serialized JSON containing findings & metrics
    format_verdict TEXT DEFAULT 'FORMAT_VALID'                     -- High level verdict
        CHECK (format_verdict IS NULL OR format_verdict IN ('FORMAT_VALID', 'FORMAT_INVALID', 'STRUCTURALLY_SALVAGED')),
    repair_log_json TEXT,                                          -- Heuristic repair log JSON if repaired
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_validation_filename ON format_validations(filename);
CREATE INDEX IF NOT EXISTS idx_validation_file_id ON format_validations(file_id);
CREATE INDEX IF NOT EXISTS idx_validation_format ON format_validations(detected_format);
