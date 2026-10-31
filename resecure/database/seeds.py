"""
CalmStacks ReSecure Test Seed Fixtures
System: ReSecure (MVP v1.0)
Module: resecure.database.seeds

Provides deterministic, sanitized seed fixtures for development,
frontend mock preview, and automated test suites.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Ensure resecure package can be resolved when executed directly
pkg_root = Path(__file__).resolve().parent.parent.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from resecure.backend.src.db.connection import (
    DatabaseConnectionManager,
    get_connection_manager,
)
from resecure.backend.src.db.models import (
    ChunkModel,
    CorruptionEventModel,
    FileModel,
    FormatValidationModel,
    ManifestModel,
    RecoveryJobModel,
)
from resecure.backend.src.db.repository import ReSecureRepository
from resecure.backend.src.db.schema import init_db

# ----------------------------------------------------------------------------
# Deterministic UUID Fixture Constants
# ----------------------------------------------------------------------------
FILE_1_UUID = "11111111-1111-4111-8111-111111111111"
FILE_2_UUID = "22222222-2222-4222-8222-222222222222"
FILE_3_UUID = "33333333-3333-4333-8333-333333333333"
FILE_4_UUID = "44444444-4444-4444-8444-444444444444"

MANIFEST_1_UUID = "aaaaaaa1-1111-4aaa-8aaa-aaaaaaaaaaaa"
MANIFEST_2_UUID = "aaaaaaa2-2222-4aaa-8aaa-aaaaaaaaaaaa"

JOB_VERIFY_UUID = "bbbbbbb1-1111-4bbb-8bbb-bbbbbbbbbbbb"
JOB_RECOVER_UUID = "bbbbbbb2-2222-4bbb-8bbb-bbbbbbbbbbbb"
JOB_FAILED_UUID = "bbbbbbb3-3333-4bbb-8bbb-bbbbbbbbbbbb"

EVENT_1_UUID = "ccccccc1-1111-4ccc-8ccc-cccccccccccc"

VAL_1_UUID = "ddddddd1-1111-4ddd-8ddd-dddddddddddd"
VAL_2_UUID = "ddddddd2-2222-4ddd-8ddd-dddddddddddd"
VAL_3_UUID = "ddddddd3-3333-4ddd-8ddd-dddddddddddd"


def get_seed_files() -> List[FileModel]:
    """Generates deterministic sample file models."""
    return [
        FileModel(
            file_id=FILE_1_UUID,
            filename="financial_records_2026.csv",
            file_size=262144,  # 256 KB = 4 x 64KB chunks
            root_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            mime_type="text/csv",
            file_path="/data/financial_records_2026.csv",
            file_format="CSV",
            created_at="2026-10-22T10:00:00.000Z",
            updated_at="2026-10-22T10:00:00.000Z",
        ),
        FileModel(
            file_id=FILE_2_UUID,
            filename="core_kernel_config.json",
            file_size=65536,  # 64 KB = 1 chunk
            root_sha256="8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
            mime_type="application/json",
            file_path="/data/core_kernel_config.json",
            file_format="JSON",
            created_at="2026-10-22T11:00:00.000Z",
            updated_at="2026-10-22T11:00:00.000Z",
        ),
        FileModel(
            file_id=FILE_3_UUID,
            filename="satellite_telemetry.png",
            file_size=524288,  # 512 KB = 8 chunks
            root_sha256="ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            mime_type="image/png",
            file_path="/data/satellite_telemetry.png",
            file_format="PNG",
            created_at="2026-10-22T12:00:00.000Z",
            updated_at="2026-10-22T12:00:00.000Z",
        ),
        FileModel(
            file_id=FILE_4_UUID,
            filename="incident_investigation.txt",
            file_size=131072,  # 128 KB = 2 chunks
            root_sha256="3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
            mime_type="text/plain",
            file_path="/data/incident_investigation.txt",
            file_format="TEXT",
            created_at="2026-10-22T13:00:00.000Z",
            updated_at="2026-10-22T13:00:00.000Z",
        ),
    ]


def get_seed_manifests() -> List[ManifestModel]:
    """Generates deterministic sample manifest models."""
    manifest_1_dict = {
        "manifest_version": "1.0.0",
        "created_at": "2026-10-22T10:05:00.000Z",
        "metadata": {
            "original_filename": "financial_records_2026.csv",
            "file_size_bytes": 262144,
            "file_format": "CSV",
            "mime_type": "text/csv",
        },
        "erasure_coding": {
            "algorithm": "Reed-Solomon-GF256",
            "chunk_size_bytes": 65536,
            "data_chunks_k": 4,
            "parity_chunks_m": 1,
            "redundancy_percentage": 25,
            "parity_file_name": "financial_records_2026.csv.rsparity",
        },
        "integrity": {
            "root_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "authentication": {
            "key_id": "k-master-2026",
            "algorithm": "HMAC-SHA256",
            "hmac_signature": "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
        },
    }

    manifest_2_dict = {
        "manifest_version": "1.0.0",
        "created_at": "2026-10-22T12:05:00.000Z",
        "metadata": {
            "original_filename": "satellite_telemetry.png",
            "file_size_bytes": 524288,
            "file_format": "PNG",
            "mime_type": "image/png",
        },
        "erasure_coding": {
            "algorithm": "Reed-Solomon-GF256",
            "chunk_size_bytes": 65536,
            "data_chunks_k": 8,
            "parity_chunks_m": 2,
            "redundancy_percentage": 25,
            "parity_file_name": "satellite_telemetry.png.rsparity",
        },
        "integrity": {
            "root_sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        },
        "authentication": {
            "key_id": "k-master-2026",
            "algorithm": "HMAC-SHA256",
            "hmac_signature": "2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d19a0ed401160a6b82",
        },
    }

    return [
        ManifestModel(
            manifest_id=MANIFEST_1_UUID,
            file_id=FILE_1_UUID,
            total_chunks=4,
            chunk_size=65536,
            redundancy_percent=25,
            parity_chunks=1,
            hmac_signature="9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
            key_id="k-master-2026",
            raw_manifest_json=json.dumps(manifest_1_dict, separators=(",", ":")),
            parity_file_path="/data/financial_records_2026.csv.rsparity",
            created_at="2026-10-22T10:05:00.000Z",
        ),
        ManifestModel(
            manifest_id=MANIFEST_2_UUID,
            file_id=FILE_3_UUID,
            total_chunks=8,
            chunk_size=65536,
            redundancy_percent=25,
            parity_chunks=2,
            hmac_signature="2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d19a0ed401160a6b82",
            key_id="k-master-2026",
            raw_manifest_json=json.dumps(manifest_2_dict, separators=(",", ":")),
            parity_file_path="/data/satellite_telemetry.png.rsparity",
            created_at="2026-10-22T12:05:00.000Z",
        ),
    ]


def get_seed_chunks() -> List[ChunkModel]:
    """Generates deterministic sample chunk models including simulated corruption."""
    chunks: List[ChunkModel] = []

    # Manifest 1: 4 data chunks + 1 parity chunk
    # Data chunk 2 is simulated as CORRUPTED
    chunk_hashes_m1 = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
    ]

    for idx, expected_hash in enumerate(chunk_hashes_m1):
        is_corrupted = (idx == 2)
        chunks.append(
            ChunkModel(
                chunk_id=f"c1111111-1111-4000-8000-{idx:012d}",
                manifest_id=MANIFEST_1_UUID,
                chunk_index=idx,
                offset_bytes=idx * 65536,
                size_bytes=65536,
                chunk_sha256=expected_hash,
                is_parity=0,
                live_sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" if is_corrupted else expected_hash,
                status="CORRUPTED" if is_corrupted else "HEALTHY",
                last_verified_at="2026-10-22T10:10:00.000Z",
            )
        )

    # Parity chunk 0 for Manifest 1
    chunks.append(
        ChunkModel(
            chunk_id="c1111111-1111-4000-8000-000000000099",
            manifest_id=MANIFEST_1_UUID,
            chunk_index=0,
            offset_bytes=0,
            size_bytes=65536,
            chunk_sha256="5555555555555555555555555555555555555555555555555555555555555555",
            is_parity=1,
            live_sha256="5555555555555555555555555555555555555555555555555555555555555555",
            status="HEALTHY",
            last_verified_at="2026-10-22T10:10:00.000Z",
        )
    )

    # Manifest 2: 8 data chunks + 2 parity chunks (all healthy)
    for idx in range(8):
        h = f"{idx+1:x}" * 64
        chunks.append(
            ChunkModel(
                chunk_id=f"c2222222-2222-4000-8000-{idx:012d}",
                manifest_id=MANIFEST_2_UUID,
                chunk_index=idx,
                offset_bytes=idx * 65536,
                size_bytes=65536,
                chunk_sha256=h,
                is_parity=0,
                live_sha256=h,
                status="HEALTHY",
                last_verified_at="2026-10-22T12:10:00.000Z",
            )
        )

    for p_idx in range(2):
        ph = f"p{p_idx+1}" + "0" * 62
        chunks.append(
            ChunkModel(
                chunk_id=f"c2222222-2222-4000-8000-{90+p_idx:012d}",
                manifest_id=MANIFEST_2_UUID,
                chunk_index=p_idx,
                offset_bytes=p_idx * 65536,
                size_bytes=65536,
                chunk_sha256=ph,
                is_parity=1,
                live_sha256=ph,
                status="HEALTHY",
                last_verified_at="2026-10-22T12:10:00.000Z",
            )
        )

    return chunks


def get_seed_jobs() -> List[RecoveryJobModel]:
    """Generates sample recovery, verify, and fail-safe jobs."""
    return [
        # Job 1: VERIFY that discovered corruption
        RecoveryJobModel(
            job_id=JOB_VERIFY_UUID,
            file_id=FILE_1_UUID,
            manifest_id=MANIFEST_1_UUID,
            job_type="VERIFY",
            status="COMPLETED",
            corrupted_chunks_count=1,
            recovered_chunks_count=0,
            original_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            recovered_sha256=None,
            sha256_match=None,
            output_path=None,
            error_code=None,
            error_message=None,
            started_at="2026-10-22T10:10:00.000Z",
            completed_at="2026-10-22T10:10:00.088Z",
            duration_ms=88,
            progress_pct=100.0,
            source_path="/data/financial_records_2026.csv",
            parity_consumed=0,
            verdict="RECOVERABLE",
        ),
        # Job 2: RECOVER that reconstructed exact file
        RecoveryJobModel(
            job_id=JOB_RECOVER_UUID,
            file_id=FILE_1_UUID,
            manifest_id=MANIFEST_1_UUID,
            job_type="RECOVER",
            status="COMPLETED",
            corrupted_chunks_count=1,
            recovered_chunks_count=1,
            original_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            recovered_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha256_match=1,
            output_path="/data/recovered/financial_records_2026.csv",
            error_code=None,
            error_message=None,
            started_at="2026-10-22T10:15:00.000Z",
            completed_at="2026-10-22T10:15:00.142Z",
            duration_ms=142,
            progress_pct=100.0,
            source_path="/data/financial_records_2026.csv",
            parity_consumed=1,
            verdict="VERIFIED_EXACT",
        ),
        # Job 3: RECOVER that halted safely (exceeded parity threshold)
        RecoveryJobModel(
            job_id=JOB_FAILED_UUID,
            file_id=FILE_1_UUID,
            manifest_id=MANIFEST_1_UUID,
            job_type="RECOVER",
            status="FAILED",
            corrupted_chunks_count=3,
            recovered_chunks_count=0,
            original_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            recovered_sha256=None,
            sha256_match=0,
            output_path=None,
            error_code="ERR_EXCEEDS_REDUNDANCY",
            error_message="Damaged chunks (3) exceed available parity shards (1). Halting to prevent emitting corrupted file.",
            started_at="2026-10-22T10:20:00.000Z",
            completed_at="2026-10-22T10:20:00.045Z",
            duration_ms=45,
            progress_pct=35.0,
            source_path="/data/financial_records_2026.csv",
            parity_consumed=0,
            verdict="UNRECOVERABLE_EXACT",
        ),
    ]


def get_seed_corruption_events() -> List[CorruptionEventModel]:
    """Generates sample corruption events."""
    return [
        CorruptionEventModel(
            event_id=EVENT_1_UUID,
            job_id=JOB_VERIFY_UUID,
            chunk_index=2,
            offset_bytes=131072,
            expected_sha256="3333333333333333333333333333333333333333333333333333333333333333",
            actual_sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            corruption_type="MODIFIED",
            byte_length=64,
            detected_at="2026-10-22T10:10:00.040Z",
        )
    ]


def get_seed_validations() -> List[FormatValidationModel]:
    """Generates sample format validation findings."""
    return [
        FormatValidationModel(
            validation_id=VAL_1_UUID,
            file_id=FILE_2_UUID,
            filename="core_kernel_config.json",
            detected_format="JSON",
            is_valid=1,
            error_count=0,
            warning_count=0,
            details_json=json.dumps({"syntax": "RFC 8259", "brace_depth": 3, "key_count": 42}),
            format_verdict="FORMAT_VALID",
            repair_log_json=None,
            created_at="2026-10-22T11:05:00.000Z",
        ),
        FormatValidationModel(
            validation_id=VAL_2_UUID,
            file_id=None,
            filename="damaged_sensor_log.csv",
            detected_format="CSV",
            is_valid=0,
            error_count=2,
            warning_count=1,
            details_json=json.dumps({
                "syntax": "RFC 4180",
                "errors": [
                    "Row 14: Column count mismatch (expected 8, got 6)",
                    "Row 32: Unbalanced quotation mark",
                ],
                "warnings": ["Trailing CRLF missing at EOF"],
            }),
            format_verdict="FORMAT_INVALID",
            repair_log_json=None,
            created_at="2026-10-22T11:15:00.000Z",
        ),
        FormatValidationModel(
            validation_id=VAL_3_UUID,
            file_id=None,
            filename="salvaged_firmware_dump.txt",
            detected_format="TEXT",
            is_valid=1,
            error_count=0,
            warning_count=3,
            details_json=json.dumps({"encoding": "UTF-8", "stripped_nulls": 14, "replacement_chars": 2}),
            format_verdict="STRUCTURALLY_SALVAGED",
            repair_log_json=json.dumps([
                {"action": "STRIP_NULL", "byte_offset": 512, "description": "Stripped forbidden null byte sequence"},
                {"action": "UTF8_REPLACE", "byte_offset": 1024, "description": "Replaced illegal UTF-8 byte with U+FFFD"},
            ]),
            created_at="2026-10-22T11:30:00.000Z",
        ),
    ]


def seed_database(
    db: Optional[Union[sqlite3.Connection, DatabaseConnectionManager]] = None,
) -> Dict[str, int]:
    """
    Seeds the target database with deterministic fixture records.
    Idempotent: uses INSERT OR REPLACE to avoid duplicate key conflicts.
    Returns counts of inserted items.
    """
    if db is None:
        manager = get_connection_manager()
        init_db(manager=manager)
        repo = ReSecureRepository(manager)
    elif isinstance(db, sqlite3.Connection):
        init_db(conn=db)
        repo = ReSecureRepository(db)
    else:
        init_db(manager=db)
        repo = ReSecureRepository(db)

    counts = {
        "files": 0,
        "manifests": 0,
        "chunks": 0,
        "jobs": 0,
        "corruption_events": 0,
        "format_validations": 0,
    }

    # 1. Seed Files
    for f in get_seed_files():
        if repo.files.get_by_id(f.file_id) is None:
            repo.files.create(f)
            counts["files"] += 1

    # 2. Seed Manifests
    for m in get_seed_manifests():
        if repo.manifests.get_by_id(m.manifest_id) is None:
            repo.manifests.create(m)
            counts["manifests"] += 1

    # 3. Seed Chunks
    for c in get_seed_chunks():
        if repo.chunks.get_by_id(c.chunk_id) is None:
            repo.chunks.create(c)
            counts["chunks"] += 1

    # 4. Seed Jobs
    for j in get_seed_jobs():
        if repo.jobs.get_by_id(j.job_id) is None:
            repo.jobs.create(j)
            counts["jobs"] += 1

    # 5. Seed Corruption Events
    for e in get_seed_corruption_events():
        if repo.corruption_events.get_by_id(e.event_id) is None:
            repo.corruption_events.create(e)
            counts["corruption_events"] += 1

    # 6. Seed Format Validations
    for v in get_seed_validations():
        if repo.format_validations.get_by_id(v.validation_id) is None:
            repo.format_validations.create(v)
            counts["format_validations"] += 1

    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the ReSecure SQLite database with test fixtures.")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    args = parser.parse_args()

    mgr = get_connection_manager(db_path=args.db)
    result = seed_database(mgr)
    print("Database seeded successfully:")
    for k, v in result.items():
        print(f"  {k}: {v} records seeded")
