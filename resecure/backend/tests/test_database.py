"""
CalmStacks ReSecure Persistence Layer - Automated Unit Test Suite
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_database
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure package can be resolved
pkg_root = Path(__file__).resolve().parent.parent.parent.parent
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
from resecure.backend.src.db.schema import (
    EXPECTED_INDEXES,
    EXPECTED_TABLES,
    init_db,
    reset_db,
    verify_schema,
)
from resecure.database.seeds import seed_database


class TestDatabaseConnection(unittest.TestCase):
    """Tests for DatabaseConnectionManager, PRAGMAs, and transaction semantics."""

    def setUp(self) -> None:
        self.mgr = DatabaseConnectionManager(db_path=":memory:")

    def tearDown(self) -> None:
        self.mgr.close()

    def test_pragmas_configured_correctly(self) -> None:
        """Verifies foreign_keys=ON, busy_timeout=5000, and synchronous mode."""
        conn = self.mgr.create_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA foreign_keys;")
        fk_val = cursor.fetchone()[0]
        self.assertEqual(fk_val, 1, "foreign_keys PRAGMA must be ON (1)")

        cursor.execute("PRAGMA busy_timeout;")
        timeout_val = cursor.fetchone()[0]
        self.assertEqual(timeout_val, 5000, "busy_timeout must be 5000 ms")

        cursor.execute("PRAGMA synchronous;")
        sync_val = cursor.fetchone()[0]
        # In SQLite: 1 = NORMAL
        self.assertEqual(sync_val, 1, "synchronous PRAGMA must be NORMAL (1)")
        cursor.close()

    def test_disk_wal_mode(self) -> None:
        """Verifies WAL journal mode on disk-backed SQLite database."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            temp_db_path = tf.name

        try:
            disk_mgr = DatabaseConnectionManager(db_path=temp_db_path)
            conn = disk_mgr.create_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0].upper()
            cursor.close()
            conn.close()
            self.assertEqual(journal_mode, "WAL", "Disk databases must use WAL mode")
        finally:
            disk_mgr.close()
            for suffix in ["", "-wal", "-shm"]:
                p = Path(temp_db_path + suffix)
                if p.exists():
                    p.unlink()

    def test_transaction_commit(self) -> None:
        """Verifies that operations within transaction commit successfully."""
        init_db(manager=self.mgr)
        repo = ReSecureRepository(self.mgr)

        with self.mgr.transaction() as conn:
            repo_tx = ReSecureRepository(conn)
            f = FileModel(
                file_id="test-tx-commit-001",
                filename="test_tx.txt",
                file_size=1024,
                root_sha256="a" * 64,
            )
            repo_tx.files.create(f)

        found = repo.files.get_by_id("test-tx-commit-001")
        self.assertIsNotNone(found)
        self.assertEqual(found.filename, "test_tx.txt")

    def test_transaction_rollback(self) -> None:
        """Verifies that an exception inside transaction triggers a clean rollback."""
        init_db(manager=self.mgr)
        repo = ReSecureRepository(self.mgr)

        with self.assertRaises(RuntimeError):
            with self.mgr.transaction() as conn:
                repo_tx = ReSecureRepository(conn)
                f = FileModel(
                    file_id="test-tx-rollback-001",
                    filename="rollback.txt",
                    file_size=2048,
                    root_sha256="b" * 64,
                )
                repo_tx.files.create(f)
                raise RuntimeError("Forced simulation error")

        found = repo.files.get_by_id("test-tx-rollback-001")
        self.assertIsNone(found, "Record must be rolled back on exception")


class TestDatabaseSchema(unittest.TestCase):
    """Tests schema execution, idempotency, constraints, and cascade behaviors."""

    def setUp(self) -> None:
        self.mgr = DatabaseConnectionManager(db_path=":memory:")
        init_db(manager=self.mgr)

    def tearDown(self) -> None:
        self.mgr.close()

    def test_schema_verification(self) -> None:
        """Verifies all 6 tables and 6 indexes exist in SQLite catalog."""
        conn = self.mgr.create_connection()
        res = verify_schema(conn)
        self.assertTrue(res["is_valid"], f"Schema validation failed: {res}")
        self.assertEqual(len(res["missing_tables"]), 0)
        self.assertEqual(len(res["missing_indexes"]), 0)

        for table in EXPECTED_TABLES:
            self.assertIn(table, res["existing_tables"])
        for index in EXPECTED_INDEXES:
            self.assertIn(index, res["existing_indexes"])

    def test_schema_idempotency(self) -> None:
        """Verifies that running init_db repeatedly causes no errors or duplications."""
        init_db(manager=self.mgr)
        init_db(manager=self.mgr)
        conn = self.mgr.create_connection()
        res = verify_schema(conn)
        self.assertTrue(res["is_valid"])

    def test_foreign_key_cascade_manifests(self) -> None:
        """Deleting a file must cascade and delete its manifests and chunks."""
        repo = ReSecureRepository(self.mgr)
        file_id = "cascade-file-01"
        manifest_id = "cascade-manifest-01"
        chunk_id = "cascade-chunk-01"

        repo.files.create(
            FileModel(
                file_id=file_id,
                filename="cascade.bin",
                file_size=65536,
                root_sha256="c" * 64,
            )
        )
        repo.manifests.create(
            ManifestModel(
                manifest_id=manifest_id,
                file_id=file_id,
                total_chunks=1,
                chunk_size=65536,
                redundancy_percent=20,
                parity_chunks=1,
                hmac_signature="d" * 64,
                raw_manifest_json="{}",
            )
        )
        repo.chunks.create(
            ChunkModel(
                chunk_id=chunk_id,
                manifest_id=manifest_id,
                chunk_index=0,
                offset_bytes=0,
                size_bytes=65536,
                chunk_sha256="e" * 64,
            )
        )

        # Assert present
        self.assertIsNotNone(repo.files.get_by_id(file_id))
        self.assertIsNotNone(repo.manifests.get_by_id(manifest_id))
        self.assertIsNotNone(repo.chunks.get_by_id(chunk_id))

        # Delete file
        deleted = repo.files.delete(file_id)
        self.assertTrue(deleted)

        # Verify cascades
        self.assertIsNone(repo.files.get_by_id(file_id))
        self.assertIsNone(repo.manifests.get_by_id(manifest_id), "Manifest must cascade delete")
        self.assertIsNone(repo.chunks.get_by_id(chunk_id), "Chunk must cascade delete")

    def test_check_constraints_negative_file_size(self) -> None:
        """CHECK constraint: file_size >= 0."""
        repo = ReSecureRepository(self.mgr)
        with self.assertRaises(Exception):
            repo.files.create(
                FileModel(
                    file_id="bad-size-01",
                    filename="bad.bin",
                    file_size=-10,
                    root_sha256="f" * 64,
                )
            )

    def test_check_constraints_redundancy_percent(self) -> None:
        """CHECK constraint: 5 <= redundancy_percent <= 100."""
        repo = ReSecureRepository(self.mgr)
        file_id = "valid-file-red"
        repo.files.create(
            FileModel(
                file_id=file_id,
                filename="valid.bin",
                file_size=65536,
                root_sha256="1" * 64,
            )
        )

        with self.assertRaises(Exception):
            repo.manifests.create(
                ManifestModel(
                    manifest_id="bad-red-01",
                    file_id=file_id,
                    total_chunks=1,
                    chunk_size=65536,
                    redundancy_percent=4,  # Under 5% minimum
                    parity_chunks=1,
                    hmac_signature="2" * 64,
                    raw_manifest_json="{}",
                )
            )


class TestRepositories(unittest.TestCase):
    """Tests CRUD operations and business methods across all 6 repositories."""

    def setUp(self) -> None:
        self.mgr = DatabaseConnectionManager(db_path=":memory:")
        init_db(manager=self.mgr)
        self.repo = ReSecureRepository(self.mgr)

    def tearDown(self) -> None:
        self.mgr.close()

    def test_file_repository_crud(self) -> None:
        """Tests create, read, update, list, and delete on FileRepository."""
        f = FileModel(
            file_id="file-crud-001",
            filename="test_doc.pdf",
            file_size=1048576,
            root_sha256="1234567890abcdef" * 4,
            mime_type="application/pdf",
            file_format="BINARY",
        )
        created = self.repo.files.create(f)
        self.assertEqual(created.file_id, "file-crud-001")
        self.assertEqual(created.filename, "test_doc.pdf")
        self.assertEqual(created.file_size, 1048576)

        # get_by_id
        fetched = self.repo.files.get_by_id("file-crud-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.root_sha256, "1234567890abcdef" * 4)

        # get_by_root_sha256
        by_hash = self.repo.files.get_by_root_sha256("1234567890abcdef" * 4)
        self.assertEqual(len(by_hash), 1)

        # update
        f_updated = FileModel(
            file_id="file-crud-001",
            filename="renamed_doc.pdf",
            file_size=1048576,
            root_sha256="1234567890abcdef" * 4,
            mime_type="application/pdf",
        )
        res_update = self.repo.files.update(f_updated)
        self.assertEqual(res_update.filename, "renamed_doc.pdf")

        # list_all
        all_files = self.repo.files.list_all(limit=10)
        self.assertGreaterEqual(len(all_files), 1)

        # delete
        del_res = self.repo.files.delete("file-crud-001")
        self.assertTrue(del_res)
        self.assertIsNone(self.repo.files.get_by_id("file-crud-001"))

    def test_chunk_batch_and_status_audit(self) -> None:
        """Tests batch chunk creation, status updates, and status counts."""
        f_id = "f-chunk-batch"
        m_id = "m-chunk-batch"
        self.repo.files.create(
            FileModel(file_id=f_id, filename="batch.dat", file_size=196608, root_sha256="a" * 64)
        )
        self.repo.manifests.create(
            ManifestModel(
                manifest_id=m_id,
                file_id=f_id,
                total_chunks=3,
                chunk_size=65536,
                redundancy_percent=20,
                parity_chunks=1,
                hmac_signature="b" * 64,
                raw_manifest_json="{}",
            )
        )

        chunks = [
            ChunkModel(
                chunk_id=f"chk-{i}",
                manifest_id=m_id,
                chunk_index=i,
                offset_bytes=i * 65536,
                size_bytes=65536,
                chunk_sha256=f"{i}" * 64,
                is_parity=0,
            )
            for i in range(3)
        ]
        inserted_count = self.repo.chunks.create_batch(chunks)
        self.assertEqual(inserted_count, 3)

        # Verify listing
        listed = self.repo.chunks.list_by_manifest_id(m_id)
        self.assertEqual(len(listed), 3)

        # Update status
        self.repo.chunks.update_status("chk-1", "CORRUPTED", live_sha256="badhash" * 8)
        chk1 = self.repo.chunks.get_by_id("chk-1")
        self.assertIsNotNone(chk1)
        self.assertEqual(chk1.status, "CORRUPTED")
        self.assertEqual(chk1.live_sha256, "badhash" * 8)

        # Count by status
        counts = self.repo.chunks.count_by_status(m_id)
        self.assertEqual(counts.get("HEALTHY"), 2)
        self.assertEqual(counts.get("CORRUPTED"), 1)

    def test_recovery_job_state_machine(self) -> None:
        """Tests job creation, progression, status updates, completion metrics, and events."""
        job = RecoveryJobModel(
            job_id="job-lifecycle-001",
            job_type="VERIFY",
            status="PENDING",
            source_path="/data/test.bin",
        )
        self.repo.jobs.create(job)

        # Update status to RUNNING
        self.repo.jobs.update_status("job-lifecycle-001", "RUNNING", progress_pct=50.0)
        j1 = self.repo.jobs.get_by_id("job-lifecycle-001")
        self.assertIsNotNone(j1)
        self.assertEqual(j1.status, "RUNNING")
        self.assertEqual(j1.progress_pct, 50.0)

        # Record corruption event
        event = CorruptionEventModel(
            event_id="evt-001",
            job_id="job-lifecycle-001",
            chunk_index=2,
            offset_bytes=131072,
            expected_sha256="1" * 64,
            actual_sha256="2" * 64,
            corruption_type="MODIFIED",
            byte_length=128,
        )
        self.repo.corruption_events.create(event)

        events = self.repo.corruption_events.list_by_job_id("job-lifecycle-001")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].corruption_type, "MODIFIED")

        # Complete job
        self.repo.jobs.complete_job(
            job_id="job-lifecycle-001",
            recovered_chunks=1,
            recovered_sha256="1" * 64,
            sha256_match=1,
            duration_ms=250,
            verdict="VERIFIED_EXACT",
            output_path="/data/recovered/test.bin",
        )
        j_done = self.repo.jobs.get_by_id("job-lifecycle-001")
        self.assertIsNotNone(j_done)
        self.assertEqual(j_done.status, "COMPLETED")
        self.assertEqual(j_done.progress_pct, 100.0)
        self.assertEqual(j_done.verdict, "VERIFIED_EXACT")
        self.assertEqual(j_done.duration_ms, 250)

    def test_format_validation_repository(self) -> None:
        """Tests recording and querying format validation findings."""
        val = FormatValidationModel(
            validation_id="val-repo-001",
            filename="data.json",
            detected_format="JSON",
            is_valid=1,
            error_count=0,
            warning_count=0,
            details_json='{"keys": 10}',
            format_verdict="FORMAT_VALID",
        )
        self.repo.format_validations.create(val)

        fetched = self.repo.format_validations.get_by_id("val-repo-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.detected_format, "JSON")
        self.assertEqual(fetched.is_valid, 1)

        by_fn = self.repo.format_validations.list_by_filename("data.json")
        self.assertEqual(len(by_fn), 1)


class TestSeeds(unittest.TestCase):
    """Tests the deterministic test seed fixtures."""

    def setUp(self) -> None:
        self.mgr = DatabaseConnectionManager(db_path=":memory:")
        init_db(manager=self.mgr)

    def tearDown(self) -> None:
        self.mgr.close()

    def test_seed_database_execution_and_idempotency(self) -> None:
        """Verifies deterministic fixtures populate all tables and second run adds 0 records."""
        first_counts = seed_database(self.mgr)
        self.assertEqual(first_counts["files"], 4)
        self.assertEqual(first_counts["manifests"], 2)
        self.assertEqual(first_counts["chunks"], 15)
        self.assertEqual(first_counts["jobs"], 3)
        self.assertEqual(first_counts["corruption_events"], 1)
        self.assertEqual(first_counts["format_validations"], 3)

        # Idempotent second execution
        second_counts = seed_database(self.mgr)
        self.assertEqual(second_counts["files"], 0)
        self.assertEqual(second_counts["manifests"], 0)
        self.assertEqual(second_counts["chunks"], 0)
        self.assertEqual(second_counts["jobs"], 0)
        self.assertEqual(second_counts["corruption_events"], 0)
        self.assertEqual(second_counts["format_validations"], 0)

        # Verify cross-table referential integrity
        repo = ReSecureRepository(self.mgr)
        files = repo.files.list_all()
        self.assertEqual(len(files), 4)

        # Financial records file has manifest with corrupted chunk
        f1_manifests = repo.manifests.get_by_file_id("11111111-1111-4111-8111-111111111111")
        self.assertEqual(len(f1_manifests), 1)
        m1 = f1_manifests[0]

        counts = repo.chunks.count_by_status(m1.manifest_id)
        self.assertEqual(counts.get("CORRUPTED"), 1)
        self.assertEqual(counts.get("HEALTHY"), 3)

        # Jobs verify
        f1_jobs = repo.jobs.list_by_file_id("11111111-1111-4111-8111-111111111111")
        self.assertEqual(len(f1_jobs), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
