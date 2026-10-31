"""
CalmStacks ReSecure Persistence Layer - Type-Safe Repositories
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.db.repository
"""

from __future__ import annotations

import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .connection import DatabaseConnectionManager, get_connection_manager
from .models import (
    ChunkModel,
    CorruptionEventModel,
    FileModel,
    FormatValidationModel,
    ManifestModel,
    RecoveryJobModel,
)


class BaseRepository:
    """Base class for repositories providing connection and transaction management."""

    def __init__(
        self,
        db: Optional[Union[sqlite3.Connection, DatabaseConnectionManager]] = None,
    ) -> None:
        if db is None:
            self._manager: Optional[DatabaseConnectionManager] = get_connection_manager()
            self._conn: Optional[sqlite3.Connection] = None
        elif isinstance(db, sqlite3.Connection):
            self._manager = None
            self._conn = db
        else:
            self._manager = db
            self._conn = None

    def _execute(
        self,
        callback: Callable[[sqlite3.Connection], Any],
        is_write: bool = False,
    ) -> Any:
        """
        Executes a database callback using the provided connection or context manager.
        If an external connection is used (e.g. inside a transaction), the caller controls commits/rollbacks.
        If a connection manager is used, automatically commits write operations upon completion.
        """
        if self._conn is not None:
            return callback(self._conn)
        assert self._manager is not None
        with self._manager.connection() as conn:
            result = callback(conn)
            if is_write:
                conn.commit()
            return result


class FileRepository(BaseRepository):
    """Repository handling persistence and querying for FileModel records."""

    def create(self, file: FileModel) -> FileModel:
        """Inserts a new file record."""
        def _op(conn: sqlite3.Connection) -> FileModel:
            sql = """
            INSERT INTO files (
                file_id, filename, file_size, root_sha256, mime_type,
                file_path, file_format, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    file.file_id,
                    file.filename,
                    file.file_size,
                    file.root_sha256,
                    file.mime_type,
                    file.file_path,
                    file.file_format,
                    file.created_at,
                    file.updated_at,
                ),
            )
            cursor.execute("SELECT * FROM files WHERE file_id = ?;", (file.file_id,))
            row = cursor.fetchone()
            cursor.close()
            return FileModel.from_row(row) if row else file

        return self._execute(_op, is_write=True)

    def get_by_id(self, file_id: str) -> Optional[FileModel]:
        """Finds a file record by file_id."""
        def _op(conn: sqlite3.Connection) -> Optional[FileModel]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE file_id = ?;", (file_id,))
            row = cursor.fetchone()
            cursor.close()
            return FileModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def get_by_root_sha256(self, root_sha256: str) -> List[FileModel]:
        """Finds all file records matching a root SHA-256 hash."""
        def _op(conn: sqlite3.Connection) -> List[FileModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM files WHERE root_sha256 = ? ORDER BY created_at DESC;",
                (root_sha256,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [FileModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def list_all(self, limit: int = 100, offset: int = 0) -> List[FileModel]:
        """Lists files with pagination."""
        def _op(conn: sqlite3.Connection) -> List[FileModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM files ORDER BY created_at DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [FileModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def update(self, file: FileModel) -> FileModel:
        """Updates an existing file record."""
        def _op(conn: sqlite3.Connection) -> FileModel:
            sql = """
            UPDATE files SET
                filename = ?,
                file_size = ?,
                root_sha256 = ?,
                mime_type = ?,
                file_path = ?,
                file_format = ?,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE file_id = ?;
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    file.filename,
                    file.file_size,
                    file.root_sha256,
                    file.mime_type,
                    file.file_path,
                    file.file_format,
                    file.file_id,
                ),
            )
            cursor.execute("SELECT * FROM files WHERE file_id = ?;", (file.file_id,))
            row = cursor.fetchone()
            cursor.close()
            return FileModel.from_row(row) if row else file

        return self._execute(_op, is_write=True)

    def delete(self, file_id: str) -> bool:
        """Deletes a file record (cascading manifests and child records)."""
        def _op(conn: sqlite3.Connection) -> bool:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE file_id = ?;", (file_id,))
            deleted = cursor.rowcount > 0
            cursor.close()
            return deleted

        return self._execute(_op, is_write=True)


class ManifestRepository(BaseRepository):
    """Repository handling persistence and querying for ManifestModel records."""

    def create(self, manifest: ManifestModel) -> ManifestModel:
        """Inserts a new manifest record."""
        def _op(conn: sqlite3.Connection) -> ManifestModel:
            sql = """
            INSERT INTO manifests (
                manifest_id, file_id, total_chunks, chunk_size, redundancy_percent,
                parity_chunks, hmac_signature, key_id, raw_manifest_json,
                parity_file_path, manifest_version, algorithm, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    manifest.manifest_id,
                    manifest.file_id,
                    manifest.total_chunks,
                    manifest.chunk_size,
                    manifest.redundancy_percent,
                    manifest.parity_chunks,
                    manifest.hmac_signature,
                    manifest.key_id,
                    manifest.raw_manifest_json,
                    manifest.parity_file_path,
                    manifest.manifest_version,
                    manifest.algorithm,
                    manifest.created_at,
                ),
            )
            cursor.execute("SELECT * FROM manifests WHERE manifest_id = ?;", (manifest.manifest_id,))
            row = cursor.fetchone()
            cursor.close()
            return ManifestModel.from_row(row) if row else manifest

        return self._execute(_op, is_write=True)

    def get_by_id(self, manifest_id: str) -> Optional[ManifestModel]:
        """Finds a manifest record by manifest_id."""
        def _op(conn: sqlite3.Connection) -> Optional[ManifestModel]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM manifests WHERE manifest_id = ?;", (manifest_id,))
            row = cursor.fetchone()
            cursor.close()
            return ManifestModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def get_by_file_id(self, file_id: str) -> List[ManifestModel]:
        """Lists all manifests associated with a file_id."""
        def _op(conn: sqlite3.Connection) -> List[ManifestModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM manifests WHERE file_id = ? ORDER BY created_at DESC;",
                (file_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [ManifestModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def get_latest_by_file_id(self, file_id: str) -> Optional[ManifestModel]:
        """Retrieves the most recent manifest for a given file_id."""
        def _op(conn: sqlite3.Connection) -> Optional[ManifestModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM manifests WHERE file_id = ? ORDER BY created_at DESC LIMIT 1;",
                (file_id,),
            )
            row = cursor.fetchone()
            cursor.close()
            return ManifestModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def delete(self, manifest_id: str) -> bool:
        """Deletes a manifest record (cascading chunk records)."""
        def _op(conn: sqlite3.Connection) -> bool:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM manifests WHERE manifest_id = ?;", (manifest_id,))
            deleted = cursor.rowcount > 0
            cursor.close()
            return deleted

        return self._execute(_op, is_write=True)


class ChunkRepository(BaseRepository):
    """Repository handling persistence and live status auditing for ChunkModel records."""

    def create(self, chunk: ChunkModel) -> ChunkModel:
        """Inserts a single chunk record."""
        def _op(conn: sqlite3.Connection) -> ChunkModel:
            sql = """
            INSERT INTO chunks (
                chunk_id, manifest_id, chunk_index, offset_bytes, size_bytes,
                chunk_sha256, is_parity, live_sha256, status, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    chunk.chunk_id,
                    chunk.manifest_id,
                    chunk.chunk_index,
                    chunk.offset_bytes,
                    chunk.size_bytes,
                    chunk.chunk_sha256,
                    chunk.is_parity,
                    chunk.live_sha256,
                    chunk.status,
                    chunk.last_verified_at,
                ),
            )
            cursor.execute("SELECT * FROM chunks WHERE chunk_id = ?;", (chunk.chunk_id,))
            row = cursor.fetchone()
            cursor.close()
            return ChunkModel.from_row(row) if row else chunk

        return self._execute(_op, is_write=True)

    def create_batch(self, chunks: List[ChunkModel]) -> int:
        """Inserts a batch of chunk records."""
        def _op(conn: sqlite3.Connection) -> int:
            sql = """
            INSERT INTO chunks (
                chunk_id, manifest_id, chunk_index, offset_bytes, size_bytes,
                chunk_sha256, is_parity, live_sha256, status, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.executemany(
                sql,
                [
                    (
                        c.chunk_id,
                        c.manifest_id,
                        c.chunk_index,
                        c.offset_bytes,
                        c.size_bytes,
                        c.chunk_sha256,
                        c.is_parity,
                        c.live_sha256,
                        c.status,
                        c.last_verified_at,
                    )
                    for c in chunks
                ],
            )
            count = cursor.rowcount
            cursor.close()
            return count

        return self._execute(_op, is_write=True)

    def get_by_id(self, chunk_id: str) -> Optional[ChunkModel]:
        """Finds a chunk record by chunk_id."""
        def _op(conn: sqlite3.Connection) -> Optional[ChunkModel]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chunks WHERE chunk_id = ?;", (chunk_id,))
            row = cursor.fetchone()
            cursor.close()
            return ChunkModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def list_by_manifest_id(
        self,
        manifest_id: str,
        is_parity: Optional[int] = None,
    ) -> List[ChunkModel]:
        """Lists chunks for a manifest, optionally filtered by is_parity."""
        def _op(conn: sqlite3.Connection) -> List[ChunkModel]:
            cursor = conn.cursor()
            if is_parity is None:
                cursor.execute(
                    "SELECT * FROM chunks WHERE manifest_id = ? ORDER BY is_parity ASC, chunk_index ASC;",
                    (manifest_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM chunks WHERE manifest_id = ? AND is_parity = ? ORDER BY chunk_index ASC;",
                    (manifest_id, is_parity),
                )
            rows = cursor.fetchall()
            cursor.close()
            return [ChunkModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def update_status(
        self,
        chunk_id: str,
        status: str,
        live_sha256: Optional[str] = None,
    ) -> bool:
        """Updates health status and live SHA-256 for a chunk."""
        def _op(conn: sqlite3.Connection) -> bool:
            sql = """
            UPDATE chunks SET
                status = ?,
                live_sha256 = ?,
                last_verified_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE chunk_id = ?;
            """
            cursor = conn.cursor()
            cursor.execute(sql, (status, live_sha256, chunk_id))
            updated = cursor.rowcount > 0
            cursor.close()
            return updated

        return self._execute(_op, is_write=True)

    def update_batch_status(
        self,
        updates: List[Tuple[str, str, Optional[str]]],
    ) -> int:
        """Updates status and live SHA-256 for multiple chunks."""
        def _op(conn: sqlite3.Connection) -> int:
            sql = """
            UPDATE chunks SET
                status = ?,
                live_sha256 = ?,
                last_verified_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE chunk_id = ?;
            """
            cursor = conn.cursor()
            cursor.executemany(
                sql,
                [(status, live_sha, chunk_id) for chunk_id, status, live_sha in updates],
            )
            count = cursor.rowcount
            cursor.close()
            return count

        return self._execute(_op, is_write=True)

    def count_by_status(self, manifest_id: str) -> Dict[str, int]:
        """Returns health status counts for all data chunks of a manifest."""
        def _op(conn: sqlite3.Connection) -> Dict[str, int]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status, COUNT(*) FROM chunks WHERE manifest_id = ? AND is_parity = 0 GROUP BY status;",
                (manifest_id,),
            )
            counts = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.close()
            return counts

        return self._execute(_op, is_write=False)


class RecoveryJobRepository(BaseRepository):
    """Repository handling execution state machine records for RecoveryJobModel."""

    def create(self, job: RecoveryJobModel) -> RecoveryJobModel:
        """Inserts a new recovery job."""
        def _op(conn: sqlite3.Connection) -> RecoveryJobModel:
            sql = """
            INSERT INTO recovery_jobs (
                job_id, file_id, manifest_id, job_type, status,
                corrupted_chunks_count, recovered_chunks_count, original_sha256,
                recovered_sha256, sha256_match, output_path, error_code,
                error_message, started_at, completed_at, duration_ms,
                progress_pct, source_path, parity_consumed, verdict
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), ?, ?, ?, ?, ?, ?);
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    job.job_id,
                    job.file_id,
                    job.manifest_id,
                    job.job_type,
                    job.status,
                    job.corrupted_chunks_count,
                    job.recovered_chunks_count,
                    job.original_sha256,
                    job.recovered_sha256,
                    job.sha256_match,
                    job.output_path,
                    job.error_code,
                    job.error_message,
                    job.started_at,
                    job.completed_at,
                    job.duration_ms,
                    job.progress_pct,
                    job.source_path,
                    job.parity_consumed,
                    job.verdict,
                ),
            )
            cursor.execute("SELECT * FROM recovery_jobs WHERE job_id = ?;", (job.job_id,))
            row = cursor.fetchone()
            cursor.close()
            return RecoveryJobModel.from_row(row) if row else job

        return self._execute(_op, is_write=True)

    def get_by_id(self, job_id: str) -> Optional[RecoveryJobModel]:
        """Finds a recovery job by job_id."""
        def _op(conn: sqlite3.Connection) -> Optional[RecoveryJobModel]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM recovery_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            cursor.close()
            return RecoveryJobModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def list_by_file_id(
        self,
        file_id: str,
        status: Optional[str] = None,
    ) -> List[RecoveryJobModel]:
        """Lists all jobs for a specific file, optionally filtered by status."""
        def _op(conn: sqlite3.Connection) -> List[RecoveryJobModel]:
            cursor = conn.cursor()
            if status is None:
                cursor.execute(
                    "SELECT * FROM recovery_jobs WHERE file_id = ? ORDER BY started_at DESC;",
                    (file_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM recovery_jobs WHERE file_id = ? AND status = ? ORDER BY started_at DESC;",
                    (file_id, status),
                )
            rows = cursor.fetchall()
            cursor.close()
            return [RecoveryJobModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def list_recent(
        self,
        limit: int = 50,
        job_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[RecoveryJobModel]:
        """Lists recent jobs with optional filtering."""
        def _op(conn: sqlite3.Connection) -> List[RecoveryJobModel]:
            cursor = conn.cursor()
            query = "SELECT * FROM recovery_jobs WHERE 1=1"
            params: List[Any] = []
            if job_type:
                query += " AND job_type = ?"
                params.append(job_type)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY started_at DESC LIMIT ?;"
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            cursor.close()
            return [RecoveryJobModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def update_status(
        self,
        job_id: str,
        status: str,
        progress_pct: Optional[float] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """Updates job progress and status."""
        def _op(conn: sqlite3.Connection) -> bool:
            sql = """
            UPDATE recovery_jobs SET
                status = ?,
                progress_pct = COALESCE(?, progress_pct),
                error_code = COALESCE(?, error_code),
                error_message = COALESCE(?, error_message)
            WHERE job_id = ?;
            """
            cursor = conn.cursor()
            cursor.execute(sql, (status, progress_pct, error_code, error_message, job_id))
            updated = cursor.rowcount > 0
            cursor.close()
            return updated

        return self._execute(_op, is_write=True)

    def complete_job(
        self,
        job_id: str,
        recovered_chunks: int,
        recovered_sha256: Optional[str],
        sha256_match: Optional[int],
        duration_ms: int,
        verdict: Optional[str] = None,
        output_path: Optional[str] = None,
        status: str = "COMPLETED",
    ) -> bool:
        """Marks a job as completed with final verification and recovery metrics."""
        def _op(conn: sqlite3.Connection) -> bool:
            sql = """
            UPDATE recovery_jobs SET
                status = ?,
                progress_pct = 100.0,
                recovered_chunks_count = ?,
                recovered_sha256 = ?,
                sha256_match = ?,
                duration_ms = ?,
                verdict = ?,
                output_path = COALESCE(?, output_path),
                completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE job_id = ?;
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    status,
                    recovered_chunks,
                    recovered_sha256,
                    sha256_match,
                    duration_ms,
                    verdict,
                    output_path,
                    job_id,
                ),
            )
            updated = cursor.rowcount > 0
            cursor.close()
            return updated

        return self._execute(_op, is_write=True)

    def delete(self, job_id: str) -> bool:
        """Deletes a job (cascading corruption events)."""
        def _op(conn: sqlite3.Connection) -> bool:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM recovery_jobs WHERE job_id = ?;", (job_id,))
            deleted = cursor.rowcount > 0
            cursor.close()
            return deleted

        return self._execute(_op, is_write=True)


class CorruptionEventRepository(BaseRepository):
    """Repository handling forensic audit events for detected byte/chunk damage."""

    def create(self, event: CorruptionEventModel) -> CorruptionEventModel:
        """Records a new corruption event."""
        def _op(conn: sqlite3.Connection) -> CorruptionEventModel:
            sql = """
            INSERT INTO corruption_events (
                event_id, job_id, chunk_index, offset_bytes, expected_sha256,
                actual_sha256, corruption_type, byte_length, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    event.event_id,
                    event.job_id,
                    event.chunk_index,
                    event.offset_bytes,
                    event.expected_sha256,
                    event.actual_sha256,
                    event.corruption_type,
                    event.byte_length,
                    event.detected_at,
                ),
            )
            cursor.close()
            return event

        return self._execute(_op, is_write=True)

    def create_batch(self, events: List[CorruptionEventModel]) -> int:
        """Inserts multiple corruption events atomically."""
        def _op(conn: sqlite3.Connection) -> int:
            sql = """
            INSERT INTO corruption_events (
                event_id, job_id, chunk_index, offset_bytes, expected_sha256,
                actual_sha256, corruption_type, byte_length, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.executemany(
                sql,
                [
                    (
                        e.event_id,
                        e.job_id,
                        e.chunk_index,
                        e.offset_bytes,
                        e.expected_sha256,
                        e.actual_sha256,
                        e.corruption_type,
                        e.byte_length,
                        e.detected_at,
                    )
                    for e in events
                ],
            )
            count = cursor.rowcount
            cursor.close()
            return count

        return self._execute(_op, is_write=True)

    def get_by_id(self, event_id: str) -> Optional[CorruptionEventModel]:
        """Finds a corruption event by event_id."""
        def _op(conn: sqlite3.Connection) -> Optional[CorruptionEventModel]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM corruption_events WHERE event_id = ?;", (event_id,))
            row = cursor.fetchone()
            cursor.close()
            return CorruptionEventModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def list_by_job_id(self, job_id: str) -> List[CorruptionEventModel]:
        """Lists all corruption events detected during a specific job."""
        def _op(conn: sqlite3.Connection) -> List[CorruptionEventModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM corruption_events WHERE job_id = ? ORDER BY chunk_index ASC;",
                (job_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [CorruptionEventModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def count_by_type(self, job_id: str) -> Dict[str, int]:
        """Returns corruption count breakdown by corruption_type for a job."""
        def _op(conn: sqlite3.Connection) -> Dict[str, int]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT corruption_type, COUNT(*) FROM corruption_events WHERE job_id = ? GROUP BY corruption_type;",
                (job_id,),
            )
            counts = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.close()
            return counts

        return self._execute(_op, is_write=False)


class FormatValidationRepository(BaseRepository):
    """Repository handling format syntactic validation and heuristic repair findings."""

    def create(self, validation: FormatValidationModel) -> FormatValidationModel:
        """Inserts a new format validation finding record."""
        def _op(conn: sqlite3.Connection) -> FormatValidationModel:
            sql = """
            INSERT INTO format_validations (
                validation_id, file_id, filename, detected_format, is_valid,
                error_count, warning_count, details_json, format_verdict,
                repair_log_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
            """
            cursor = conn.cursor()
            cursor.execute(
                sql,
                (
                    validation.validation_id,
                    validation.file_id,
                    validation.filename,
                    validation.detected_format,
                    validation.is_valid,
                    validation.error_count,
                    validation.warning_count,
                    validation.details_json,
                    validation.format_verdict,
                    validation.repair_log_json,
                    validation.created_at,
                ),
            )
            cursor.execute(
                "SELECT * FROM format_validations WHERE validation_id = ?;",
                (validation.validation_id,),
            )
            row = cursor.fetchone()
            cursor.close()
            return FormatValidationModel.from_row(row) if row else validation

        return self._execute(_op, is_write=True)

    def get_by_id(self, validation_id: str) -> Optional[FormatValidationModel]:
        """Finds a format validation record by validation_id."""
        def _op(conn: sqlite3.Connection) -> Optional[FormatValidationModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM format_validations WHERE validation_id = ?;",
                (validation_id,),
            )
            row = cursor.fetchone()
            cursor.close()
            return FormatValidationModel.from_row(row) if row else None

        return self._execute(_op, is_write=False)

    def list_by_filename(self, filename: str) -> List[FormatValidationModel]:
        """Lists validation records for a given filename."""
        def _op(conn: sqlite3.Connection) -> List[FormatValidationModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM format_validations WHERE filename = ? ORDER BY created_at DESC;",
                (filename,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [FormatValidationModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def list_by_file_id(self, file_id: str) -> List[FormatValidationModel]:
        """Lists validation records associated with a file_id."""
        def _op(conn: sqlite3.Connection) -> List[FormatValidationModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM format_validations WHERE file_id = ? ORDER BY created_at DESC;",
                (file_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [FormatValidationModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def list_recent(self, limit: int = 50) -> List[FormatValidationModel]:
        """Lists recent format validation records."""
        def _op(conn: sqlite3.Connection) -> List[FormatValidationModel]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM format_validations ORDER BY created_at DESC LIMIT ?;",
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [FormatValidationModel.from_row(r) for r in rows]

        return self._execute(_op, is_write=False)

    def delete(self, validation_id: str) -> bool:
        """Deletes a validation record."""
        def _op(conn: sqlite3.Connection) -> bool:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM format_validations WHERE validation_id = ?;",
                (validation_id,),
            )
            deleted = cursor.rowcount > 0
            cursor.close()
            return deleted

        return self._execute(_op, is_write=True)


class ReSecureRepository:
    """
    Unified Unit of Work container aggregating all ReSecure repositories.
    Provides single point of entry for service and test layers.
    """

    def __init__(
        self,
        db: Optional[Union[sqlite3.Connection, DatabaseConnectionManager]] = None,
    ) -> None:
        self.files = FileRepository(db)
        self.manifests = ManifestRepository(db)
        self.chunks = ChunkRepository(db)
        self.jobs = RecoveryJobRepository(db)
        self.corruption_events = CorruptionEventRepository(db)
        self.format_validations = FormatValidationRepository(db)
