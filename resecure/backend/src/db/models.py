"""
CalmStacks ReSecure Persistence Layer - Data Models
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.db.models
"""

from __future__ import annotations

import sqlite3
from typing import Any, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class FileModel(BaseModel):
    """Represents a protected or audited file record in ReSecure."""
    model_config = ConfigDict(populate_by_name=True)

    file_id: str = Field(description="UUIDv4 identifier of the file")
    filename: str = Field(description="Base filename without directory path")
    file_size: int = Field(ge=0, description="Exact size of the file in bytes")
    root_sha256: str = Field(min_length=64, max_length=64, description="64-char lowercase SHA-256 root hash")
    mime_type: str = Field(default="application/octet-stream", description="MIME classification")
    file_path: Optional[str] = Field(default=None, description="Absolute canonical file path")
    file_format: Optional[str] = Field(default="BINARY", description="Format: TEXT, CSV, JSON, PNG, JPEG, PDF, BINARY")
    created_at: Optional[str] = Field(default=None, description="ISO-8601 creation timestamp")
    updated_at: Optional[str] = Field(default=None, description="ISO-8601 last updated timestamp")

    @property
    def id(self) -> str:
        """Compatibility alias for file_id."""
        return self.file_id

    @property
    def size_bytes(self) -> int:
        """Compatibility alias for file_size."""
        return self.file_size

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> FileModel:
        d = dict(row)
        return cls(
            file_id=d.get("file_id") or d.get("id"),
            filename=d["filename"],
            file_size=d.get("file_size") if d.get("file_size") is not None else d.get("size_bytes", 0),
            root_sha256=d["root_sha256"],
            mime_type=d.get("mime_type", "application/octet-stream"),
            file_path=d.get("file_path"),
            file_format=d.get("file_format", "BINARY"),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        )


class ManifestModel(BaseModel):
    """Represents an authenticated integrity manifest record."""
    model_config = ConfigDict(populate_by_name=True)

    manifest_id: str = Field(description="UUIDv4 identifier of the manifest")
    file_id: str = Field(description="Foreign key referencing files.file_id")
    total_chunks: int = Field(gt=0, description="Total data chunks (K)")
    chunk_size: int = Field(gt=0, description="Chunk size in bytes (e.g. 65536)")
    redundancy_percent: int = Field(ge=5, le=100, description="Configured redundancy (5% to 100%)")
    parity_chunks: int = Field(ge=0, description="Total parity chunks (M)")
    hmac_signature: str = Field(min_length=64, max_length=64, description="64-char HMAC-SHA256 signature")
    key_id: Optional[str] = Field(default=None, description="Optional key identifier")
    raw_manifest_json: str = Field(description="Complete canonical JSON manifest payload")
    parity_file_path: Optional[str] = Field(default=None, description="Path to .rsparity file")
    manifest_version: str = Field(default="1.0.0", description="Semantic schema version")
    algorithm: str = Field(default="Reed-Solomon-GF256", description="FEC algorithm")
    created_at: Optional[str] = Field(default=None, description="ISO-8601 creation timestamp")

    @property
    def id(self) -> str:
        """Compatibility alias for manifest_id."""
        return self.manifest_id

    @property
    def chunk_size_bytes(self) -> int:
        return self.chunk_size

    @property
    def data_chunks_k(self) -> int:
        return self.total_chunks

    @property
    def parity_chunks_m(self) -> int:
        return self.parity_chunks

    @property
    def redundancy_percentage(self) -> int:
        return self.redundancy_percent

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> ManifestModel:
        d = dict(row)
        return cls(
            manifest_id=d.get("manifest_id") or d.get("id"),
            file_id=d["file_id"],
            total_chunks=d.get("total_chunks") if d.get("total_chunks") is not None else d.get("data_chunks_k", 1),
            chunk_size=d.get("chunk_size") if d.get("chunk_size") is not None else d.get("chunk_size_bytes", 65536),
            redundancy_percent=d.get("redundancy_percent") if d.get("redundancy_percent") is not None else d.get("redundancy_percentage", 20),
            parity_chunks=d.get("parity_chunks") if d.get("parity_chunks") is not None else d.get("parity_chunks_m", 0),
            hmac_signature=d["hmac_signature"],
            key_id=d.get("key_id"),
            raw_manifest_json=d["raw_manifest_json"],
            parity_file_path=d.get("parity_file_path"),
            manifest_version=d.get("manifest_version", "1.0.0"),
            algorithm=d.get("algorithm", "Reed-Solomon-GF256"),
            created_at=d.get("created_at"),
        )


class ChunkModel(BaseModel):
    """Represents a discrete 64KB chunk catalog record."""
    model_config = ConfigDict(populate_by_name=True)

    chunk_id: str = Field(description="UUIDv4 identifier of the chunk")
    manifest_id: str = Field(description="Foreign key referencing manifests.manifest_id")
    chunk_index: int = Field(ge=0, description="0-based sequence index")
    offset_bytes: int = Field(ge=0, description="Byte offset in original file")
    size_bytes: int = Field(gt=0, description="Actual byte size of the chunk")
    chunk_sha256: str = Field(min_length=64, max_length=64, description="Pristine chunk SHA-256 hash")
    is_parity: int = Field(default=0, ge=0, le=1, description="0 for data chunk, 1 for parity chunk")
    live_sha256: Optional[str] = Field(default=None, description="Live computed SHA-256 during audit")
    status: str = Field(default="HEALTHY", description="HEALTHY, CORRUPTED, MISSING, OVERSIZED")
    last_verified_at: Optional[str] = Field(default=None, description="ISO-8601 last verified timestamp")

    @property
    def id(self) -> str:
        """Compatibility alias for chunk_id."""
        return self.chunk_id

    @property
    def expected_sha256(self) -> str:
        """Compatibility alias for chunk_sha256."""
        return self.chunk_sha256

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> ChunkModel:
        d = dict(row)
        return cls(
            chunk_id=d.get("chunk_id") or d.get("id"),
            manifest_id=d["manifest_id"],
            chunk_index=d["chunk_index"],
            offset_bytes=d["offset_bytes"],
            size_bytes=d["size_bytes"],
            chunk_sha256=d.get("chunk_sha256") or d.get("expected_sha256", ""),
            is_parity=d.get("is_parity", 0),
            live_sha256=d.get("live_sha256"),
            status=d.get("status", "HEALTHY"),
            last_verified_at=d.get("last_verified_at"),
        )


class RecoveryJobModel(BaseModel):
    """Represents a job state machine execution record."""
    model_config = ConfigDict(populate_by_name=True)

    job_id: str = Field(description="UUIDv4 identifier of the job")
    file_id: Optional[str] = Field(default=None, description="Optional foreign key to files")
    manifest_id: Optional[str] = Field(default=None, description="Optional foreign key to manifests")
    job_type: str = Field(description="VERIFY, RECOVER, REPAIR, PROTECT, VALIDATE")
    status: str = Field(default="PENDING", description="PENDING, RUNNING, PROCESSING, COMPLETED, FAILED, UNRECOVERABLE")
    corrupted_chunks_count: int = Field(default=0, ge=0, description="Count of detected corrupted chunks")
    recovered_chunks_count: int = Field(default=0, ge=0, description="Count of recovered chunks")
    original_sha256: Optional[str] = Field(default=None, description="Original pristine root SHA-256")
    recovered_sha256: Optional[str] = Field(default=None, description="Recovered root SHA-256")
    sha256_match: Optional[int] = Field(default=None, description="1 if hash matches bit-for-bit, 0 if mismatch")
    output_path: Optional[str] = Field(default=None, description="Recovered output file path")
    error_code: Optional[str] = Field(default=None, description="Machine-readable error code")
    error_message: Optional[str] = Field(default=None, description="Diagnostic error message")
    started_at: Optional[str] = Field(default=None, description="ISO-8601 start timestamp")
    completed_at: Optional[str] = Field(default=None, description="ISO-8601 completion timestamp")
    duration_ms: Optional[int] = Field(default=None, description="Total execution duration in milliseconds")
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0, description="Progress percentage")
    source_path: Optional[str] = Field(default=None, description="Target source path")
    parity_consumed: int = Field(default=0, ge=0, description="Parity shards consumed")
    verdict: Optional[str] = Field(default=None, description="PRISTINE, RECOVERABLE, VERIFIED_EXACT, UNRECOVERABLE_EXACT, STRUCTURALLY_SALVAGED, INTEGRITY_VIOLATION")

    @property
    def id(self) -> str:
        """Compatibility alias for job_id."""
        return self.job_id

    @property
    def corrupted_chunks(self) -> int:
        return self.corrupted_chunks_count

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> RecoveryJobModel:
        d = dict(row)
        return cls(
            job_id=d.get("job_id") or d.get("id"),
            file_id=d.get("file_id"),
            manifest_id=d.get("manifest_id"),
            job_type=d["job_type"],
            status=d.get("status", "PENDING"),
            corrupted_chunks_count=d.get("corrupted_chunks_count") if d.get("corrupted_chunks_count") is not None else d.get("corrupted_chunks", 0),
            recovered_chunks_count=d.get("recovered_chunks_count", 0),
            original_sha256=d.get("original_sha256"),
            recovered_sha256=d.get("recovered_sha256"),
            sha256_match=d.get("sha256_match"),
            output_path=d.get("output_path"),
            error_code=d.get("error_code"),
            error_message=d.get("error_message"),
            started_at=d.get("started_at") or d.get("created_at"),
            completed_at=d.get("completed_at"),
            duration_ms=d.get("duration_ms"),
            progress_pct=d.get("progress_pct", 0.0),
            source_path=d.get("source_path"),
            parity_consumed=d.get("parity_consumed", 0),
            verdict=d.get("verdict"),
        )


class CorruptionEventModel(BaseModel):
    """Represents a detected chunk corruption forensic event."""
    model_config = ConfigDict(populate_by_name=True)

    event_id: str = Field(description="UUIDv4 identifier of the event")
    job_id: str = Field(description="Foreign key referencing recovery_jobs.job_id")
    chunk_index: int = Field(ge=0, description="Affected chunk index")
    offset_bytes: int = Field(ge=0, description="Byte offset in target file")
    expected_sha256: str = Field(min_length=64, max_length=64, description="Expected SHA-256 hash")
    actual_sha256: Optional[str] = Field(default=None, description="Live SHA-256 hash (or None if missing)")
    corruption_type: str = Field(description="MODIFIED, MISSING, TRUNCATED, BIT_FLIP, ZERO_FILL, HEADER_WIPE, INJECTION")
    byte_length: Optional[int] = Field(default=None, description="Damaged byte span length")
    detected_at: Optional[str] = Field(default=None, description="ISO-8601 detection timestamp")

    @property
    def id(self) -> str:
        """Compatibility alias for event_id."""
        return self.event_id

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> CorruptionEventModel:
        d = dict(row)
        return cls(
            event_id=d.get("event_id") or d.get("id"),
            job_id=d["job_id"],
            chunk_index=d["chunk_index"],
            offset_bytes=d["offset_bytes"],
            expected_sha256=d["expected_sha256"],
            actual_sha256=d.get("actual_sha256"),
            corruption_type=d["corruption_type"],
            byte_length=d.get("byte_length"),
            detected_at=d.get("detected_at"),
        )


class FormatValidationModel(BaseModel):
    """Represents a format syntax and heuristic validation finding."""
    model_config = ConfigDict(populate_by_name=True)

    validation_id: str = Field(description="UUIDv4 identifier of the validation record")
    file_id: Optional[str] = Field(default=None, description="Optional foreign key to files")
    filename: str = Field(description="Target file name inspected")
    detected_format: str = Field(description="Detected format (TEXT, CSV, JSON, PNG, JPEG, BINARY, UNKNOWN)")
    is_valid: int = Field(ge=0, le=1, description="1 if structurally valid, 0 if invalid")
    error_count: int = Field(default=0, ge=0, description="Number of syntax/format errors")
    warning_count: int = Field(default=0, ge=0, description="Number of format anomalies/warnings")
    details_json: str = Field(default="{}", description="JSON serialized findings and extracted metrics")
    format_verdict: Optional[str] = Field(default="FORMAT_VALID", description="FORMAT_VALID, FORMAT_INVALID, STRUCTURALLY_SALVAGED")
    repair_log_json: Optional[str] = Field(default=None, description="JSON serialized repair disclosure actions")
    created_at: Optional[str] = Field(default=None, description="ISO-8601 validation timestamp")

    @property
    def id(self) -> str:
        """Compatibility alias for validation_id."""
        return self.validation_id

    @property
    def format(self) -> str:
        """Compatibility alias for detected_format."""
        return self.detected_format

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, dict[str, Any]]) -> FormatValidationModel:
        d = dict(row)
        return cls(
            validation_id=d.get("validation_id") or d.get("id"),
            file_id=d.get("file_id"),
            filename=d.get("filename", "unknown"),
            detected_format=d.get("detected_format") or d.get("format", "UNKNOWN"),
            is_valid=int(d.get("is_valid", 0)),
            error_count=d.get("error_count", 0),
            warning_count=d.get("warning_count", 0),
            details_json=d.get("details_json") or d.get("metrics_json", "{}"),
            format_verdict=d.get("format_verdict", "FORMAT_VALID"),
            repair_log_json=d.get("repair_log_json"),
            created_at=d.get("created_at") or d.get("validated_at"),
        )
