"""
CalmStacks ReSecure API Tier - Pydantic Request & Response Schemas
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.api.schemas
Contract: contracts/resecure/api.yaml
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FileFormat(str, Enum):
    TEXT = "TEXT"
    CSV = "CSV"
    JSON = "JSON"
    PNG = "PNG"
    JPEG = "JPEG"
    PDF = "PDF"
    BINARY = "BINARY"
    AUTO = "AUTO"


class ChunkStatus(str, Enum):
    HEALTHY = "HEALTHY"
    CORRUPTED = "CORRUPTED"
    MISSING = "MISSING"
    OVERSIZED = "OVERSIZED"


class OperationVerdict(str, Enum):
    PRISTINE = "PRISTINE"
    RECOVERABLE = "RECOVERABLE"
    VERIFIED_EXACT = "VERIFIED_EXACT"
    UNRECOVERABLE_EXACT = "UNRECOVERABLE_EXACT"
    STRUCTURALLY_SALVAGED = "STRUCTURALLY_SALVAGED"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"


class JobType(str, Enum):
    PROTECT = "PROTECT"
    VERIFY = "VERIFY"
    RECOVER = "RECOVER"
    VALIDATE = "VALIDATE"
    REPAIR = "REPAIR"


class JobStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNRECOVERABLE = "UNRECOVERABLE"


class CorruptionType(str, Enum):
    BIT_FLIP = "BIT_FLIP"
    ZERO_FILL = "ZERO_FILL"
    HEADER_WIPE = "HEADER_WIPE"
    TRUNCATION = "TRUNCATION"
    INJECTION = "INJECTION"
    MODIFIED = "MODIFIED"


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ProtectFileRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(description="Absolute path to the file to be protected")
    redundancy_percentage: int = Field(default=20, ge=5, le=100, description="Reed-Solomon redundancy ratio percentage")
    chunk_size_bytes: int = Field(default=65536, description="Chunk size in bytes (16384, 65536, 262144, 1048576)")
    output_dir: Optional[str] = Field(default=None, description="Directory to place .rsmanifest.json and .rsparity")
    secret_key: Optional[str] = Field(default=None, description="Pre-shared key for HMAC-SHA256 manifest authentication")
    key_id: Optional[str] = Field(default=None, description="Identifier for the HMAC key")


class VerifyFileRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(description="Absolute path to the target file to be verified")
    manifest_path: str = Field(description="Absolute path to the .rsmanifest.json file")
    secret_key: Optional[str] = Field(default=None, description="Pre-shared key used to authenticate manifest HMAC signature")


class RecoverFileRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(description="Absolute path to the damaged source file")
    manifest_path: str = Field(description="Absolute path to the authenticated manifest file")
    parity_path: str = Field(description="Absolute path to the .rsparity container")
    output_path: str = Field(description="Absolute path to write the restored file (must NOT equal source_path)")
    secret_key: Optional[str] = Field(default=None, description="Pre-shared key for HMAC-SHA256 authentication")


class ValidateFormatRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(description="Absolute path to the file to validate")
    format: FileFormat = Field(default=FileFormat.AUTO, description="Target format parser")


class RepairFormatRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str = Field(description="Absolute path to the damaged file")
    output_path: str = Field(description="Absolute path to write the repaired file (must NOT equal source_path)")
    format: FileFormat = Field(default=FileFormat.AUTO, description="File format to apply heuristic repair for")


# ---------------------------------------------------------------------------
# Response Models & Sub-Entities
# ---------------------------------------------------------------------------

class ChunkHashItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    index: int
    offset: int
    size_bytes: int
    sha256: str


class ChunkHealthItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    index: int
    offset: int
    size_bytes: int
    expected_sha256: str
    live_sha256: Optional[str] = None
    status: ChunkStatus


class ProtectFileResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    job_id: str
    file_id: str
    manifest_path: str
    parity_path: str
    root_sha256: str
    total_chunks_k: int
    parity_chunks_m: int
    redundancy_percentage: int
    hmac_signature: str
    duration_ms: int


class VerifyFileResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    job_id: str
    source_path: str
    manifest_hmac_valid: bool
    verdict: OperationVerdict
    health_percentage: float
    total_chunks_k: int
    healthy_chunks: int
    corrupted_chunks: int
    missing_chunks: int
    corrupted_indices: Optional[List[int]] = None
    parity_chunks_available: Optional[int] = None
    chunk_health_map: List[ChunkHealthItem]
    duration_ms: int


class RecoverFileResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    job_id: str
    source_path: str
    output_path: str
    original_root_sha256: str
    recovered_root_sha256: str
    hash_verified_exact: bool
    verdict: OperationVerdict
    parity_shards_consumed: int
    parity_shards_remaining: int
    duration_ms: int
    throughput_mb_s: float


class SafeFailureResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    error_code: str = "ERR_EXCEEDS_REDUNDANCY"
    verdict: OperationVerdict = OperationVerdict.UNRECOVERABLE_EXACT
    message: str
    damaged_chunks_count: int
    parity_chunks_available: int
    deficit: int
    damaged_indices: List[int]
    safe_action_taken: str = "No files written to output destination. Temporary buffers purged."


class FormatValidationFinding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_name: str
    passed: bool
    severity: str
    message: str
    byte_offset: Optional[int] = None
    line_number: Optional[int] = None


class ValidateFormatResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    format: FileFormat
    is_valid: bool
    verdict: str
    findings: List[FormatValidationFinding]
    metrics: Dict[str, Any] = Field(default_factory=dict)


class RepairLogEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    action: str
    description: str
    row: Optional[int] = None
    byte_offset: Optional[int] = None
    tokens_appended: Optional[str] = None


class RepairFormatResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    source_path: str
    output_path: str
    log_path: str
    format: FileFormat
    verdict: OperationVerdict
    disclosure_warning: str
    mutations_count: int
    repair_log: List[RepairLogEntry]


class JobStatusResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    job_id: str
    job_type: JobType
    status: JobStatus
    progress_pct: float
    created_at: str
    source_path: Optional[str] = None
    output_path: Optional[str] = None
    verdict: Optional[OperationVerdict] = None
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None
    throughput_mb_s: Optional[float] = None
    completed_at: Optional[str] = None


class TargetFileTelemetry(BaseModel):
    source_path: str
    output_path: Optional[str] = None
    original_size_bytes: int
    recovered_size_bytes: Optional[int] = None


class CryptographyTelemetry(BaseModel):
    manifest_hmac_valid: bool
    original_root_sha256: str
    recovered_root_sha256: Optional[str] = None
    hash_match_verified: Optional[bool] = None


class ChunkDiagnosticsTelemetry(BaseModel):
    total_chunks_k: int
    parity_chunks_m: int
    healthy_chunks: int
    corrupted_chunks: int
    missing_chunks: int
    health_percentage: float
    corrupted_indices: Optional[List[int]] = None


class RecoveryMetricsTelemetry(BaseModel):
    verdict: OperationVerdict
    duration_ms: int
    parity_shards_consumed: Optional[int] = None
    parity_shards_remaining: Optional[int] = None
    throughput_mb_s: Optional[float] = None


class FormatValidationTelemetry(BaseModel):
    format_detected: str
    is_structurally_valid: bool
    anomalies_detected: int


class ForensicReportResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    operation_id: str
    timestamp: str
    tool_version: str = "ReSecure MVP v1.0.0"
    operation_type: JobType
    target_file: TargetFileTelemetry
    cryptography: CryptographyTelemetry
    chunk_diagnostics: ChunkDiagnosticsTelemetry
    recovery_metrics: RecoveryMetricsTelemetry
    format_validation: Optional[FormatValidationTelemetry] = None


class HealthCheckResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: str
    timestamp: str
    version: str = "1.0.0"
    database_connected: bool
    memory_rss_mb: float
    disk_space_available_gb: Optional[float] = None


class ErrorResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    error_code: str
    message: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class OneClickRepairResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    job_id: str = Field(..., description="Unique UUID for this repair execution")
    filename: str = Field(..., description="Sanitized original filename")
    file_size_bytes: int = Field(..., description="Original input file size in bytes")
    detected_format: str = Field(..., description="Detected format (TEXT, CSV, JSON, PNG, JPEG, BINARY)")
    verdict: str = Field(..., description="Overall verdict: PRISTINE, EXACT_RECOVERED, REPAIRED, UNRECOVERABLE, UNSUPPORTED")
    is_exact: bool = Field(False, description="True ONLY if output verified bit-for-bit against trusted root SHA-256")
    original_sha256: str = Field(..., description="SHA-256 hash of the input file")
    output_sha256: Optional[str] = Field(None, description="SHA-256 hash of the repaired/recovered file")
    mutations_count: int = Field(0, description="Number of mutations/corrections applied")
    repair_log: List[Dict[str, Any]] = Field(default_factory=list, description="Granular log of structural corrections")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Diagnostic findings before/after repair")
    download_url: Optional[str] = Field(None, description="Endpoint to download the repaired/recovered file")
    message: str = Field(..., description="Human-readable outcome summary")
    duration_ms: float = Field(0.0, description="Processing duration in milliseconds")
