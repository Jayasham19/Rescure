/**
 * ReSecure Frontend TypeScript Types
 * Single source of truth mapped directly to contracts/resecure/types.ts
 */

export type FileFormat = 'TEXT' | 'CSV' | 'JSON' | 'PNG' | 'JPEG' | 'PDF' | 'BINARY' | 'AUTO';

export type ChunkStatus = 'HEALTHY' | 'CORRUPTED' | 'MISSING' | 'OVERSIZED';

export type OperationVerdict =
  | 'PRISTINE'
  | 'RECOVERABLE'
  | 'VERIFIED_EXACT'
  | 'UNRECOVERABLE_EXACT'
  | 'STRUCTURALLY_SALVAGED'
  | 'INTEGRITY_VIOLATION';

export type JobType = 'PROTECT' | 'VERIFY' | 'RECOVER' | 'VALIDATE' | 'REPAIR';

export type JobStatus = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'UNRECOVERABLE';

export type CorruptionType = 'BIT_FLIP' | 'ZERO_FILL' | 'HEADER_WIPE' | 'TRUNCATION' | 'INJECTION';

export type FindingSeverity = 'INFO' | 'WARNING' | 'ERROR';

export type FormatVerdict = 'FORMAT_VALID' | 'FORMAT_INVALID' | 'STRUCTURALLY_SALVAGED';

// ----------------------------------------------------------------------------
// Core Database / Entity Interfaces
// ----------------------------------------------------------------------------

export interface FileRecord {
  id: string;
  file_path: string;
  filename: string;
  size_bytes: number;
  file_format: 'TEXT' | 'CSV' | 'JSON' | 'PNG' | 'JPEG' | 'BINARY';
  mime_type: string;
  root_sha256: string;
  created_at: string;
  updated_at: string;
}

export interface ManifestRecord {
  id: string;
  file_id: string;
  manifest_version: string;
  algorithm: string;
  chunk_size_bytes: number;
  data_chunks_k: number;
  parity_chunks_m: number;
  redundancy_percentage: number;
  parity_file_path: string;
  key_id?: string | null;
  hmac_signature: string;
  raw_manifest_json: string;
  created_at: string;
}

export interface ChunkRecord {
  id: string;
  manifest_id: string;
  chunk_index: number;
  offset_bytes: number;
  size_bytes: number;
  expected_sha256: string;
  live_sha256?: string | null;
  status: ChunkStatus;
  last_verified_at: string;
}

export interface RecoveryJobRecord {
  id: string;
  file_id?: string | null;
  manifest_id?: string | null;
  job_type: JobType;
  status: JobStatus;
  progress_pct: number;
  source_path: string;
  output_path?: string | null;
  corrupted_chunks: number;
  missing_chunks: number;
  parity_consumed: number;
  verdict?: OperationVerdict | null;
  duration_ms?: number | null;
  throughput_mb_s?: number | null;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export interface CorruptionEventRecord {
  id: string;
  job_id: string;
  file_id?: string | null;
  chunk_index: number;
  offset_bytes: number;
  byte_length: number;
  corruption_type: CorruptionType;
  detected_at: string;
}

export interface FormatValidationRecord {
  id: string;
  file_id: string;
  format: 'TEXT' | 'CSV' | 'JSON' | 'PNG' | 'JPEG';
  is_valid: number;
  format_verdict: FormatVerdict;
  metrics_json: string;
  anomalies_json: string;
  repair_log_json?: string | null;
  validated_at: string;
}

// ----------------------------------------------------------------------------
// Manifest File Schemas
// ----------------------------------------------------------------------------

export interface ChunkHashItem {
  index: number;
  offset: number;
  size_bytes: number;
  sha256: string;
}

export interface ManifestMetadata {
  original_filename: string;
  file_size_bytes: number;
  file_format: string;
  mime_type: string;
}

export interface ErasureCodingConfig {
  algorithm: 'Reed-Solomon-GF256';
  chunk_size_bytes: number;
  data_chunks_k: number;
  parity_chunks_m: number;
  redundancy_percentage: number;
  parity_file_name: string;
}

export interface ManifestIntegrity {
  root_sha256: string;
  chunk_hashes: ChunkHashItem[];
}

export interface ManifestAuthentication {
  key_id?: string;
  algorithm: 'HMAC-SHA256';
  hmac_signature: string;
}

export interface IntegrityManifest {
  $schema?: string;
  manifest_version: string;
  created_at: string;
  metadata: ManifestMetadata;
  erasure_coding: ErasureCodingConfig;
  integrity: ManifestIntegrity;
  authentication: ManifestAuthentication;
}

// ----------------------------------------------------------------------------
// API Requests & Responses
// ----------------------------------------------------------------------------

export interface ProtectFileRequest {
  source_path: string;
  redundancy_percentage?: number; // 5 to 100, default 20
  chunk_size_bytes?: 16384 | 65536 | 262144 | 1048576; // default 65536
  output_dir?: string | null;
  secret_key?: string | null;
  key_id?: string | null;
}

export interface ProtectFileResponse {
  job_id: string;
  file_id: string;
  manifest_path: string;
  parity_path: string;
  root_sha256: string;
  total_chunks_k: number;
  parity_chunks_m: number;
  redundancy_percentage: number;
  hmac_signature: string;
  duration_ms: number;
}

export interface ChunkHealthItem {
  index: number;
  offset: number;
  size_bytes: number;
  expected_sha256: string;
  live_sha256: string | null;
  status: ChunkStatus;
  detected_flaw?: string;
}

export interface VerifyFileRequest {
  source_path: string;
  manifest_path: string;
  secret_key?: string | null;
}

export interface VerifyFileResponse {
  job_id: string;
  source_path: string;
  manifest_hmac_valid: boolean;
  verdict: OperationVerdict;
  health_percentage: number;
  total_chunks_k: number;
  healthy_chunks: number;
  corrupted_chunks: number;
  missing_chunks: number;
  corrupted_indices?: number[];
  parity_chunks_available?: number;
  chunk_health_map: ChunkHealthItem[];
  duration_ms: number;
}

export interface RecoverFileRequest {
  source_path: string;
  manifest_path: string;
  parity_path: string;
  output_path: string;
  secret_key?: string | null;
}

export interface RecoverFileResponse {
  job_id: string;
  source_path: string;
  output_path: string;
  original_root_sha256: string;
  recovered_root_sha256: string;
  hash_verified_exact: boolean;
  verdict: OperationVerdict;
  parity_shards_consumed: number;
  parity_shards_remaining: number;
  duration_ms: number;
  throughput_mb_s: number;
}

export interface SafeFailureResponse {
  error_code: 'ERR_EXCEEDS_REDUNDANCY';
  verdict: 'UNRECOVERABLE_EXACT';
  message: string;
  damaged_chunks_count: number;
  parity_chunks_available: number;
  deficit: number;
  damaged_indices: number[];
  safe_action_taken: string;
}

export interface FormatValidationFinding {
  rule_name: string;
  passed: boolean;
  severity: FindingSeverity;
  message: string;
  byte_offset?: number | null;
  line_number?: number | null;
}

export interface ValidateFormatRequest {
  source_path: string;
  format?: FileFormat;
}

export interface ValidateFormatResponse {
  format: FileFormat;
  is_valid: boolean;
  verdict: 'FORMAT_VALID' | 'FORMAT_INVALID';
  findings: FormatValidationFinding[];
  metrics: Record<string, unknown>;
}

export interface RepairLogEntry {
  action: string;
  row?: number | null;
  byte_offset?: number | null;
  description: string;
  tokens_appended?: string | null;
}

export interface RepairFormatRequest {
  source_path: string;
  output_path: string;
  format?: FileFormat;
  actions?: string[];
}

export interface RepairFormatResponse {
  source_path: string;
  output_path: string;
  log_path: string;
  format: FileFormat;
  verdict: OperationVerdict;
  disclosure_warning: string;
  mutations_count: number;
  repair_log: RepairLogEntry[];
}

export interface JobStatusResponse {
  job_id: string;
  job_type: JobType;
  status: JobStatus;
  progress_pct: number;
  source_path: string;
  output_path?: string | null;
  verdict?: OperationVerdict | null;
  error_message?: string | null;
  duration_ms?: number | null;
  throughput_mb_s?: number | null;
  created_at: string;
  completed_at?: string | null;
}

export interface ForensicReportResponse {
  operation_id: string;
  timestamp: string;
  tool_version: string;
  operation_type: JobType;
  target_file: {
    source_path: string;
    output_path?: string | null;
    original_size_bytes: number;
    recovered_size_bytes?: number | null;
  };
  cryptography: {
    manifest_hmac_valid: boolean;
    original_root_sha256: string;
    recovered_root_sha256?: string | null;
    hash_match_verified?: boolean | null;
  };
  chunk_diagnostics: {
    total_chunks_k: number;
    parity_chunks_m: number;
    healthy_chunks: number;
    corrupted_chunks: number;
    missing_chunks: number;
    corrupted_indices?: number[];
    health_percentage: number;
  };
  recovery_metrics: {
    parity_shards_consumed?: number | null;
    parity_shards_remaining?: number | null;
    verdict: OperationVerdict;
    duration_ms: number;
    throughput_mb_s?: number | null;
  };
  format_validation?: {
    format_detected: string;
    is_structurally_valid: boolean;
    anomalies_detected: number;
  } | null;
}

export interface HealthCheckResponse {
  status: 'OK' | 'DEGRADED';
  timestamp: string;
  version: string;
  database_connected: boolean;
  memory_rss_mb: number;
  disk_space_available_gb?: number;
}

export interface ErrorResponse {
  error_code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
}


export interface OneClickRepairResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  detected_format: string;
  verdict: 'PRISTINE' | 'EXACT_RECOVERED' | 'REPAIRED' | 'UNRECOVERABLE' | 'UNSUPPORTED';
  is_exact: boolean;
  original_sha256: string;
  output_sha256?: string | null;
  mutations_count: number;
  repair_log: RepairLogEntry[];
  findings: FormatValidationFinding[];
  download_url?: string | null;
  message: string;
  duration_ms: number;
}
