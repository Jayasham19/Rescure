/**
 * ReSecure Mock Data Provider
 * Realistic cybersecurity fixtures and mock responses conforming to OpenAPI 3.1 & TypeScript contracts.
 */

import type {
  ChunkHealthItem,
  ForensicReportResponse,
  HealthCheckResponse,
  ProtectFileResponse,
  RecoverFileResponse,
  RecoveryJobRecord,
  RepairFormatResponse,
  SafeFailureResponse,
  ValidateFormatResponse,
  VerifyFileResponse,
  OneClickRepairResponse,
} from '../types/index';

export const mockHealth: HealthCheckResponse = {
  status: 'OK',
  timestamp: new Date().toISOString(),
  version: '1.0.0-mvp',
  database_connected: true,
  memory_rss_mb: 42.4,
  disk_space_available_gb: 128.5,
};

export const createMockChunks = (
  totalK: number = 16,
  corruptedIndices: number[] = [2, 7],
  missingIndices: number[] = []
): ChunkHealthItem[] => {
  return Array.from({ length: totalK }, (_, i) => {
    const isCorrupted = corruptedIndices.includes(i);
    const isMissing = missingIndices.includes(i);
    const offset = i * 65536;

    let status: ChunkHealthItem['status'] = 'HEALTHY';
    let liveSha: string | null = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8${i.toString(16).padStart(2, '0')}`;
    let flaw: string | undefined = undefined;

    if (isCorrupted) {
      status = 'CORRUPTED';
      liveSha = `a3c49e2101ab43cc77889100112233445566778899aabbccddeeff00112233${i.toString(16).padStart(2, '0')}`;
      flaw = i === 2 
        ? '14 Bit Flips detected in CSV row 412 (offset 0x00020420)'
        : 'Null-byte zero fill detected in CSV row 1205 (offset 0x00070110)';
    } else if (isMissing) {
      status = 'MISSING';
      liveSha = null;
      flaw = 'Unexpected EOF; chunk block missing from storage disk';
    }

    return {
      index: i,
      offset,
      size_bytes: 65536,
      expected_sha256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8${i.toString(16).padStart(2, '0')}`,
      live_sha256: liveSha,
      status,
      detected_flaw: flaw,
    };
  });
};

export const mockProtectResponse: ProtectFileResponse = {
  job_id: 'job-protect-8f3e21a0-9c12',
  file_id: 'file-ent-financials-9c12-4e89',
  manifest_path: '/data/enterprise_q3_financials.csv.rsmanifest.json',
  parity_path: '/data/enterprise_q3_financials.csv.rsparity',
  root_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  total_chunks_k: 16,
  parity_chunks_m: 4,
  redundancy_percentage: 20,
  hmac_signature: '9a7b4512e0fc1d882354cfa9e31d45bc8843912061bcda0954b819f24cb514c2',
  duration_ms: 84,
};

export const mockVerifyResponse: VerifyFileResponse = {
  job_id: 'job-verify-44ac71e2-b01f',
  source_path: '/data/enterprise_q3_financials.csv',
  manifest_hmac_valid: true,
  verdict: 'RECOVERABLE',
  health_percentage: 87.5,
  total_chunks_k: 16,
  healthy_chunks: 14,
  corrupted_chunks: 2,
  missing_chunks: 0,
  corrupted_indices: [2, 7],
  parity_chunks_available: 4,
  chunk_health_map: createMockChunks(16, [2, 7], []),
  duration_ms: 56,
};

export const mockRecoverResponse: RecoverFileResponse = {
  job_id: 'job-recover-14b9c8d3-77ef',
  source_path: '/data/enterprise_q3_financials.csv',
  output_path: '/data/recovered/enterprise_q3_financials.csv',
  original_root_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  recovered_root_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  hash_verified_exact: true,
  verdict: 'VERIFIED_EXACT',
  parity_shards_consumed: 2,
  parity_shards_remaining: 2,
  duration_ms: 112,
  throughput_mb_s: 9.4,
};

export const mockSafeFailureResponse: SafeFailureResponse = {
  error_code: 'ERR_EXCEEDS_REDUNDANCY',
  verdict: 'UNRECOVERABLE_EXACT',
  message: 'Critical threshold exceeded: 6 damaged chunks detected while only 4 parity shards are available (Deficit: -2 chunks).',
  damaged_chunks_count: 6,
  parity_chunks_available: 4,
  deficit: -2,
  damaged_indices: [1, 2, 6, 7, 10, 14],
  safe_action_taken: 'Safe Failure Protocol Enforced: Output write halted. Source file untouched.',
};

export const mockValidateFormatResponse: ValidateFormatResponse = {
  format: 'JSON',
  is_valid: false,
  verdict: 'FORMAT_INVALID',
  findings: [
    {
      rule_name: 'RFC_8259_STRING_DELIMITERS',
      passed: false,
      severity: 'ERROR',
      message: 'Unterminated string literal before newline',
      line_number: 48,
      byte_offset: 1024,
    },
    {
      rule_name: 'RFC_8259_TRAILING_COMMAS',
      passed: false,
      severity: 'WARNING',
      message: 'Trailing comma before closing object bracket "}"',
      line_number: 52,
      byte_offset: 1180,
    },
    {
      rule_name: 'RFC_8259_STREAM_COMPLETION',
      passed: false,
      severity: 'ERROR',
      message: 'Truncated stream with 2 unclosed brackets (1 Array "[", 1 Object "{"',
      line_number: 85,
      byte_offset: 2450,
    },
  ],
  metrics: {
    nesting_depth: 4,
    total_tokens: 412,
    unclosed_brackets: 2,
  },
};

export const mockRepairFormatResponse: RepairFormatResponse = {
  source_path: '/data/corrupted_telemetry.json',
  output_path: '/data/recovered/corrupted_telemetry.repaired.json',
  log_path: '/data/recovered/corrupted_telemetry.repaired.log.json',
  format: 'JSON',
  verdict: 'STRUCTURALLY_SALVAGED',
  disclosure_warning: 'Heuristic structural repair alters syntax to achieve RFC compliance. It does NOT guarantee semantic completeness. Source file remains untouched.',
  mutations_count: 3,
  repair_log: [
    {
      action: 'CLOSE_STRING_LITERAL',
      row: 48,
      byte_offset: 1024,
      description: 'Appended closing quote before newline',
      tokens_appended: '"',
    },
    {
      action: 'STRIP_TRAILING_COMMA',
      row: 52,
      byte_offset: 1180,
      description: 'Removed illegal trailing comma before object terminator',
    },
    {
      action: 'BALANCE_DELIMITERS',
      row: 85,
      byte_offset: 2450,
      description: 'Appended balanced closing brackets "]}"',
      tokens_appended: ']}',
    },
  ],
};

export const mockAuditRecords: RecoveryJobRecord[] = [
  {
    id: 'job-rec-8812a-001',
    file_id: 'file-001',
    job_type: 'RECOVER',
    status: 'COMPLETED',
    progress_pct: 100,
    source_path: 'enterprise_financials.csv',
    output_path: '/data/recovered/enterprise_financials.csv',
    corrupted_chunks: 2,
    missing_chunks: 0,
    parity_consumed: 2,
    verdict: 'VERIFIED_EXACT',
    duration_ms: 112,
    throughput_mb_s: 9.4,
    created_at: '2026-10-22T17:15:02Z',
    completed_at: '2026-10-22T17:15:02Z',
  },
  {
    id: 'job-ver-7741b-002',
    file_id: 'file-001',
    job_type: 'VERIFY',
    status: 'COMPLETED',
    progress_pct: 100,
    source_path: 'enterprise_financials.csv',
    corrupted_chunks: 2,
    missing_chunks: 0,
    parity_consumed: 0,
    verdict: 'RECOVERABLE',
    duration_ms: 56,
    throughput_mb_s: 18.2,
    created_at: '2026-10-22T16:50:31Z',
    completed_at: '2026-10-22T16:50:31Z',
  },
  {
    id: 'job-rep-9923c-003',
    file_id: 'file-003',
    job_type: 'REPAIR',
    status: 'COMPLETED',
    progress_pct: 100,
    source_path: 'event_stream.json',
    output_path: '/data/recovered/event_stream.repaired.json',
    corrupted_chunks: 0,
    missing_chunks: 0,
    parity_consumed: 0,
    verdict: 'STRUCTURALLY_SALVAGED',
    duration_ms: 45,
    throughput_mb_s: 12.0,
    created_at: '2026-10-22T15:30:10Z',
    completed_at: '2026-10-22T15:30:10Z',
  },
  {
    id: 'job-rec-3301d-004',
    file_id: 'file-004',
    job_type: 'RECOVER',
    status: 'UNRECOVERABLE',
    progress_pct: 100,
    source_path: 'patient_records_q2.db',
    corrupted_chunks: 6,
    missing_chunks: 0,
    parity_consumed: 0,
    verdict: 'UNRECOVERABLE_EXACT',
    duration_ms: 32,
    throughput_mb_s: 22.0,
    error_message: 'ERR_EXCEEDS_REDUNDANCY: 6 damaged chunks exceed 2 parity shards (deficit -4)',
    created_at: '2026-10-22T14:12:44Z',
    completed_at: '2026-10-22T14:12:44Z',
  },
  {
    id: 'job-pro-1192e-005',
    file_id: 'file-001',
    job_type: 'PROTECT',
    status: 'COMPLETED',
    progress_pct: 100,
    source_path: 'enterprise_financials.csv',
    corrupted_chunks: 0,
    missing_chunks: 0,
    parity_consumed: 0,
    verdict: 'PRISTINE',
    duration_ms: 84,
    throughput_mb_s: 12.5,
    created_at: '2026-10-22T12:00:19Z',
    completed_at: '2026-10-22T12:00:19Z',
  },
];

export const getMockForensicReport = (jobId: string): ForensicReportResponse => {
  const match = mockAuditRecords.find((r) => r.id === jobId) || mockAuditRecords[0];

  return {
    operation_id: match.id,
    timestamp: match.created_at,
    tool_version: '1.0.0-mvp',
    operation_type: match.job_type,
    target_file: {
      source_path: match.source_path,
      output_path: match.output_path || null,
      original_size_bytes: 1048576,
      recovered_size_bytes: match.output_path ? 1048576 : null,
    },
    cryptography: {
      manifest_hmac_valid: true,
      original_root_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      recovered_root_sha256: match.verdict === 'VERIFIED_EXACT' ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' : null,
      hash_match_verified: match.verdict === 'VERIFIED_EXACT',
    },
    chunk_diagnostics: {
      total_chunks_k: 16,
      parity_chunks_m: 4,
      healthy_chunks: 16 - match.corrupted_chunks,
      corrupted_chunks: match.corrupted_chunks,
      missing_chunks: match.missing_chunks,
      corrupted_indices: match.corrupted_chunks > 0 ? [2, 7] : [],
      health_percentage: ((16 - match.corrupted_chunks) / 16) * 100,
    },
    recovery_metrics: {
      parity_shards_consumed: match.parity_consumed,
      parity_shards_remaining: 4 - match.parity_consumed,
      verdict: match.verdict || 'PRISTINE',
      duration_ms: match.duration_ms || 84,
      throughput_mb_s: match.throughput_mb_s || 12.5,
    },
    format_validation: match.job_type === 'REPAIR' ? {
      format_detected: 'JSON',
      is_structurally_valid: true,
      anomalies_detected: 3,
    } : null,
  };
};

export const mockOneClickRepairResponse: OneClickRepairResponse = {
  job_id: 'job-oneclick-mock-001',
  filename: 'corrupted_sample.json',
  file_size_bytes: 1024,
  detected_format: 'JSON',
  verdict: 'REPAIRED',
  is_exact: false,
  original_sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
  output_sha256: 'f0e1d2c3b4a59687123456789abcdef0123456789abcdef0123456789abcdef0',
  mutations_count: 2,
  repair_log: [
    {
      action: 'STRIP_TRAILING_DELIMITER',
      byte_offset: 104,
      description: 'Stripped trailing comma before closing bracket',
    },
    {
      action: 'SYNTHESIZE_CLOSING_DELIMITER',
      byte_offset: 120,
      description: 'Synthesized missing closing delimiter ]',
      tokens_appended: ']',
    },
  ],
  findings: [
    {
      rule_name: 'JSON_SYNTAX',
      passed: true,
      severity: 'INFO',
      message: 'Syntactically valid JSON after repair',
    },
  ],
  download_url: '/api/download-repaired/job-oneclick-mock-001',
  message: 'Heuristic structural repair succeeded. Validated with 2 mutations.',
  duration_ms: 45,
};
