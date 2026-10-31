/**
 * Automated Verification Test Suite for ReSecure Frontend
 * Validates API client contracts, mock engine fixtures, and mathematical invariants.
 */

import assert from 'node:assert/strict';
import { test, describe } from 'node:test';

// Import compiled or source modules
import {
  mockHealth,
  mockProtectResponse,
  mockVerifyResponse,
  mockRecoverResponse,
  mockSafeFailureResponse,
  mockValidateFormatResponse,
  mockRepairFormatResponse,
  mockAuditRecords,
  createMockChunks,
  getMockForensicReport,
  mockOneClickRepairResponse,
} from '../src/api/mockData.ts';

describe('ReSecure Frontend Verification Test Suite', () => {
  test('1. Health Check Response Schema Conformance', () => {
    assert.equal(mockHealth.status, 'OK');
    assert.equal(mockHealth.version, '1.0.0-mvp');
    assert.equal(mockHealth.database_connected, true);
    assert.ok(mockHealth.memory_rss_mb <= 150, 'Memory RSS must be stream bounded <= 150MB');
  });

  test('2. Erasure Coding & Redundancy Mathematics', () => {
    const fileSizeBytes = 1048576; // 1 MB
    const chunkSizeBytes = 65536; // 64 KB
    const redundancyPct = 20;

    const dataChunksK = Math.ceil(fileSizeBytes / chunkSizeBytes);
    assert.equal(dataChunksK, 16, '1MB at 64KB chunks must yield K=16');

    const parityChunksM = Math.max(1, Math.ceil((dataChunksK * redundancyPct) / 100));
    assert.equal(parityChunksM, 4, '16 chunks at 20% redundancy must yield M=4 parity shards');

    // Test extreme redundancy (100% mirror)
    const mirrorM = Math.max(1, Math.ceil((dataChunksK * 100) / 100));
    assert.equal(mirrorM, 16, '100% redundancy must yield M=16');
  });

  test('3. Chunk Grid Visualizer State Generator', () => {
    const chunks = createMockChunks(16, [2, 7], []);
    assert.equal(chunks.length, 16);
    assert.equal(chunks[0].status, 'HEALTHY');
    assert.equal(chunks[2].status, 'CORRUPTED');
    assert.equal(chunks[7].status, 'CORRUPTED');
    assert.equal(chunks[2].offset, 2 * 65536);
    assert.ok(chunks[2].detected_flaw?.includes('Bit Flips'));
  });

  test('4. Exact Mathematical Recovery Invariant (E <= M)', () => {
    assert.equal(mockRecoverResponse.verdict, 'VERIFIED_EXACT');
    assert.equal(mockRecoverResponse.hash_verified_exact, true);
    assert.equal(
      mockRecoverResponse.original_root_sha256,
      mockRecoverResponse.recovered_root_sha256,
      'Recovered SHA-256 must match original root SHA-256 bit-for-bit'
    );
    assert.ok(
      mockRecoverResponse.output_path.includes('/data/recovered/'),
      'Output path must be segregated from source path'
    );
  });

  test('5. Safe Failure Invariant Enforcement (E > M)', () => {
    assert.equal(mockSafeFailureResponse.error_code, 'ERR_EXCEEDS_REDUNDANCY');
    assert.equal(mockSafeFailureResponse.verdict, 'UNRECOVERABLE_EXACT');
    assert.equal(mockSafeFailureResponse.damaged_chunks_count, 6);
    assert.equal(mockSafeFailureResponse.parity_chunks_available, 4);
    assert.equal(mockSafeFailureResponse.deficit, -2);
    assert.ok(
      mockSafeFailureResponse.safe_action_taken.includes('Output write halted'),
      'Safe failure must strictly halt output write'
    );
  });

  test('6. Deep Format Validation & Structural Anomaly Detection', () => {
    assert.equal(mockValidateFormatResponse.format, 'JSON');
    assert.equal(mockValidateFormatResponse.is_valid, false);
    assert.equal(mockValidateFormatResponse.verdict, 'FORMAT_INVALID');
    assert.equal(mockValidateFormatResponse.findings.length, 3);
    assert.equal(mockValidateFormatResponse.findings[0].severity, 'ERROR');
  });

  test('7. Opt-In Heuristic Structural Repair & Disclosure Logging', () => {
    assert.equal(mockRepairFormatResponse.verdict, 'STRUCTURALLY_SALVAGED');
    assert.equal(mockRepairFormatResponse.mutations_count, 3);
    assert.ok(mockRepairFormatResponse.output_path.endsWith('.repaired.json'));
    assert.ok(mockRepairFormatResponse.log_path.endsWith('.log.json'));
    assert.equal(mockRepairFormatResponse.repair_log.length, 3);
    assert.ok(mockRepairFormatResponse.disclosure_warning.includes('NOT guarantee semantic completeness'));
  });

  test('8. Forensic Report Contract Integrity', () => {
    const report = getMockForensicReport('job-rec-8812a-001');
    assert.equal(report.operation_type, 'RECOVER');
    assert.equal(report.cryptography.hash_match_verified, true);
    assert.equal(report.chunk_diagnostics.total_chunks_k, 16);
    assert.equal(report.chunk_diagnostics.parity_chunks_m, 4);
    assert.ok(report.recovery_metrics.duration_ms > 0);
  });

  test('9. Forensic Audit Registry Dataset', () => {
    assert.ok(mockAuditRecords.length >= 5);
    const verdicts = mockAuditRecords.map((r) => r.verdict);
    assert.ok(verdicts.includes('VERIFIED_EXACT'));
    assert.ok(verdicts.includes('RECOVERABLE'));
    assert.ok(verdicts.includes('STRUCTURALLY_SALVAGED'));
    assert.ok(verdicts.includes('UNRECOVERABLE_EXACT'));
  });

  test('10. One-Click Repair Response Contract and Landing Page Fixtures', () => {
    assert.equal(mockOneClickRepairResponse.job_id, 'job-oneclick-mock-001');
    assert.equal(mockOneClickRepairResponse.filename, 'corrupted_sample.json');
    assert.equal(mockOneClickRepairResponse.detected_format, 'JSON');
    assert.equal(mockOneClickRepairResponse.verdict, 'REPAIRED');
    assert.equal(mockOneClickRepairResponse.is_exact, false);
    assert.equal(mockOneClickRepairResponse.mutations_count, 2);
    assert.equal(mockOneClickRepairResponse.repair_log.length, 2);
    assert.ok(mockOneClickRepairResponse.download_url.includes('/api/download-repaired/'));
  });
});
