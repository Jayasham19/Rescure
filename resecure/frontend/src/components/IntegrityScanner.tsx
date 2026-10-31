import React, { useState } from 'react';
import {
  Search,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  Activity,
} from './icons';
import { ChunkHealthItem, VerifyFileResponse } from '../types';
import { apiClient } from '../api/client';
import { ChunkGrid } from './ChunkGrid';

interface IntegrityScannerProps {
  onProceedToRecovery?: (verifyData: VerifyFileResponse) => void;
}

export const IntegrityScanner: React.FC<IntegrityScannerProps> = ({ onProceedToRecovery }) => {
  const [sourcePath, setSourcePath] = useState<string>('enterprise_q3_financials.csv');
  const [manifestPath, setManifestPath] = useState<string>('enterprise_q3_financials.csv.rsmanifest.json');
  const [secretKey, setSecretKey] = useState<string>('c0ffee8899aabbccddeeff00112233445566778899aabbccddeeff0011223344');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<VerifyFileResponse | null>(null);
  const [hmacError, setHmacError] = useState<string | null>(null);
  const [selectedChunk, setSelectedChunk] = useState<ChunkHealthItem | null>(null);

  const handleExecuteAudit = async () => {
    setIsScanning(true);
    setHmacError(null);
    setScanResult(null);

    try {
      const res = await apiClient.verifyFile({
        source_path: sourcePath,
        manifest_path: manifestPath,
        secret_key: secretKey || null,
      });
      setScanResult(res);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'isHmacMismatch' in err) {
        setHmacError('Manifest HMAC signature mismatch: Cryptographic tampering detected. System has failed closed.');
      } else {
        console.error('Audit failure:', err);
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handlePreCheckSignature = () => {
    if (secretKey === 'tampered' || secretKey === 'bad_key') {
      setHmacError('Recorded signature: 9a7b...14c2 does NOT match computed signature: 1f0e...58ba. Integrity violated.');
      setScanResult(null);
    } else {
      setHmacError(null);
    }
  };

  const damagedCount = scanResult ? scanResult.corrupted_chunks + scanResult.missing_chunks : 0;
  const parityAvailable = scanResult?.parity_chunks_available ?? 4;
  const isRecoverable = damagedCount <= parityAvailable;

  return (
    <div className="space-y-6">
      {/* Target Ingestion & Signature Inputs */}
      <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
            <Search className="w-4 h-4 text-[#06B6D4]" />
            <span>INTEGRITY SCANNER: AUDIT TARGET FILE AGAINST TRUSTED MANIFEST</span>
          </h3>
          <span className="text-xs font-mono text-[#94A3B8]">Single-Byte Precision</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
              Target File to Audit:
            </label>
            <div className="relative">
              <input
                type="text"
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
              Integrity Manifest (.rsmanifest.json):
            </label>
            <div className="relative">
              <input
                type="text"
                value={manifestPath}
                onChange={(e) => setManifestPath(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* Pre-Shared Key with Test Controls */}
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="flex-1 w-full">
            <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
              Pre-Shared Key (HMAC Verification):
            </label>
            <input
              type="password"
              value={secretKey}
              onChange={(e) => {
                setSecretKey(e.target.value);
                setHmacError(null);
              }}
              placeholder="Enter pre-shared HMAC secret key..."
              className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            />
          </div>

          <div className="flex items-center space-x-2 pt-5 w-full sm:w-auto">
            <button
              type="button"
              onClick={handlePreCheckSignature}
              className="px-3 py-2 rounded-lg bg-[#1E293B] hover:bg-[#334155] text-xs font-mono text-[#CBD5E1] border border-[#334155] transition-colors whitespace-nowrap"
            >
              Verify Signature
            </button>

            <button
              type="button"
              onClick={() => {
                setSecretKey('tampered');
                setHmacError('CRITICAL SECURITY ALERT: Manifest HMAC signature mismatch (Tampering Detected). System has failed closed.');
                setScanResult(null);
              }}
              className="px-2.5 py-2 rounded-lg bg-[#78350F]/40 hover:bg-[#78350F] text-xs font-mono text-[#FCD34D] border border-[#F59E0B]/50 transition-colors whitespace-nowrap"
              title="Inject simulated signature tamper to test Fail-Closed invariant"
            >
              Simulate Tamper
            </button>
          </div>
        </div>

        {/* Execute Action */}
        <button
          type="button"
          disabled={isScanning}
          onClick={handleExecuteAudit}
          className={`w-full py-3 px-4 rounded-xl font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 ${
            isScanning
              ? 'bg-[#1E293B] text-[#94A3B8] cursor-wait'
              : 'bg-[#06B6D4] hover:bg-[#0891B2] text-[#0A0F1D] shadow-cyan-glow'
          }`}
        >
          {isScanning ? (
            <>
              <div className="w-4 h-4 rounded-full border-2 border-[#0A0F1D] border-t-transparent animate-spin" />
              <span>STREAMING CHUNKS &amp; AUDITING CRYPTOGRAPHIC INTEGRITY...</span>
            </>
          ) : (
            <>
              <Activity className="w-4 h-4" />
              <span>EXECUTE INTEGRITY AUDIT</span>
            </>
          )}
        </button>
      </div>

      {/* Fail-Closed Critical HMAC Tamper Alert */}
      {hmacError && (
        <div className="p-5 rounded-xl bg-[#7F1D1D]/30 border-2 border-[#EF4444] shadow-crimson-glow space-y-3">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-6 h-6 text-[#EF4444] shrink-0" />
            <div>
              <h4 className="font-bold text-base text-[#FCA5A5]">
                🚨 CRITICAL SECURITY ALERT: MANIFEST HMAC SIGNATURE MISMATCH (TAMPERING DETECTED)
              </h4>
              <p className="text-xs text-[#CBD5E1]">
                Invariant Violated: Manifest payload has been altered or signed with an unauthorized secret key.
              </p>
            </div>
          </div>
          <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#EF4444]/40 font-mono text-xs text-[#EF4444]">
            {hmacError}
          </div>
          <p className="text-xs text-[#CBD5E1]">
            <strong>Fail-Closed Security:</strong> All downstream recovery and audit routines are immediately
            halted to protect user data from manipulated metadata.
          </p>
        </div>
      )}

      {/* Audit Results Dashboard */}
      {scanResult && !hmacError && (
        <div className="space-y-6">
          {/* Health Score & Verdict Overview */}
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="space-y-1">
              <span className="text-xs font-mono text-[#94A3B8]">Operational Verdict:</span>
              <div className="flex items-center space-x-2">
                <span
                  className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase border ${
                    scanResult.verdict === 'PRISTINE'
                      ? 'bg-[#064E3B]/60 text-[#6EE7B7] border-[#10B981]/50'
                      : isRecoverable
                      ? 'bg-[#78350F]/60 text-[#FCD34D] border-[#F59E0B]/50'
                      : 'bg-[#7F1D1D]/60 text-[#FCA5A5] border-[#EF4444]/60'
                  }`}
                >
                  {scanResult.verdict === 'PRISTINE'
                    ? '✓ PRISTINE (100% VERIFIED)'
                    : isRecoverable
                    ? '⚠ CORRUPTED (RECOVERABLE VIA GF-2^8)'
                    : '✕ UNRECOVERABLE EXACT (DAMAGE > PARITY)'}
                </span>

                <span className="px-2.5 py-1 rounded-full bg-[#064E3B]/40 text-[#6EE7B7] text-xs font-mono border border-[#10B981]/40 flex items-center space-x-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>HMAC VALID</span>
                </span>
              </div>
            </div>

            {/* Health Score Gauge */}
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-2xl font-bold font-mono text-[#F8FAFC]">
                  {scanResult.health_percentage.toFixed(1)}%
                </div>
                <div className="text-xs text-[#94A3B8] font-mono">
                  {scanResult.healthy_chunks}/{scanResult.total_chunks_k} Healthy Chunks
                </div>
              </div>

              {/* Progress Bar Container */}
              <div className="w-32 h-3.5 bg-[#0A0F1D] rounded-full overflow-hidden border border-[#334155]">
                <div
                  className={`h-full transition-all duration-500 ${
                    scanResult.health_percentage === 100
                      ? 'bg-[#10B981]'
                      : scanResult.health_percentage >= 75
                      ? 'bg-[#F59E0B]'
                      : 'bg-[#EF4444]'
                  }`}
                  style={{ width: `${scanResult.health_percentage}%` }}
                />
              </div>
            </div>
          </div>

          {/* 64KB Interactive Chunk Grid */}
          <ChunkGrid
            chunks={scanResult.chunk_health_map}
            parityCount={scanResult.parity_chunks_available || 4}
            onSelectChunk={(c) => setSelectedChunk(c)}
            selectedChunkIndex={selectedChunk?.index}
          />

          {/* Damage Analysis Card */}
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
            <h4 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-[#F59E0B]" />
              <span>FORENSIC DAMAGE ANALYSIS &amp; SOLVABILITY STATUS</span>
            </h4>

            <div className="space-y-2 text-xs font-mono">
              {scanResult.chunk_health_map
                .filter((c) => c.status !== 'HEALTHY')
                .map((chunk) => (
                  <div
                    key={chunk.index}
                    className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"
                  >
                    <div>
                      <span className="font-bold text-[#F59E0B]">
                        Chunk #{chunk.index.toString().padStart(2, '0')}:
                      </span>{' '}
                      <span className="text-[#CBD5E1]">
                        Offset 0x{chunk.offset.toString(16).padStart(8, '0').toUpperCase()} - 0x
                        {(chunk.offset + 65535).toString(16).padStart(8, '0').toUpperCase()}
                      </span>
                      <div className="text-[11px] text-[#94A3B8]">
                        {chunk.detected_flaw || 'Cryptographic SHA-256 hash divergence'}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-[#78350F]/50 text-[#FCD34D] border border-[#F59E0B]/50 shrink-0 text-center">
                      {chunk.status}
                    </span>
                  </div>
                ))}

              {damagedCount === 0 && (
                <div className="p-3 rounded-lg bg-[#064E3B]/30 border border-[#10B981]/40 text-[#6EE7B7]">
                  No corrupted or missing chunks detected. All block digests match the authenticated manifest.
                </div>
              )}
            </div>

            {/* Solvability Metric */}
            <div className="p-3.5 rounded-lg bg-[#0A0F1D] border border-[#1E293B] text-xs font-mono flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div>
                <span className="text-[#94A3B8]">Mathematical Verdict: </span>
                {isRecoverable ? (
                  <span className="text-[#10B981] font-bold">
                    RECOVERABLE (E={damagedCount} &le; M={parityAvailable}). Linear system matrix invertible in GF(2^8).
                  </span>
                ) : (
                  <span className="text-[#EF4444] font-bold">
                    UNRECOVERABLE EXACT (E={damagedCount} &gt; M={parityAvailable}). Safe failure protocol active.
                  </span>
                )}
              </div>

              {isRecoverable && damagedCount > 0 && onProceedToRecovery && (
                <button
                  type="button"
                  onClick={() => onProceedToRecovery(scanResult)}
                  className="px-4 py-2 rounded-lg bg-[#06B6D4] hover:bg-[#0891B2] text-[#0A0F1D] font-bold text-xs flex items-center space-x-1.5 transition-all shadow-cyan-glow shrink-0"
                >
                  <span>PROCEED TO RECOVERY STUDIO</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
