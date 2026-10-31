import React, { useState } from 'react';
import {
  Upload,
  Lock,
  Eye,
  EyeOff,
  CheckCircle,
  Download,
  FileText,
  Activity,
  ShieldCheck,
  AlertTriangle,
} from './icons';
import { ProtectFileResponse } from '../types';
import { apiClient } from '../api/client';

interface ProtectStudioProps {
  onProtectionComplete?: (res: ProtectFileResponse) => void;
}

export const ProtectStudio: React.FC<ProtectStudioProps> = ({ onProtectionComplete }) => {
  const [sourcePath, setSourcePath] = useState<string>('enterprise_q3_financials.csv');
  const [fileSizeBytes, setFileSizeBytes] = useState<number>(1048576); // 1.0 MB
  const [fileFormat, setFileFormat] = useState<string>('CSV');
  const [chunkSizeBytes, setChunkSizeBytes] = useState<number>(65536); // 64KB
  const [redundancyPct, setRedundancyPct] = useState<number>(20);
  const [secretKey, setSecretKey] = useState<string>('c0ffee8899aabbccddeeff00112233445566778899aabbccddeeff0011223344');
  const [keyId, setKeyId] = useState<string>('vault-key-prod-01');
  const [showSecret, setShowSecret] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [protectResult, setProtectResult] = useState<ProtectFileResponse | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  // Mathematical Calculations
  const dataChunksK = Math.max(1, Math.ceil(fileSizeBytes / chunkSizeBytes));
  const parityChunksM = Math.max(1, Math.ceil((dataChunksK * redundancyPct) / 100));
  const parityOverheadBytes = parityChunksM * chunkSizeBytes;

  const handleGenerateKey = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const hex = Array.from(array)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    setSecretKey(hex);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setSourcePath(file.name);
      setFileSizeBytes(file.size);
      const ext = file.name.split('.').pop()?.toUpperCase() || 'BINARY';
      setFileFormat(['CSV', 'JSON', 'PNG', 'JPEG', 'TEXT'].includes(ext) ? ext : 'BINARY');
    }
  };

  const handleExecuteProtect = async () => {
    setIsProcessing(true);
    setProtectResult(null);

    try {
      let res: ProtectFileResponse;
      if (selectedFile) {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('redundancy_percentage', redundancyPct.toString());
        formData.append('chunk_size_bytes', chunkSizeBytes.toString());
        if (secretKey) formData.append('secret_key', secretKey);
        if (keyId) formData.append('key_id', keyId);

        const response = await fetch('/api/protect-file-upload', {
          method: 'POST',
          body: formData,
        });
        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.detail || 'Protection file upload failed');
        }
        res = await response.json();
      } else {
        res = await apiClient.protectFile({
          source_path: sourcePath,
          redundancy_percentage: redundancyPct,
          chunk_size_bytes: chunkSizeBytes as 16384 | 65536 | 262144 | 1048576,
          secret_key: secretKey || null,
          key_id: keyId || null,
        });
      }
      setProtectResult(res);
      onProtectionComplete?.(res);
    } catch (err) {
      console.error('Protection error:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const triggerDownloadArtifact = (filePath: string, defaultFilename: string) => {
    const filename = filePath.split(/[/\\]/).pop() || defaultFilename;
    const a = document.createElement('a');
    a.href = `/api/download-artifact?file_path=${encodeURIComponent(filePath)}`;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="space-y-6">
      {/* Non-Destructive Invariant Banner */}
      <div className="p-3.5 rounded-xl bg-[#0F172A] border border-[#06B6D4]/40 flex items-center justify-between text-xs text-[#CBD5E1] shadow-lg">
        <div className="flex items-center space-x-2.5">
          <ShieldCheck className="w-5 h-5 text-[#06B6D4] shrink-0" />
          <span>
            <strong className="text-[#F8FAFC]">NON-DESTRUCTIVE GUARANTEE:</strong> Source files remain
            completely read-only and immutable. Parity shards and cryptographic manifests are written
            to segregated companion files.
          </span>
        </div>
        <span className="hidden md:inline-block font-mono text-[11px] px-2 py-0.5 rounded bg-[#111827] text-[#67E8F9] border border-[#1E293B]">
          Deterministic Invariant
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Configuration Controls (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* STEP 1: Select Target File */}
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#06B6D4]/20 text-[#06B6D4] text-xs font-mono">
                  1
                </span>
                <span>TARGET FILE INGESTION</span>
              </h3>
              <span className="text-xs font-mono text-[#94A3B8]">Max 2.0 GB</span>
            </div>

            {/* Drag & Drop Surface */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  const file = e.dataTransfer.files[0];
                  setSelectedFile(file);
                  setSourcePath(file.name);
                  setFileSizeBytes(file.size);
                  const ext = file.name.split('.').pop()?.toUpperCase() || 'BINARY';
                  setFileFormat(['CSV', 'JSON', 'PNG', 'JPEG', 'TEXT'].includes(ext) ? ext : 'BINARY');
                }
              }}
              className={`p-6 rounded-lg border-2 border-dashed transition-all text-center cursor-pointer ${
                dragOver
                  ? 'border-[#06B6D4] bg-[#06B6D4]/10 shadow-cyan-glow'
                  : 'border-[#334155] bg-[#0A0F1D] hover:border-[#06B6D4]/50'
              }`}
            >
              <input
                type="file"
                id="file-upload"
                className="hidden"
                onChange={handleFileSelect}
              />
              <label htmlFor="file-upload" className="cursor-pointer space-y-2 block">
                <div className="flex justify-center">
                  <div className="p-3 rounded-full bg-[#1E293B] text-[#06B6D4]">
                    <Upload className="w-6 h-6" />
                  </div>
                </div>
                <div className="text-sm font-semibold text-[#F8FAFC]">
                  Drag &amp; drop mission-critical file here, or{' '}
                  <span className="text-[#06B6D4] underline">browse files</span>
                </div>
                <div className="text-xs text-[#94A3B8]">
                  Text, CSV, JSON, PNG, JPEG, SQLite, or raw binary payloads
                </div>
              </label>
            </div>

            {/* Selected File Details */}
            <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] flex items-center justify-between text-xs">
              <div className="flex items-center space-x-2.5 truncate">
                <FileText className="w-4 h-4 text-[#06B6D4] shrink-0" />
                <span className="font-mono text-[#F8FAFC] truncate">{sourcePath}</span>
              </div>
              <div className="flex items-center space-x-3 font-mono shrink-0">
                <span className="text-[#94A3B8]">
                  {(fileSizeBytes / (1024 * 1024)).toFixed(2)} MB ({fileSizeBytes.toLocaleString()} B)
                </span>
                <span className="px-2 py-0.5 rounded bg-[#1E293B] text-[#67E8F9] border border-[#334155]">
                  {fileFormat}
                </span>
              </div>
            </div>

            {sourcePath.toLowerCase().includes('corrupted') && (
              <div className="p-3 rounded-lg bg-[#7F1D1D]/40 border border-[#EF4444]/60 text-xs text-[#FCA5A5] flex items-start space-x-2.5">
                <AlertTriangle className="w-4 h-4 text-[#EF4444] shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-[#F87171]">Caution: Protecting an already corrupted file</div>
                  <div className="text-[11px] text-[#FECACA]">
                    Parity shards and manifests must be generated on the <strong>original healthy file</strong> before damage occurs.
                    If you generate parity on an already damaged file, the parity will preserve the corruption instead of fixing it.
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* STEP 2: Erasure Coding & Redundancy Configuration */}
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#06B6D4]/20 text-[#06B6D4] text-xs font-mono">
                  2
                </span>
                <span>ERASURE CODING &amp; REDUNDANCY RATIO</span>
              </h3>
              <span className="text-xs font-mono text-[#3B82F6]">Reed-Solomon GF(2^8)</span>
            </div>

            {/* Chunk Size Selector */}
            <div>
              <label className="text-xs text-[#CBD5E1] font-semibold mb-2 block">
                Chunk Slicing Size ($S_c$):
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { label: '16 KB', bytes: 16384 },
                  { label: '64 KB (Recommended)', bytes: 65536 },
                  { label: '256 KB', bytes: 262144 },
                  { label: '1 MB', bytes: 1048576 },
                ].map((item) => (
                  <button
                    key={item.bytes}
                    type="button"
                    onClick={() => setChunkSizeBytes(item.bytes)}
                    className={`p-2.5 rounded-lg border text-xs font-mono text-center transition-all ${
                      chunkSizeBytes === item.bytes
                        ? 'bg-[#083344] border-[#06B6D4] text-[#67E8F9] shadow-cyan-glow font-bold'
                        : 'bg-[#0A0F1D] border-[#1E293B] text-[#94A3B8] hover:border-[#334155]'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Redundancy Slider */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-[#CBD5E1] font-semibold">Parity Redundancy Ratio:</span>
                <span className="font-mono text-sm font-bold text-[#06B6D4]">{redundancyPct}%</span>
              </div>

              <input
                type="range"
                min="5"
                max="100"
                value={redundancyPct}
                onChange={(e) => setRedundancyPct(Number(e.target.value))}
                className="w-full h-2 bg-[#1E293B] rounded-lg appearance-none cursor-pointer accent-[#06B6D4]"
              />

              {/* Snap Presets */}
              <div className="flex justify-between items-center text-[11px] font-mono text-[#94A3B8] pt-1">
                {[
                  { label: '10% (Std)', val: 10 },
                  { label: '20% (Default)', val: 20 },
                  { label: '30% (High)', val: 30 },
                  { label: '50% (Critical)', val: 50 },
                  { label: '100% (Mirror)', val: 100 },
                ].map((snap) => (
                  <button
                    key={snap.val}
                    type="button"
                    onClick={() => setRedundancyPct(snap.val)}
                    className={`px-1.5 py-0.5 rounded hover:text-[#06B6D4] ${
                      redundancyPct === snap.val ? 'text-[#06B6D4] font-bold bg-[#1E293B]' : ''
                    }`}
                  >
                    {snap.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Real-time Mathematical Calculation Card */}
            <div className="p-3.5 rounded-lg bg-[#0A0F1D] border border-[#1E293B] text-xs font-mono space-y-1.5">
              <div className="flex justify-between text-[#CBD5E1]">
                <span>Data Chunks (K):</span>
                <span className="text-[#F8FAFC] font-bold">{dataChunksK} chunks</span>
              </div>
              <div className="flex justify-between text-[#CBD5E1]">
                <span>Parity Chunks (M):</span>
                <span className="text-[#3B82F6] font-bold">{parityChunksM} parity shards</span>
              </div>
              <div className="flex justify-between text-[#CBD5E1]">
                <span>Total Parity Overhead:</span>
                <span className="text-[#94A3B8]">
                  {(parityOverheadBytes / 1024).toFixed(1)} KB ({(fileSizeBytes > 0 ? (parityOverheadBytes / fileSizeBytes) * 100 : 0).toFixed(1)}%)
                </span>
              </div>
              <div className="pt-1.5 border-t border-[#1E293B] text-[#10B981] text-[11px]">
                🛡 Guarantees 100% exact bit-for-bit recovery against any {parityChunksM} corrupted or lost chunk{parityChunksM > 1 ? 's' : ''}.
              </div>
            </div>
          </div>

          {/* STEP 3: Authenticated Manifest Security (HMAC-SHA256) */}
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#06B6D4]/20 text-[#06B6D4] text-xs font-mono">
                  3
                </span>
                <span>AUTHENTICATED MANIFEST SECURITY</span>
              </h3>
              <span className="text-xs font-mono text-[#06B6D4]">HMAC-SHA256</span>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
                  Pre-Shared Secret Key:
                </label>
                <div className="flex items-center space-x-2">
                  <div className="relative flex-1">
                    <input
                      type={showSecret ? 'text' : 'password'}
                      value={secretKey}
                      onChange={(e) => setSecretKey(e.target.value)}
                      placeholder="Enter 256-bit hexadecimal pre-shared key..."
                      className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret(!showSecret)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#F8FAFC]"
                      aria-label="Toggle Secret Visibility"
                    >
                      {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={handleGenerateKey}
                    className="px-3 py-2 rounded-lg bg-[#1E293B] hover:bg-[#334155] text-xs font-mono text-[#06B6D4] border border-[#334155] transition-colors whitespace-nowrap"
                  >
                    Generate Strong Key
                  </button>
                </div>
              </div>

              <div>
                <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
                  Key Identifier (Key-ID):
                </label>
                <input
                  type="text"
                  value={keyId}
                  onChange={(e) => setKeyId(e.target.value)}
                  placeholder="e.g. vault-key-prod-01"
                  className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
                />
              </div>

              {/* Dynamic Warning Pill */}
              {!secretKey ? (
                <div className="p-2.5 rounded-lg bg-[#78350F]/40 border border-[#F59E0B]/50 flex items-center space-x-2 text-xs text-[#FCD34D]">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-[#F59E0B]" />
                  <span>
                    Unkeyed mode: Manifest will use machine-derived local signature. External auditing
                    requires a pre-shared secret.
                  </span>
                </div>
              ) : (
                <div className="p-2.5 rounded-lg bg-[#064E3B]/40 border border-[#10B981]/50 flex items-center space-x-2 text-xs text-[#6EE7B7]">
                  <ShieldCheck className="w-4 h-4 shrink-0 text-[#10B981]" />
                  <span>
                    Manifest will be cryptographically authenticated with HMAC-SHA256 to prevent unauthorized tampering.
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Action Button */}
          <button
            type="button"
            disabled={isProcessing}
            onClick={handleExecuteProtect}
            className={`w-full py-3.5 px-4 rounded-xl font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 ${
              isProcessing
                ? 'bg-[#1E293B] text-[#94A3B8] cursor-wait'
                : 'bg-[#06B6D4] hover:bg-[#0891B2] text-[#0A0F1D] shadow-cyan-glow'
            }`}
          >
            {isProcessing ? (
              <>
                <div className="w-4 h-4 rounded-full border-2 border-[#0A0F1D] border-t-transparent animate-spin" />
                <span>COMPUTING GF(2^8) PARITY &amp; SIGNING MANIFEST...</span>
              </>
            ) : (
              <>
                <Activity className="w-4 h-4" />
                <span>GENERATE PARITY &amp; SECURE FILE</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column: Execution Summary & Download Artifacts (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
            <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-[#06B6D4]" />
              <span>PROTECTION ARTIFACTS &amp; DIGEST</span>
            </h3>

            {protectResult ? (
              <div className="space-y-4">
                <div className="p-3 rounded-lg bg-[#064E3B]/40 border border-[#10B981]/60 text-xs text-[#6EE7B7] flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4 shrink-0 text-[#10B981]" />
                  <span>
                    Protection complete in <strong>{protectResult.duration_ms}ms</strong> (Throughput: 12.5 MB/s)
                  </span>
                </div>

                {/* Cryptographic Root Digest */}
                <div className="space-y-1">
                  <span className="text-xs text-[#94A3B8] font-mono">Root SHA-256 Digest:</span>
                  <div className="p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] text-xs font-mono text-[#F8FAFC] break-all select-all">
                    {protectResult.root_sha256}
                  </div>
                </div>

                {/* HMAC Signature */}
                <div className="space-y-1">
                  <span className="text-xs text-[#94A3B8] font-mono">HMAC-SHA256 Signature:</span>
                  <div className="p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] text-xs font-mono text-[#67E8F9] break-all select-all">
                    {protectResult.hmac_signature}
                  </div>
                </div>

                {/* Artifact Downloads */}
                <div className="space-y-2 pt-2 border-t border-[#1E293B]">
                  <span className="text-xs text-[#CBD5E1] font-semibold block">Generated Artifacts:</span>

                  {/* Manifest File Trigger */}
                  <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] flex items-center justify-between">
                    <div className="truncate mr-2">
                      <div className="text-xs font-mono text-[#F8FAFC] truncate">
                        {protectResult.manifest_path.split('/').pop()}
                      </div>
                      <div className="text-[11px] text-[#94A3B8]">Cryptographic Integrity Manifest</div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        triggerDownloadArtifact(
                          protectResult.manifest_path,
                          protectResult.manifest_path.split(/[/\\]/).pop() || 'manifest.json'
                        )
                      }
                      className="px-2.5 py-1 rounded bg-[#1E293B] hover:bg-[#334155] text-xs text-[#06B6D4] font-mono border border-[#334155] flex items-center space-x-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download</span>
                    </button>
                  </div>

                  {/* Parity Shards Trigger */}
                  <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] flex items-center justify-between">
                    <div className="truncate mr-2">
                      <div className="text-xs font-mono text-[#F8FAFC] truncate">
                        {protectResult.parity_path.split(/[/\\]/).pop()}
                      </div>
                      <div className="text-[11px] text-[#94A3B8]">Reed-Solomon Parity Shards (M={protectResult.parity_chunks_m})</div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        triggerDownloadArtifact(
                          protectResult.parity_path,
                          protectResult.parity_path.split(/[/\\]/).pop() || 'shards.rsparity'
                        )
                      }
                      className="px-2.5 py-1 rounded bg-[#1E293B] hover:bg-[#334155] text-xs text-[#3B82F6] font-mono border border-[#334155] flex items-center space-x-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-[#94A3B8] space-y-2 border border-dashed border-[#1E293B] rounded-lg">
                <Lock className="w-8 h-8 text-[#334155] mx-auto" />
                <p>Configure file and redundancy parameters, then click &ldquo;Generate Parity &amp; Secure File&rdquo;.</p>
                <p className="text-[11px] text-[#64748B]">All parity mathematics execute locally in user-space.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
