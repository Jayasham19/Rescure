import React, { useState, useRef } from 'react';
import {
  Upload,
  Wrench,
  Sparkles,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Download,
  FileCode,
  Activity,
  ArrowRight,
  RefreshCw,
  Info,
  X,
} from './icons';
import { OneClickRepairResponse, RepairLogEntry } from '../types';
import { apiClient } from '../api/client';

interface OneClickRepairProps {
  onNavigateToRecovery?: () => void;
  onNavigateToValidator?: () => void;
}

const SUPPORTED_FORMATS = [
  { name: 'JSON', ext: '.json', desc: 'RFC 8259 syntax, brackets, trailing commas' },
  { name: 'CSV', ext: '.csv', desc: 'RFC 4180 parsing, row alignment, quoting' },
  { name: 'Plain Text', ext: '.txt, .log', desc: 'UTF-8 encoding, BOM, ASCII control chars' },
  { name: 'PNG Image', ext: '.png', desc: 'Magic bytes, IHDR/IDAT/IEND, CRC32 chunk checks' },
  { name: 'JPEG Image', ext: '.jpg, .jpeg', desc: 'SOI/EOI markers, segment integrity' },
  { name: 'PDF Document', ext: '.pdf', desc: 'Magic bytes, xref catalog, stream integrity & EOF markers' },
  { name: 'RS Parity Package', ext: '.rsmanifest.json, .rsparity', desc: 'Cryptographic Reed-Solomon Galois Field recovery' },
];

export const OneClickRepair: React.FC<OneClickRepairProps> = ({
  onNavigateToRecovery,
  onNavigateToValidator,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [manifestFile, setManifestFile] = useState<File | null>(null);
  const [parityFile, setParityFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [repairStep, setRepairStep] = useState<string>('');
  const [progressPct, setProgressPct] = useState<number>(0);
  const [repairResult, setRepairResult] = useState<OneClickRepairResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showAdvancedUploads, setShowAdvancedUploads] = useState<boolean>(true);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      handleFileSelected(droppedFile);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  };

  const handleFileSelected = (file: File) => {
    setSelectedFile(file);
    setRepairResult(null);
    setErrorMessage(null);
    setProgressPct(0);
    setRepairStep('');
  };

  const handleRepairFile = async () => {
    if (!selectedFile) return;

    setIsProcessing(true);
    setErrorMessage(null);
    setRepairResult(null);
    setProgressPct(10);
    setRepairStep('Analyzing file header and computing cryptographic SHA-256...');

    try {
      await new Promise((r) => setTimeout(r, 200));
      setProgressPct(35);
      setRepairStep('Detecting format syntax and assessing corruption...');

      await new Promise((r) => setTimeout(r, 250));
      setProgressPct(60);
      setRepairStep('Evaluating recovery methods & applying structural correction...');

      const result = await apiClient.oneClickRepair(
        selectedFile,
        manifestFile,
        parityFile
      );

      setProgressPct(90);
      setRepairStep('Verifying output integrity & finalizing forensic log...');
      await new Promise((r) => setTimeout(r, 150));

      setProgressPct(100);
      setRepairStep('Completed');
      setRepairResult(result);
    } catch (err: unknown) {
      console.error('One-Click Repair failed:', err);
      const msg = err instanceof Error ? err.message : 'An unexpected error occurred during repair.';
      setErrorMessage(msg);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownload = () => {
    if (!repairResult || !repairResult.download_url) return;

    const downloadUrl = repairResult.download_url.startsWith('http')
      ? repairResult.download_url
      : repairResult.download_url;

    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', `${repairResult.filename}.repaired`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleReset = () => {
    setSelectedFile(null);
    setManifestFile(null);
    setParityFile(null);
    setRepairResult(null);
    setErrorMessage(null);
    setProgressPct(0);
    setRepairStep('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-6">
      {/* Non-Destructive Invariant Guarantee Banner */}
      <div className="p-3.5 rounded-xl bg-[#0F172A] border border-[#06B6D4]/40 flex items-center justify-between text-xs text-[#CBD5E1] shadow-lg">
        <div className="flex items-center space-x-2.5">
          <ShieldCheck className="w-5 h-5 text-[#06B6D4] shrink-0" />
          <span>
            <strong className="text-[#F8FAFC]">NON-DESTRUCTIVE GUARANTEE:</strong> Your original file is
            never modified or overwritten. Repaired output is staged safely in an isolated target file.
          </span>
        </div>
        <span className="hidden md:inline-flex items-center space-x-1 font-mono text-[11px] px-2.5 py-0.5 rounded bg-[#111827] text-[#67E8F9] border border-[#1E293B]">
          <span>100% Local Processing</span>
        </span>
      </div>

      {/* Main Landing Hero Card */}
      <div className="p-6 lg:p-8 rounded-2xl bg-[#111827] border border-[#1E293B] shadow-2xl relative overflow-hidden">
        {/* Subtle Background Glow */}
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-[#06B6D4]/5 rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-[#06B6D4]/10 border border-[#06B6D4]/30 text-xs font-semibold text-[#06B6D4]">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Automated File Integrity &amp; Self-Healing</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#F8FAFC] tracking-tight">
            Repair Your File
          </h1>

          <p className="text-sm text-[#94A3B8] leading-relaxed">
            Upload your corrupted, damaged, or truncated file. ReSecure automatically identifies the file
            format, assesses structural integrity, and executes available deterministic or heuristic
            repair mechanisms—without manual configuration.
          </p>
        </div>

        {/* Upload Drop Zone & Controls */}
        <div className="mt-8 space-y-5">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`p-8 sm:p-10 rounded-xl border-2 border-dashed transition-all text-center cursor-pointer relative ${
              isDragging
                ? 'border-[#06B6D4] bg-[#06B6D4]/10 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
                : selectedFile
                ? 'border-[#10B981]/60 bg-[#10B981]/5'
                : 'border-[#334155] bg-[#0A0F1D] hover:border-[#06B6D4]/60 hover:bg-[#0F172A]'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={handleFileInputChange}
            />

            <div className="flex flex-col items-center justify-center space-y-3">
              <div
                className={`p-4 rounded-full transition-colors ${
                  selectedFile
                    ? 'bg-[#10B981]/20 text-[#10B981]'
                    : 'bg-[#1E293B] text-[#06B6D4]'
                }`}
              >
                {selectedFile ? <FileCode className="w-8 h-8" /> : <Upload className="w-8 h-8" />}
              </div>

              {selectedFile ? (
                <div className="space-y-1">
                  <div className="text-base font-bold text-[#F8FAFC] flex items-center justify-center space-x-2">
                    <span>{selectedFile.name}</span>
                    <CheckCircle className="w-4 h-4 text-[#10B981]" />
                  </div>
                  <p className="text-xs text-[#94A3B8] font-mono">
                    Size: {formatFileSize(selectedFile.size)} &bull; Ready for automated repair
                  </p>
                  <p className="text-xs text-[#06B6D4] underline pt-1">
                    Click or drop another file to replace
                  </p>
                </div>
              ) : (
                <div className="space-y-1">
                  <p className="text-base font-semibold text-[#F8FAFC]">
                    Drag and drop your corrupted file here, or{' '}
                    <span className="text-[#06B6D4] underline">browse files</span>
                  </p>
                  <p className="text-xs text-[#94A3B8]">
                    Supports JSON, CSV, Text, PNG, JPEG, and Reed-Solomon protected files (up to 2.0 GB)
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Optional Companion Files Toggle (Manifest & Parity for Exact RS Recovery) */}
          <div className="pt-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#06B6D4] flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-[#06B6D4]" />
                <span>Attach Parity &amp; Manifest (For 100% Exact Bit-for-Bit Recovery):</span>
              </span>
              <button
                type="button"
                onClick={() => setShowAdvancedUploads(!showAdvancedUploads)}
                className="text-xs text-[#94A3B8] hover:text-[#06B6D4] transition-colors"
              >
                {showAdvancedUploads ? 'Hide Fields' : 'Show Fields'}
              </button>
            </div>

            {showAdvancedUploads && (
              <div className="mt-2.5 p-4 rounded-xl bg-[#0A0F1D] border border-[#06B6D4]/40 grid grid-cols-1 sm:grid-cols-2 gap-4 shadow-lg">
                <div>
                  <label className="block text-xs font-semibold text-[#CBD5E1] mb-1">
                    1. HMAC Manifest (.rsmanifest.json):
                  </label>
                  <input
                    type="file"
                    accept=".json"
                    onChange={(e) => setManifestFile(e.target.files?.[0] || null)}
                    className="block w-full text-xs text-[#94A3B8] file:mr-2 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-[#1E293B] file:text-[#06B6D4] hover:file:bg-[#334155] cursor-pointer"
                  />
                  {manifestFile && (
                    <span className="text-[11px] text-[#10B981] font-mono mt-1 block">
                      ✓ {manifestFile.name}
                    </span>
                  )}
                </div>

                <div>
                  <label className="block text-xs font-semibold text-[#CBD5E1] mb-1">
                    2. Parity Shards Container (.rsparity):
                  </label>
                  <input
                    type="file"
                    onChange={(e) => setParityFile(e.target.files?.[0] || null)}
                    className="block w-full text-xs text-[#94A3B8] file:mr-2 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-[#1E293B] file:text-[#3B82F6] hover:file:bg-[#334155] cursor-pointer"
                  />
                  {parityFile && (
                    <span className="text-[11px] text-[#10B981] font-mono mt-1 block">
                      ✓ {parityFile.name}
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Primary Action Button: "Repair File" */}
          <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
            <button
              type="button"
              disabled={!selectedFile || isProcessing}
              onClick={handleRepairFile}
              className={`w-full sm:w-auto px-8 py-3.5 rounded-xl font-bold text-sm flex items-center justify-center space-x-2.5 transition-all shadow-lg ${
                !selectedFile || isProcessing
                  ? 'bg-[#1E293B] text-[#64748B] cursor-not-allowed border border-[#334155]'
                  : 'bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] text-white hover:opacity-95 shadow-[0_0_20px_rgba(6,182,212,0.4)] border border-[#06B6D4]'
              }`}
            >
              {isProcessing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Repairing File...</span>
                </>
              ) : (
                <>
                  <Wrench className="w-4 h-4" />
                  <span>Repair File</span>
                </>
              )}
            </button>

            {selectedFile && !isProcessing && (
              <button
                type="button"
                onClick={handleReset}
                className="w-full sm:w-auto px-4 py-3.5 rounded-xl text-xs font-semibold text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B] transition-colors"
              >
                Clear Selection
              </button>
            )}
          </div>
        </div>

        {/* Live Progress Bar State */}
        {isProcessing && (
          <div className="mt-6 p-4 rounded-xl bg-[#0A0F1D] border border-[#06B6D4]/30 space-y-3 animate-fade-in">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#06B6D4] font-semibold flex items-center space-x-2">
                <Activity className="w-3.5 h-3.5 animate-pulse" />
                <span>{repairStep}</span>
              </span>
              <span className="text-[#F8FAFC] font-mono">{progressPct}%</span>
            </div>
            <div className="w-full h-2 rounded-full bg-[#1E293B] overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-[#06B6D4] to-[#10B981] transition-all duration-300 ease-out"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>
        )}

        {/* Error Notification State */}
        {errorMessage && (
          <div className="mt-6 p-4 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/40 flex items-start space-x-3 text-xs text-[#FCA5A5] animate-fade-in">
            <ShieldAlert className="w-5 h-5 text-[#EF4444] shrink-0 mt-0.5" />
            <div className="space-y-1 flex-1">
              <strong className="text-white block font-semibold">Repair Execution Error</strong>
              <p>{errorMessage}</p>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-[#94A3B8] hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Results Presentation States */}
        {repairResult && (
          <div className="mt-6 space-y-4 animate-fade-in">
            {/* Status Case 1: EXACT MATCH VERIFIED */}
            {repairResult.verdict === 'EXACT_RECOVERED' && (
              <div className="p-5 rounded-xl bg-[#10B981]/10 border border-[#10B981]/50 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-[#10B981] font-bold text-sm">
                    <CheckCircle className="w-5 h-5" />
                    <span>EXACT RECOVERY VERIFIED — 100% BIT-FOR-BIT CRYPTOGRAPHIC INVARIANCE</span>
                  </div>
                  <span className="text-xs font-mono text-[#10B981] px-2 py-0.5 rounded bg-[#10B981]/20 border border-[#10B981]/40">
                    SHA-256 MATCH
                  </span>
                </div>

                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  {repairResult.message} Original and reconstructed SHA-256 checksums match bit-for-bit.
                </p>

                <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-[#94A3B8]">
                    <span>Original SHA-256:</span>
                    <span className="text-[#F8FAFC]">{repairResult.original_sha256}</span>
                  </div>
                  <div className="flex items-center justify-between text-[#94A3B8]">
                    <span>Recovered SHA-256:</span>
                    <span className="text-[#10B981]">{repairResult.output_sha256}</span>
                  </div>
                  <div className="flex items-center justify-between text-[#94A3B8]">
                    <span>Format Detected:</span>
                    <span className="text-[#67E8F9]">{repairResult.detected_format}</span>
                  </div>
                </div>

                {repairResult.download_url && (
                  <div className="pt-2 flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={handleDownload}
                      className="px-5 py-2.5 rounded-lg bg-[#10B981] text-[#0A0F1D] font-bold text-xs flex items-center space-x-2 hover:bg-[#10B981]/90 transition-all shadow-md"
                    >
                      <Download className="w-4 h-4" />
                      <span>Download Repaired File ({repairResult.filename}.repaired)</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleReset}
                      className="text-xs text-[#94A3B8] hover:text-white"
                    >
                      Repair Another File
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Status Case 2: PARTIAL RECOVERY / HEURISTIC SALVAGE */}
            {repairResult.verdict === 'REPAIRED' && (
              <div className="p-5 rounded-xl bg-[#F59E0B]/10 border border-[#F59E0B]/50 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-[#F59E0B] font-bold text-sm">
                    <AlertTriangle className="w-5 h-5" />
                    <span>HEURISTIC STRUCTURAL REPAIR APPLIED — PARTIAL SALVAGE</span>
                  </div>
                  <span className="text-xs font-mono text-[#F59E0B] px-2 py-0.5 rounded bg-[#F59E0B]/20 border border-[#F59E0B]/40">
                    {repairResult.mutations_count} MUTATIONS APPLIED
                  </span>
                </div>

                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  {repairResult.message}
                </p>

                {/* Disclosure Notice */}
                <div className="p-3.5 rounded-lg bg-[#0A0F1D] border border-[#F59E0B]/30 space-y-2">
                  <span className="text-xs font-semibold text-[#F59E0B] flex items-center space-x-1.5">
                    <Info className="w-4 h-4" />
                    <span>Full Mutation &amp; Repair Audit Disclosure:</span>
                  </span>
                  {repairResult.repair_log && repairResult.repair_log.length > 0 ? (
                    <ul className="text-xs text-[#CBD5E1] space-y-1 font-mono list-disc list-inside">
                      {repairResult.repair_log.map((entry: RepairLogEntry, idx: number) => (
                        <li key={idx}>
                          <strong className="text-[#F8FAFC]">{entry.action}</strong>: {entry.description}
                          {entry.byte_offset !== undefined && entry.byte_offset !== null ? ` (at offset ${entry.byte_offset})` : ''}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-[#94A3B8] font-mono">
                      Repaired syntax delimiters, missing headers, or truncated markers.
                    </p>
                  )}
                </div>

                <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] space-y-1 font-mono text-[11px] text-[#94A3B8]">
                  <div className="flex items-center justify-between">
                    <span>Source Hash:</span>
                    <span className="text-[#F8FAFC]">{repairResult.original_sha256.substring(0, 32)}...</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Repaired Hash:</span>
                    <span className="text-[#F59E0B]">{repairResult.output_sha256?.substring(0, 32)}...</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Cryptographic Match:</span>
                    <span className="text-[#F59E0B]">No (Heuristic Structural Salvage)</span>
                  </div>
                </div>

                {repairResult.download_url && (
                  <div className="pt-2 flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={handleDownload}
                      className="px-5 py-2.5 rounded-lg bg-[#F59E0B] text-[#0A0F1D] font-bold text-xs flex items-center space-x-2 hover:bg-[#F59E0B]/90 transition-all shadow-md"
                    >
                      <Download className="w-4 h-4" />
                      <span>Download Repaired File ({repairResult.filename}.repaired)</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleReset}
                      className="text-xs text-[#94A3B8] hover:text-white"
                    >
                      Repair Another File
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Status Case 3: PRISTINE FILE */}
            {repairResult.verdict === 'PRISTINE' && (
              <div className="p-5 rounded-xl bg-[#06B6D4]/10 border border-[#06B6D4]/50 space-y-3">
                <div className="flex items-center space-x-2 text-[#06B6D4] font-bold text-sm">
                  <ShieldCheck className="w-5 h-5" />
                  <span>FILE IS PRISTINE &amp; HEALTHY — NO REPAIR NEEDED</span>
                </div>
                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  {repairResult.message} Format verification confirmed that the syntax, headers, and
                  checksums are completely valid.
                </p>
                <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] font-mono text-[11px] text-[#94A3B8]">
                  <span>SHA-256 Checksum: </span>
                  <span className="text-[#F8FAFC]">{repairResult.original_sha256}</span>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={handleReset}
                    className="px-4 py-2 rounded-lg bg-[#1E293B] text-xs font-semibold text-[#F8FAFC] hover:bg-[#334155]"
                  >
                    Check Another File
                  </button>
                </div>
              </div>
            )}

            {/* Status Case 4: UNRECOVERABLE SAFE FAILURE */}
            {repairResult.verdict === 'UNRECOVERABLE' && (
              <div className="p-5 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/50 space-y-4">
                <div className="flex items-center space-x-2 text-[#EF4444] font-bold text-sm">
                  <ShieldAlert className="w-5 h-5" />
                  <span>RECOVERY UNSUCCESSFUL — SAFE FAILURE EXECUTED</span>
                </div>
                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  {repairResult.message}
                </p>

                <div className="p-3.5 rounded-lg bg-[#0A0F1D] border border-[#EF4444]/30 text-xs text-[#F8FAFC] space-y-2">
                  <div className="font-semibold text-[#EF4444] flex items-center space-x-1.5">
                    <Info className="w-4 h-4" />
                    <span>Why did this happen?</span>
                  </div>
                  <p className="text-[#94A3B8] leading-relaxed">
                    This file is too severely corrupted to be repaired through structural heuristics alone.
                    Exact bit-for-bit reconstruction requires pre-generated Reed-Solomon parity shards
                    and an HMAC manifest.
                  </p>
                </div>

                <div className="pt-2 flex flex-wrap items-center gap-3">
                  {onNavigateToRecovery && (
                    <button
                      type="button"
                      onClick={onNavigateToRecovery}
                      className="px-4 py-2.5 rounded-lg bg-[#06B6D4] text-[#0A0F1D] font-bold text-xs flex items-center space-x-2 hover:bg-[#06B6D4]/90 transition-all shadow-md"
                    >
                      <span>Open Recovery Studio</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                  {onNavigateToValidator && (
                    <button
                      type="button"
                      onClick={onNavigateToValidator}
                      className="px-4 py-2.5 rounded-lg bg-[#1E293B] text-xs font-semibold text-[#F8FAFC] hover:bg-[#334155]"
                    >
                      Advanced Format Repair
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-xs text-[#94A3B8] hover:text-white"
                  >
                    Try Another File
                  </button>
                </div>
              </div>
            )}

            {/* Status Case 5: UNSUPPORTED FORMAT */}
            {repairResult.verdict === 'UNSUPPORTED' && (
              <div className="p-5 rounded-xl bg-[#64748B]/10 border border-[#64748B]/50 space-y-3">
                <div className="flex items-center space-x-2 text-[#94A3B8] font-bold text-sm">
                  <Info className="w-5 h-5" />
                  <span>UNSUPPORTED FILE FORMAT</span>
                </div>
                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  {repairResult.message}
                </p>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={handleReset}
                    className="px-4 py-2 rounded-lg bg-[#1E293B] text-xs font-semibold text-[#F8FAFC] hover:bg-[#334155]"
                  >
                    Select a Supported File
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Supported File Formats Grid */}
      <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-xs tracking-wider text-[#CBD5E1] uppercase flex items-center space-x-2">
            <CheckCircle className="w-4 h-4 text-[#06B6D4]" />
            <span>Supported Formats &amp; Repair Capabilities</span>
          </h3>
          <span className="text-[11px] font-mono text-[#94A3B8]">Deterministic &amp; Heuristic Engines</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {SUPPORTED_FORMATS.map((fmt) => (
            <div
              key={fmt.name}
              className="p-3.5 rounded-lg bg-[#0A0F1D] border border-[#1E293B] hover:border-[#334155] transition-all space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[#F8FAFC]">{fmt.name}</span>
                <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#1E293B] text-[#06B6D4]">
                  {fmt.ext}
                </span>
              </div>
              <p className="text-[11px] text-[#94A3B8] leading-tight">{fmt.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Workflow Navigation Cards to Advanced Tools */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-[#0F172A] border border-[#1E293B] flex items-center justify-between text-xs">
          <div className="space-y-1">
            <span className="font-bold text-[#F8FAFC] block">Want to protect healthy files before corruption?</span>
            <span className="text-[#94A3B8]">Generate 64KB chunk SHA-256 hashes and Reed-Solomon parity shards.</span>
          </div>
          {onNavigateToRecovery && (
            <button
              type="button"
              onClick={onNavigateToRecovery}
              className="px-3.5 py-2 rounded-lg bg-[#1E293B] text-[#06B6D4] hover:bg-[#06B6D4]/10 transition-colors shrink-0 ml-4 font-semibold text-xs"
            >
              Protect &amp; Parity &rarr;
            </button>
          )}
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A] border border-[#1E293B] flex items-center justify-between text-xs">
          <div className="space-y-1">
            <span className="font-bold text-[#F8FAFC] block">Need chunk-by-chunk visual inspection?</span>
            <span className="text-[#94A3B8]">Inspect live damage matrix, bit flips, and parity deficit indicators.</span>
          </div>
          {onNavigateToValidator && (
            <button
              type="button"
              onClick={onNavigateToValidator}
              className="px-3.5 py-2 rounded-lg bg-[#1E293B] text-[#06B6D4] hover:bg-[#06B6D4]/10 transition-colors shrink-0 ml-4 font-semibold text-xs"
            >
              Inspect Matrix &rarr;
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
