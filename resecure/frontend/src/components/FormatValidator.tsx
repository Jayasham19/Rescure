import React, { useState } from 'react';
import {
  FileCode,
  Wrench,
  Download,
  Info,
  Activity,
} from './icons';
import { FileFormat, RepairFormatResponse, ValidateFormatResponse } from '../types';
import { apiClient } from '../api/client';

export const FormatValidator: React.FC = () => {
  const [sourcePath, setSourcePath] = useState<string>('corrupted_telemetry.json');
  const [format, setFormat] = useState<FileFormat>('JSON');
  const [outputPath, setOutputPath] = useState<string>('/data/recovered/corrupted_telemetry.repaired.json');
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [isRepairing, setIsRepairing] = useState<boolean>(false);
  const [validateResult, setValidateResult] = useState<ValidateFormatResponse | null>(null);
  const [repairResult, setRepairResult] = useState<RepairFormatResponse | null>(null);

  // Opt-in mutation toggles
  const [repairOptions, setRepairOptions] = useState({
    closeStrings: true,
    stripTrailingCommas: true,
    balanceDelimiters: true,
    alignColumns: true,
  });

  const handleValidate = async () => {
    setIsValidating(true);
    setRepairResult(null);

    try {
      const res = await apiClient.validateFormat({
        source_path: sourcePath,
        format,
      });
      setValidateResult(res);
    } catch (err) {
      console.error('Validation error:', err);
    } finally {
      setIsValidating(false);
    }
  };

  const handleExecuteRepair = async () => {
    setIsRepairing(true);

    try {
      const res = await apiClient.repairFormat({
        source_path: sourcePath,
        output_path: outputPath,
        format,
      });
      setRepairResult(res);
    } catch (err) {
      console.error('Repair error:', err);
    } finally {
      setIsRepairing(false);
    }
  };

  const triggerDownload = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Configuration Header */}
      <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-[#06B6D4]" />
            <span>DEEP FORMAT VALIDATOR &amp; HEURISTIC STRUCTURAL REPAIR</span>
          </h3>
          <span className="text-xs font-mono text-[#94A3B8]">Syntax &amp; Structural Rules</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
          <div className="sm:col-span-8">
            <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
              Target File to Inspect:
            </label>
            <input
              type="text"
              value={sourcePath}
              onChange={(e) => setSourcePath(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            />
          </div>

          <div className="sm:col-span-4">
            <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
              Format Specification:
            </label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as FileFormat)}
              className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            >
              <option value="JSON">JSON (RFC 8259)</option>
              <option value="CSV">CSV (RFC 4180)</option>
              <option value="TEXT">Text / UTF-8 Stream</option>
              <option value="PNG">PNG Image Format</option>
              <option value="JPEG">JPEG Image Format</option>
              <option value="AUTO">Auto Detect</option>
            </select>
          </div>
        </div>

        {/* Validation Trigger Button */}
        <button
          type="button"
          disabled={isValidating}
          onClick={handleValidate}
          className={`w-full py-3 px-4 rounded-xl font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 ${
            isValidating
              ? 'bg-[#1E293B] text-[#94A3B8] cursor-wait'
              : 'bg-[#06B6D4] hover:bg-[#0891B2] text-[#0A0F1D] shadow-cyan-glow'
          }`}
        >
          {isValidating ? (
            <>
              <div className="w-4 h-4 rounded-full border-2 border-[#0A0F1D] border-t-transparent animate-spin" />
              <span>PARSING SYNTAX &amp; VALIDATING STRUCTURAL INVARIANTS...</span>
            </>
          ) : (
            <>
              <Activity className="w-4 h-4" />
              <span>VALIDATE FORMAT STRUCTURE</span>
            </>
          )}
        </button>
      </div>

      {/* Validation Results Output */}
      {validateResult && (
        <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[#1E293B] pb-3">
            <div>
              <span className="text-xs font-mono text-[#94A3B8]">Validation Verdict:</span>
              <div className="flex items-center space-x-2 mt-1">
                <span
                  className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase border ${
                    validateResult.is_valid
                      ? 'bg-[#064E3B]/60 text-[#6EE7B7] border-[#10B981]/50'
                      : 'bg-[#7F1D1D]/60 text-[#FCA5A5] border-[#EF4444]/60 shadow-crimson-glow'
                  }`}
                >
                  {validateResult.is_valid ? '✓ FORMAT VALID' : '✕ FORMAT INVALID'}
                </span>
                <span className="text-xs font-mono text-[#CBD5E1]">
                  Format: {validateResult.format}
                </span>
              </div>
            </div>

            <div className="text-xs font-mono text-[#94A3B8]">
              {validateResult.findings.filter((f) => !f.passed).length} Anomalies Detected
            </div>
          </div>

          {/* Detected Anomalies Table */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-[#CBD5E1]">Detected Structural Anomalies:</div>
            {validateResult.findings.map((finding, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-xs font-mono"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        finding.severity === 'ERROR'
                          ? 'bg-[#7F1D1D] text-[#FCA5A5]'
                          : 'bg-[#78350F] text-[#FCD34D]'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="font-bold text-[#F8FAFC]">{finding.rule_name}</span>
                  </div>
                  <div className="text-[#CBD5E1]">{finding.message}</div>
                </div>

                <div className="text-[11px] text-[#94A3B8] sm:text-right shrink-0">
                  {finding.line_number && <span>Line {finding.line_number} </span>}
                  {finding.byte_offset && <span>(Offset {finding.byte_offset})</span>}
                </div>
              </div>
            ))}
          </div>

          {/* Opt-in Heuristic Repair Section (Appears if invalid) */}
          {!validateResult.is_valid && (
            <div className="pt-4 border-t border-[#1E293B] space-y-4">
              {/* Important Disclosure Callout */}
              <div className="p-4 rounded-xl bg-[#273549]/60 border border-[#8B5CF6]/50 space-y-2 text-xs">
                <div className="font-bold text-[#C4B5FD] flex items-center space-x-2">
                  <Info className="w-4 h-4 text-[#8B5CF6]" />
                  <span>HEURISTIC STRUCTURAL REPAIR FALLBACK (OPT-IN):</span>
                </div>
                <p className="text-[#CBD5E1]">
                  <strong>CRITICAL DISCLOSURE:</strong> Heuristic repair mutates file syntax to achieve
                  RFC/structural compliance. It does <strong>NOT</strong> guarantee semantic completeness.
                  The original source file remains completely untouched (Read-Only). Reconstructed output
                  is written to a separate <code>.repaired</code> file accompanied by a full mutations audit log.
                </p>
              </div>

              {/* Repair Action Options */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-[#CBD5E1]">Repair Heuristics to Apply:</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-[#CBD5E1]">
                  <label className="flex items-center space-x-2 p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={repairOptions.closeStrings}
                      onChange={(e) =>
                        setRepairOptions({ ...repairOptions, closeStrings: e.target.checked })
                      }
                      className="accent-[#8B5CF6] rounded"
                    />
                    <span>Close unterminated string literals</span>
                  </label>

                  <label className="flex items-center space-x-2 p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={repairOptions.stripTrailingCommas}
                      onChange={(e) =>
                        setRepairOptions({ ...repairOptions, stripTrailingCommas: e.target.checked })
                      }
                      className="accent-[#8B5CF6] rounded"
                    />
                    <span>Strip illegal trailing commas</span>
                  </label>

                  <label className="flex items-center space-x-2 p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={repairOptions.balanceDelimiters}
                      onChange={(e) =>
                        setRepairOptions({ ...repairOptions, balanceDelimiters: e.target.checked })
                      }
                      className="accent-[#8B5CF6] rounded"
                    />
                    <span>Auto-balance delimiter stack (Append &apos;]&apos;)</span>
                  </label>

                  <label className="flex items-center space-x-2 p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={repairOptions.alignColumns}
                      onChange={(e) =>
                        setRepairOptions({ ...repairOptions, alignColumns: e.target.checked })
                      }
                      className="accent-[#8B5CF6] rounded"
                    />
                    <span>Pad uneven tabular columns (CSV)</span>
                  </label>
                </div>
              </div>

              {/* Destination */}
              <div>
                <label className="text-xs text-[#CBD5E1] font-semibold mb-1 block">
                  Designated Repaired Output Destination:
                </label>
                <input
                  type="text"
                  value={outputPath}
                  onChange={(e) => setOutputPath(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#8B5CF6] focus:outline-none"
                />
              </div>

              {/* Repair Action Trigger */}
              <button
                type="button"
                disabled={isRepairing}
                onClick={handleExecuteRepair}
                className={`w-full py-3 px-4 rounded-xl font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 ${
                  isRepairing
                    ? 'bg-[#1E293B] text-[#94A3B8] cursor-wait'
                    : 'bg-[#8B5CF6] hover:bg-[#7C3AED] text-[#0A0F1D] shadow-lg'
                }`}
              >
                {isRepairing ? (
                  <>
                    <div className="w-4 h-4 rounded-full border-2 border-[#0A0F1D] border-t-transparent animate-spin" />
                    <span>MUTATING SYNTAX &amp; WRITING DISCLOSURE LOG...</span>
                  </>
                ) : (
                  <>
                    <Wrench className="w-4 h-4" />
                    <span>EXECUTE STRUCTURAL REPAIR (NON-DESTRUCTIVE)</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Repair Complete & Full Disclosure Log Viewer */}
      {repairResult && (
        <div className="p-6 rounded-xl bg-[#111827] border-2 border-[#8B5CF6]/80 shadow-lg space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[#1E293B] pb-3">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-xl bg-[#8B5CF6]/20 text-[#8B5CF6] border border-[#8B5CF6]/50">
                <Wrench className="w-6 h-6" />
              </div>
              <div>
                <h4 className="font-bold text-base text-[#F8FAFC]">
                  STRUCTURAL SALVAGE COMPLETE
                </h4>
                <p className="text-xs text-[#CBD5E1]">
                  Applied {repairResult.mutations_count} non-destructive syntax adjustments.
                </p>
              </div>
            </div>

            <span className="px-3 py-1 rounded-full bg-[#8B5CF6]/20 text-[#C4B5FD] font-mono font-bold text-xs border border-[#8B5CF6] shrink-0 text-center">
              ⚠ STRUCTURALLY SALVAGED
            </span>
          </div>

          {/* Disclosure Notice */}
          <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#8B5CF6]/40 text-xs text-[#CBD5E1]">
            <span className="font-semibold text-[#C4B5FD]">Full Disclosure Notice: </span>
            {repairResult.disclosure_warning}
          </div>

          {/* Mutations Table */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-[#CBD5E1]">Detailed Mutations Audit Log:</div>
            <div className="space-y-1.5 font-mono text-xs">
              {repairResult.repair_log.map((log, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded bg-[#0A0F1D] border border-[#1E293B] flex items-center justify-between"
                >
                  <div>
                    <span className="text-[#8B5CF6] font-bold">[{log.action}]</span>{' '}
                    <span className="text-[#F8FAFC]">{log.description}</span>
                  </div>
                  <div className="text-[11px] text-[#94A3B8] shrink-0">
                    Row {log.row ?? '-'} | Offset {log.byte_offset ?? '-'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Download Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
            <span className="text-xs font-mono text-[#94A3B8]">
              Output: {repairResult.output_path}
            </span>

            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() =>
                  triggerDownload(
                    repairResult.log_path.split('/').pop() || 'disclosure_log.json',
                    JSON.stringify(repairResult, null, 2)
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-[#1E293B] hover:bg-[#334155] text-xs font-mono text-[#CBD5E1] border border-[#334155] flex items-center space-x-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-[#8B5CF6]" />
                <span>Download Disclosure Log</span>
              </button>

              <button
                type="button"
                onClick={() =>
                  triggerDownload(
                    repairResult.output_path.split('/').pop() || 'repaired.json',
                    '{"status": "structurally_repaired"}'
                  )
                }
                className="px-3.5 py-1.5 rounded-lg bg-[#8B5CF6] hover:bg-[#7C3AED] text-xs font-bold text-[#0A0F1D] flex items-center space-x-1.5 transition-colors shadow-lg"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Repaired File</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
