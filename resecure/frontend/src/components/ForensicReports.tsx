import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Download,
  ExternalLink,
} from './icons';
import { ForensicReportResponse, OperationVerdict, RecoveryJobRecord } from '../types';
import { apiClient } from '../api/client';
import { ForensicDrawer } from './ForensicDrawer';

interface ForensicReportsProps {
  initialJobId?: string | null;
}

export const ForensicReports: React.FC<ForensicReportsProps> = ({ initialJobId }) => {
  const [jobs, setJobs] = useState<RecoveryJobRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [selectedReport, setSelectedReport] = useState<ForensicReportResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchJobs = async () => {
      try {
        const records = await apiClient.listJobs();
        setJobs(records);
        if (initialJobId) {
          const report = await apiClient.getForensicReport(initialJobId);
          setSelectedReport(report);
        }
      } catch (err) {
        console.error('Failed to load audit records:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchJobs();
  }, [initialJobId]);

  const handleOpenReport = async (jobId: string) => {
    try {
      const rep = await apiClient.getForensicReport(jobId);
      setSelectedReport(rep);
    } catch (err) {
      console.error('Failed to load report:', err);
    }
  };

  const filteredJobs = jobs.filter((j) => {
    const matchesSearch =
      j.source_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      j.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesVerdict = verdictFilter === 'ALL' || j.verdict === verdictFilter;
    const matchesType = typeFilter === 'ALL' || j.job_type === typeFilter;
    return matchesSearch && matchesVerdict && matchesType;
  });

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(filteredJobs, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `resecure_audit_registry_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    const headers = 'ID,JobType,Status,SourcePath,Verdict,DurationMs,CreatedAt\n';
    const rows = filteredJobs
      .map(
        (j) =>
          `"${j.id}","${j.job_type}","${j.status}","${j.source_path}","${j.verdict || ''}",${
            j.duration_ms || 0
          },"${j.created_at}"`
      )
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `resecure_audit_registry_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getVerdictBadge = (verdict?: OperationVerdict | null) => {
    switch (verdict) {
      case 'VERIFIED_EXACT':
      case 'PRISTINE':
        return (
          <span className="px-2.5 py-0.5 rounded-full bg-[#064E3B]/60 text-[#6EE7B7] border border-[#10B981]/50 font-bold text-[11px] font-mono whitespace-nowrap">
            {verdict}
          </span>
        );
      case 'RECOVERABLE':
      case 'STRUCTURALLY_SALVAGED':
        return (
          <span className="px-2.5 py-0.5 rounded-full bg-[#78350F]/60 text-[#FCD34D] border border-[#F59E0B]/50 font-bold text-[11px] font-mono whitespace-nowrap">
            {verdict}
          </span>
        );
      case 'UNRECOVERABLE_EXACT':
      case 'INTEGRITY_VIOLATION':
        return (
          <span className="px-2.5 py-0.5 rounded-full bg-[#7F1D1D]/60 text-[#FCA5A5] border border-[#EF4444]/60 font-bold text-[11px] font-mono whitespace-nowrap">
            {verdict}
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full bg-[#1E293B] text-[#94A3B8] border border-[#334155] text-[11px] font-mono">
            {verdict || 'PENDING'}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Registry Filter Toolbar */}
      <div className="p-5 rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <h3 className="font-semibold text-sm text-[#F8FAFC] flex items-center space-x-2">
            <FileText className="w-4 h-4 text-[#06B6D4]" />
            <span>FORENSIC AUDIT REGISTRY &amp; OPERATIONS LOG</span>
          </h3>
          <span className="text-xs font-mono text-[#94A3B8]">
            Immutable Cryptographic Ledger
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
          {/* Search Box */}
          <div className="sm:col-span-6 relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by filename, UUID, or hash..."
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            />
            <Search className="w-4 h-4 text-[#94A3B8] absolute left-3 top-1/2 -translate-y-1/2" />
          </div>

          {/* Verdict Filter */}
          <div className="sm:col-span-3">
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            >
              <option value="ALL">All Verdicts</option>
              <option value="VERIFIED_EXACT">VERIFIED_EXACT</option>
              <option value="RECOVERABLE">RECOVERABLE</option>
              <option value="PRISTINE">PRISTINE</option>
              <option value="STRUCTURALLY_SALVAGED">STRUCTURALLY_SALVAGED</option>
              <option value="UNRECOVERABLE_EXACT">UNRECOVERABLE_EXACT</option>
            </select>
          </div>

          {/* Operation Type Filter */}
          <div className="sm:col-span-3">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[#0A0F1D] border border-[#334155] text-xs font-mono text-[#F8FAFC] focus:border-[#06B6D4] focus:outline-none"
            >
              <option value="ALL">All Operations</option>
              <option value="PROTECT">PROTECT</option>
              <option value="VERIFY">VERIFY</option>
              <option value="RECOVER">RECOVER</option>
              <option value="REPAIR">REPAIR</option>
            </select>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-xl bg-[#111827] border border-[#1E293B] shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0F172A] border-b border-[#1E293B] text-[#94A3B8]">
              <tr>
                <th className="p-3.5">TIMESTAMP (UTC)</th>
                <th className="p-3.5">OPERATION</th>
                <th className="p-3.5">TARGET FILE</th>
                <th className="p-3.5">CHUNKS (K/M)</th>
                <th className="p-3.5">VERDICT</th>
                <th className="p-3.5">DURATION</th>
                <th className="p-3.5 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B] text-[#CBD5E1]">
              {filteredJobs.map((job) => (
                <tr
                  key={job.id}
                  onClick={() => handleOpenReport(job.id)}
                  className="hover:bg-[#1E293B]/70 cursor-pointer transition-colors"
                >
                  <td className="p-3.5 whitespace-nowrap text-[#94A3B8]">
                    {job.created_at.replace('T', ' ').replace('Z', '')}
                  </td>
                  <td className="p-3.5 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-[#1E293B] text-[#06B6D4] border border-[#334155]">
                      {job.job_type}
                    </span>
                  </td>
                  <td className="p-3.5 font-bold text-[#F8FAFC] truncate max-w-xs">
                    {job.source_path}
                  </td>
                  <td className="p-3.5 whitespace-nowrap text-[#94A3B8]">
                    {job.job_type === 'REPAIR' ? 'N/A' : 'K=16, M=4'}
                  </td>
                  <td className="p-3.5 whitespace-nowrap">
                    {getVerdictBadge(job.verdict)}
                  </td>
                  <td className="p-3.5 whitespace-nowrap text-[#94A3B8]">
                    {job.duration_ms ? `${job.duration_ms} ms` : '-'}
                  </td>
                  <td className="p-3.5 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleOpenReport(job.id);
                      }}
                      className="px-2.5 py-1 rounded bg-[#1E293B] hover:bg-[#334155] text-xs text-[#06B6D4] border border-[#334155] inline-flex items-center space-x-1"
                    >
                      <span>Report</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}

              {loading ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-[#94A3B8]">
                    Loading audit records...
                  </td>
                </tr>
              ) : filteredJobs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-[#94A3B8]">
                    No audit records matching query criteria.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        {/* Footer with Exports and Count */}
        <div className="p-4 bg-[#0F172A] border-t border-[#1E293B] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs font-mono">
          <span className="text-[#94A3B8]">
            Showing {filteredJobs.length} of {jobs.length} Operations Recorded
          </span>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={exportJson}
              className="px-3 py-1.5 rounded-lg bg-[#1E293B] hover:bg-[#334155] text-[#CBD5E1] border border-[#334155] flex items-center space-x-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-[#06B6D4]" />
              <span>Export JSON</span>
            </button>

            <button
              type="button"
              onClick={exportCsv}
              className="px-3 py-1.5 rounded-lg bg-[#1E293B] hover:bg-[#334155] text-[#CBD5E1] border border-[#334155] flex items-center space-x-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-[#3B82F6]" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>
      </div>

      {/* Forensic Report Drawer */}
      <ForensicDrawer
        report={selectedReport}
        onClose={() => setSelectedReport(null)}
      />
    </div>
  );
};
