import React from 'react';
import { ShieldCheck, RefreshCw } from './icons';
import { HealthCheckResponse } from '../types';

interface NavbarProps {
  health: HealthCheckResponse | null;
  isMockMode?: boolean;
  onToggleMockMode?: () => void;
  onRefreshHealth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  health,
  onRefreshHealth,
}) => {
  const isHealthy = health?.status === 'OK';

  return (
    <header className="bg-[#0F172A] border-b border-[#1E293B] sticky top-0 z-40 px-4 lg:px-8 py-3 shadow-lg shadow-black/40">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Brand & System Title */}
        <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-[#0A0F1D] border border-[#06B6D4]/50 shadow-[0_0_12px_rgba(6,182,212,0.3)]">
            <ShieldCheck className="w-6 h-6 text-[#06B6D4]" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#10B981] animate-ping" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#10B981]" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-[#F8FAFC] tracking-tight">ReSecure</span>
              <span className="text-xs px-2 py-0.5 rounded bg-[#1E293B] text-[#06B6D4] font-mono border border-[#334155]">
                v1.0-mvp
              </span>
            </div>
            <p className="text-xs text-[#94A3B8]">
              Zero-Trust Cryptographic File Resilience & Recovery Console
            </p>
          </div>
        </div>

        {/* Security & Sovereignty Indicators */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Engine Status Beacon */}
          <div
            className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full border ${
              isHealthy
                ? 'bg-[#064E3B]/60 text-[#6EE7B7] border-[#10B981]/50'
                : 'bg-[#7F1D1D]/60 text-[#FCA5A5] border-[#EF4444]/60'
            }`}
            title="Core Cryptographic Engine Status"
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isHealthy ? 'bg-[#10B981] animate-pulse' : 'bg-[#EF4444]'
              }`}
            />
            <span className="font-mono font-semibold">
              {isHealthy ? 'ENGINE: READY' : 'ENGINE: DEGRADED'}
            </span>
          </div>



          {/* Refresh Health */}
          <button
            onClick={onRefreshHealth}
            className="p-1.5 rounded-full bg-[#111827] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F8FAFC] border border-[#334155] transition-colors"
            title="Ping Health Endpoint"
            aria-label="Refresh Health"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
