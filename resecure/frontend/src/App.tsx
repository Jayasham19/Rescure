import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OneClickRepair } from './components/OneClickRepair';
import { ProtectStudio } from './components/ProtectStudio';
import { IntegrityScanner } from './components/IntegrityScanner';
import { RecoveryStudio } from './components/RecoveryStudio';
import { FormatValidator } from './components/FormatValidator';
import { ForensicReports } from './components/ForensicReports';
import {
  Wrench,
  ShieldCheck,
  Search,
  Activity,
  CheckCircle,
} from './components/icons';
import { HealthCheckResponse, VerifyFileResponse } from './types';
import { apiClient } from './api/client';

type ActiveTab = 'ONE_CLICK' | 'PROTECT' | 'SCANNER' | 'RECOVERY' | 'VALIDATOR' | 'REPORTS';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('ONE_CLICK');
  const [health, setHealth] = useState<HealthCheckResponse | null>(null);
  const [isMockMode, setIsMockMode] = useState<boolean>(false);
  const [verifyData, setVerifyData] = useState<VerifyFileResponse | null>(null);
  const [targetJobId, setTargetJobId] = useState<string | null>(null);

  const fetchHealth = async () => {
    try {
      const res = await apiClient.getHealth();
      setHealth(res);
    } catch (err) {
      console.warn('Health check fetch failed:', err);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleMockMode = () => {
    const nextMode = !isMockMode;
    setIsMockMode(nextMode);
    apiClient.setForceMock(nextMode);
    fetchHealth();
  };

  const handleProceedToRecovery = (data: VerifyFileResponse) => {
    setVerifyData(data);
    setActiveTab('RECOVERY');
  };

  const handleNavigateToRepair = () => {
    setActiveTab('VALIDATOR');
  };

  const handleViewReport = (jobId: string) => {
    setTargetJobId(jobId);
    setActiveTab('REPORTS');
  };

  const navTabs: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    {
      id: 'ONE_CLICK',
      label: '1. One-Click Repair',
      icon: <Wrench className="w-4 h-4" />,
    },
    {
      id: 'PROTECT',
      label: '2. Protect & Parity',
      icon: <ShieldCheck className="w-4 h-4" />,
    },
    {
      id: 'SCANNER',
      label: '3. Integrity Scanner',
      icon: <Search className="w-4 h-4" />,
    },
    {
      id: 'RECOVERY',
      label: '4. Recovery Studio',
      icon: <Activity className="w-4 h-4" />,
    },
  ];

  return (
    <div className="min-h-screen bg-[#0A0F1D] text-[#F8FAFC] flex flex-col selection:bg-[#06B6D4]/30 selection:text-[#67E8F9]">
      {/* Top Header Navbar */}
      <Navbar
        health={health}
        isMockMode={isMockMode}
        onToggleMockMode={handleToggleMockMode}
        onRefreshHealth={fetchHealth}
      />

      {/* Main Workspace Navigation Bar */}
      <div className="bg-[#0F172A] border-b border-[#1E293B] sticky top-[61px] z-30 shadow-md">
        <div className="max-w-7xl mx-auto px-4 lg:px-8">
          <nav className="flex space-x-1 sm:space-x-3 overflow-x-auto py-2.5" role="tablist">
            {navTabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all border ${
                    isActive
                      ? 'bg-[#1E293B] text-[#06B6D4] border-[#06B6D4]/50 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                      : 'bg-transparent text-[#94A3B8] border-transparent hover:text-[#F8FAFC] hover:bg-[#111827]'
                  }`}
                >
                  <span className={isActive ? 'text-[#06B6D4]' : 'text-[#94A3B8]'}>{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Main Active Tab Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6">
        {activeTab === 'ONE_CLICK' && (
          <OneClickRepair
            onNavigateToRecovery={() => setActiveTab('RECOVERY')}
            onNavigateToValidator={() => setActiveTab('VALIDATOR')}
          />
        )}

        {activeTab === 'PROTECT' && (
          <ProtectStudio
            onProtectionComplete={(res) => {
              // Preload protection file for scanner
              setVerifyData({
                job_id: res.job_id,
                source_path: 'enterprise_q3_financials.csv',
                manifest_hmac_valid: true,
                verdict: 'PRISTINE',
                health_percentage: 100,
                total_chunks_k: res.total_chunks_k,
                healthy_chunks: res.total_chunks_k,
                corrupted_chunks: 0,
                missing_chunks: 0,
                parity_chunks_available: res.parity_chunks_m,
                chunk_health_map: [],
                duration_ms: res.duration_ms,
              });
            }}
          />
        )}

        {activeTab === 'SCANNER' && (
          <IntegrityScanner onProceedToRecovery={handleProceedToRecovery} />
        )}

        {activeTab === 'RECOVERY' && (
          <RecoveryStudio
            initialVerifyData={verifyData}
            onNavigateToRepair={handleNavigateToRepair}
            onViewReport={handleViewReport}
          />
        )}

        {activeTab === 'VALIDATOR' && <FormatValidator />}

        {activeTab === 'REPORTS' && <ForensicReports initialJobId={targetJobId} />}
      </main>

      {/* Forensic Footer */}
      <footer className="bg-[#0F172A] border-t border-[#1E293B] py-5 px-4 lg:px-8 mt-auto text-xs text-[#94A3B8]">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-[#CBD5E1]">ReSecure MVP v1.0</span>
            <span>&bull;</span>
            <span>Deterministic Galois Field GF(2^8) Erasure Coding &amp; Integrity Console</span>
          </div>

          <div className="flex items-center space-x-4 font-mono text-[11px]">
            <span className="text-[#10B981] flex items-center space-x-1">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Zero-Hallucination Invariant</span>
            </span>
            <span>&bull;</span>
            <span className="text-[#67E8F9]">Bounded &le; 150MB RSS</span>
            <span>&bull;</span>
            <span className="text-[#CBD5E1]">CalmStacks Agent Factory</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
