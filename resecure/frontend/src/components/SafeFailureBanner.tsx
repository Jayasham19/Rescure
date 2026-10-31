import React from 'react';
import { ShieldAlert, AlertTriangle, ArrowRight, Wrench } from './icons';
import { SafeFailureResponse } from '../types';

interface SafeFailureBannerProps {
  safeFailure: SafeFailureResponse;
  onNavigateToRepair?: () => void;
}

export const SafeFailureBanner: React.FC<SafeFailureBannerProps> = ({
  safeFailure,
  onNavigateToRepair,
}) => {
  const damaged = safeFailure.damaged_chunks_count;
  const parity = safeFailure.parity_chunks_available;
  const deficit = Math.abs(safeFailure.deficit);

  return (
    <div className="p-5 rounded-xl bg-[#7F1D1D]/30 border-2 border-[#EF4444] shadow-crimson-glow space-y-4">
      {/* Critical Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-[#7F1D1D] text-[#EF4444] border border-[#EF4444]/60">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h4 className="font-bold text-base text-[#FCA5A5] tracking-wide">
              ✕ SAFE FAILURE PROTOCOL ACTIVE: DAMAGE EXCEEDS REDUNDANCY (E &gt; M)
            </h4>
            <p className="text-xs text-[#CBD5E1]">
              Mathematical Solvability Threshold Exceeded in Galois Field GF(2^8).
            </p>
          </div>
        </div>

        <span className="font-mono text-xs px-2.5 py-1 rounded bg-[#7F1D1D] text-[#FCA5A5] border border-[#EF4444] font-bold">
          FAIL-SAFE HALTED
        </span>
      </div>

      {/* Non-Negotiable Invariant Notice */}
      <div className="p-3 rounded-lg bg-[#0A0F1D] border border-[#EF4444]/40 text-xs text-[#CBD5E1] space-y-1">
        <div className="font-semibold text-[#EF4444] flex items-center space-x-1.5">
          <AlertTriangle className="w-4 h-4" />
          <span>Core Invariant Enforced:</span>
        </div>
        <p>
          Corrupted data will <strong>NEVER</strong> be written to output disguised as recovered.
          Unlike probabilistic guessing or generative tools, ReSecure refuses to emit silent errors.
        </p>
      </div>

      {/* Damage vs Parity Deficit Meter */}
      <div className="p-4 rounded-lg bg-[#0A0F1D] border border-[#1E293B] space-y-3 font-mono text-xs">
        <div className="text-[#CBD5E1] font-bold uppercase tracking-wider">
          Damage vs. Parity Deficit Meter:
        </div>

        {/* Visual Bar: Damaged */}
        <div className="space-y-1">
          <div className="flex justify-between text-[#CBD5E1]">
            <span>Damaged Chunks (E):</span>
            <span className="text-[#EF4444] font-bold">{damaged} Chunks Damaged</span>
          </div>
          <div className="flex flex-wrap gap-1 p-2 rounded bg-[#111827] border border-[#1E293B]">
            {Array.from({ length: damaged }, (_, i) => (
              <span
                key={`dmg-${i}`}
                className="w-5 h-5 flex items-center justify-center rounded bg-[#7F1D1D] text-[#EF4444] font-bold border border-[#EF4444]/50"
                title={`Damaged Chunk #${safeFailure.damaged_indices[i] ?? i}`}
              >
                ■
              </span>
            ))}
          </div>
        </div>

        {/* Visual Bar: Parity */}
        <div className="space-y-1">
          <div className="flex justify-between text-[#CBD5E1]">
            <span>Available Parity (M):</span>
            <span className="text-[#3B82F6] font-bold">{parity} Parity Shards</span>
          </div>
          <div className="flex flex-wrap gap-1 p-2 rounded bg-[#111827] border border-[#1E293B]">
            {Array.from({ length: parity }, (_, i) => (
              <span
                key={`par-${i}`}
                className="w-5 h-5 flex items-center justify-center rounded bg-[#1E3A8A] text-[#93C5FD] font-bold border border-[#3B82F6]/50"
                title={`Parity Shard P${i}`}
              >
                ●
              </span>
            ))}
          </div>
        </div>

        {/* Deficit Metric */}
        <div className="pt-2 border-t border-[#1E293B] flex justify-between items-center text-[#EF4444]">
          <span className="font-semibold">Redundancy Deficit:</span>
          <span className="font-bold text-sm bg-[#7F1D1D]/50 px-2.5 py-0.5 rounded border border-[#EF4444]/60">
            -{deficit} Shards Needed for Bit-for-Bit Exact Recovery
          </span>
        </div>
      </div>

      {/* Next Safe Steps */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
        <div className="text-xs text-[#CBD5E1] space-y-1">
          <div className="font-semibold text-[#F8FAFC]">Recommended Safe Actions:</div>
          <div className="text-[#94A3B8]">
            1. Mount secondary cold-storage parity backup (.rsparity).
            <br />
            2. Or opt-in to Heuristic Format Repair for partial structural recovery.
          </div>
        </div>

        {onNavigateToRepair && (
          <button
            type="button"
            onClick={onNavigateToRepair}
            className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-[#8B5CF6] hover:bg-[#7C3AED] text-[#0A0F1D] font-bold text-xs tracking-wide flex items-center justify-center space-x-2 transition-all shrink-0 shadow-lg"
          >
            <Wrench className="w-4 h-4 text-[#0A0F1D]" />
            <span>OPT-IN TO HEURISTIC REPAIR</span>
            <ArrowRight className="w-4 h-4 text-[#0A0F1D]" />
          </button>
        )}
      </div>
    </div>
  );
};
