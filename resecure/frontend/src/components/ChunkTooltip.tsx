import React from 'react';
import { ChunkHealthItem } from '../types';

interface ChunkTooltipProps {
  chunk: ChunkHealthItem | null;
  parityShardsAvailable?: number;
  parityIndex?: number;
}

export const ChunkTooltip: React.FC<ChunkTooltipProps> = ({
  chunk,
  parityShardsAvailable = 4,
  parityIndex,
}) => {
  if (!chunk && parityIndex === undefined) return null;

  const isParity = parityIndex !== undefined;
  const index = isParity ? parityIndex : chunk!.index;
  const offsetStart = isParity ? index * 65536 : chunk!.offset;
  const offsetEnd = offsetStart + 65535;
  const offsetHexStart = `0x${offsetStart.toString(16).padStart(8, '0').toUpperCase()}`;
  const offsetHexEnd = `0x${offsetEnd.toString(16).padStart(8, '0').toUpperCase()}`;

  const status = isParity ? 'PARITY' : chunk!.status;
  const statusColor = {
    HEALTHY: 'text-[#10B981]',
    CORRUPTED: 'text-[#F59E0B]',
    MISSING: 'text-[#EF4444]',
    OVERSIZED: 'text-[#EF4444]',
    PARITY: 'text-[#3B82F6]',
  }[status];

  return (
    <div className="absolute z-50 pointer-events-none -top-36 left-1/2 -translate-x-1/2 w-80 p-3 rounded-lg bg-[#273549] border border-[#334155] shadow-2xl text-xs space-y-1.5 backdrop-blur-md">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#334155] pb-1.5">
        <span className="font-mono font-bold text-[#F8FAFC]">
          {isParity ? `PARITY SHARD P${index}` : `CHUNK #${index.toString().padStart(2, '0')}`}
        </span>
        <span className={`font-mono font-bold uppercase ${statusColor}`}>
          {isParity ? '● READY (GF-2^8)' : `${status}`}
        </span>
      </div>

      {/* Byte Range */}
      <div className="flex justify-between text-[#CBD5E1] font-mono">
        <span className="text-[#94A3B8]">Byte Range:</span>
        <span>
          {offsetHexStart} - {offsetHexEnd} (64 KB)
        </span>
      </div>

      {/* Expected SHA-256 */}
      {!isParity && chunk?.expected_sha256 && (
        <div className="flex justify-between text-[#CBD5E1] font-mono">
          <span className="text-[#94A3B8]">Expected SHA:</span>
          <span className="truncate max-w-[150px]" title={chunk.expected_sha256}>
            {chunk.expected_sha256.substring(0, 16)}...
          </span>
        </div>
      )}

      {/* Live SHA-256 */}
      {!isParity && (
        <div className="flex justify-between text-[#CBD5E1] font-mono">
          <span className="text-[#94A3B8]">Live SHA:</span>
          <span
            className={`truncate max-w-[150px] ${
              chunk?.status === 'HEALTHY'
                ? 'text-[#10B981]'
                : chunk?.status === 'CORRUPTED'
                ? 'text-[#F59E0B]'
                : 'text-[#EF4444]'
            }`}
            title={chunk?.live_sha256 || 'None'}
          >
            {chunk?.live_sha256 ? `${chunk.live_sha256.substring(0, 16)}...` : 'MISSING'}
          </span>
        </div>
      )}

      {/* Flaw Details */}
      {!isParity && chunk?.detected_flaw && (
        <div className="pt-1 border-t border-[#334155] text-[#F59E0B] text-[11px] leading-tight">
          <span className="font-semibold">Flaw: </span>
          {chunk.detected_flaw}
        </div>
      )}

      {/* Recovery Action */}
      <div className="pt-1 border-t border-[#334155] text-[11px] text-[#67E8F9]">
        {isParity ? (
          <span>Erasure shard available to reconstruct any single lost data block</span>
        ) : chunk?.status === 'HEALTHY' ? (
          <span className="text-[#10B981]">✓ Invariant Verified (Bit-for-Bit Match)</span>
        ) : parityShardsAvailable > 0 ? (
          <span>🛠 Solvable via Galois Field GF(2^8) Reed-Solomon</span>
        ) : (
          <span className="text-[#EF4444]">✕ Unsolvable without parity shards</span>
        )}
      </div>
    </div>
  );
};
