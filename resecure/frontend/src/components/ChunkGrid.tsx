import React, { useState } from 'react';
import { ChunkHealthItem } from '../types';
import { ChunkTooltip } from './ChunkTooltip';
import { ZoomIn, ZoomOut } from './icons';

interface ChunkGridProps {
  chunks: ChunkHealthItem[];
  parityCount?: number;
  onSelectChunk?: (chunk: ChunkHealthItem) => void;
  selectedChunkIndex?: number | null;
}

type FilterMode = 'ALL' | 'HEALTHY' | 'CORRUPTED' | 'MISSING';
type ZoomMode = 'COMPACT' | 'NORMAL' | 'EXPANDED';

export const ChunkGrid: React.FC<ChunkGridProps> = ({
  chunks,
  parityCount = 4,
  onSelectChunk,
  selectedChunkIndex,
}) => {
  const [filter, setFilter] = useState<FilterMode>('ALL');
  const [zoom, setZoom] = useState<ZoomMode>('NORMAL');
  const [hoveredChunk, setHoveredChunk] = useState<ChunkHealthItem | null>(null);
  const [hoveredParity, setHoveredParity] = useState<number | null>(null);

  const healthyCount = chunks.filter((c) => c.status === 'HEALTHY').length;
  const corruptedCount = chunks.filter((c) => c.status === 'CORRUPTED').length;
  const missingCount = chunks.filter((c) => c.status === 'MISSING').length;
  const totalCount = chunks.length;

  const filteredChunks = chunks.filter((c) => {
    if (filter === 'ALL') return true;
    if (filter === 'HEALTHY') return c.status === 'HEALTHY';
    if (filter === 'CORRUPTED') return c.status === 'CORRUPTED';
    if (filter === 'MISSING') return c.status === 'MISSING';
    return true;
  });

  const cellSizeClass = {
    COMPACT: 'w-6 h-6 text-[10px]',
    NORMAL: 'w-8 h-8 text-xs',
    EXPANDED: 'w-11 h-11 text-sm font-semibold',
  }[zoom];

  return (
    <div className="bg-[#111827] border border-[#1E293B] rounded-xl p-4 shadow-xl space-y-4">
      {/* Visualizer Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[#1E293B] pb-3">
        <div className="flex items-center space-x-3">
          <h3 className="font-semibold text-sm text-[#F8FAFC] tracking-wide flex items-center space-x-2">
            <span>64KB CHUNK HEALTH MATRIX</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#1E293B] text-[#94A3B8] border border-[#334155]">
              K={totalCount} Data | M={parityCount} Parity
            </span>
          </h3>
        </div>

        {/* Toolbar: Filters and Zoom */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filters */}
          <div className="flex items-center space-x-1 bg-[#0A0F1D] p-1 rounded-lg border border-[#1E293B] text-xs">
            <button
              onClick={() => setFilter('ALL')}
              className={`px-2 py-0.5 rounded transition-colors ${
                filter === 'ALL'
                  ? 'bg-[#1E293B] text-[#F8FAFC] font-semibold'
                  : 'text-[#94A3B8] hover:text-[#CBD5E1]'
              }`}
            >
              All ({totalCount})
            </button>
            <button
              onClick={() => setFilter('HEALTHY')}
              className={`px-2 py-0.5 rounded transition-colors ${
                filter === 'HEALTHY'
                  ? 'bg-[#064E3B] text-[#6EE7B7] font-semibold'
                  : 'text-[#94A3B8] hover:text-[#10B981]'
              }`}
            >
              Healthy ({healthyCount})
            </button>
            <button
              onClick={() => setFilter('CORRUPTED')}
              className={`px-2 py-0.5 rounded transition-colors ${
                filter === 'CORRUPTED'
                  ? 'bg-[#78350F] text-[#FCD34D] font-semibold'
                  : 'text-[#94A3B8] hover:text-[#F59E0B]'
              }`}
            >
              Corrupted ({corruptedCount})
            </button>
            {missingCount > 0 && (
              <button
                onClick={() => setFilter('MISSING')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  filter === 'MISSING'
                    ? 'bg-[#7F1D1D] text-[#FCA5A5] font-semibold'
                    : 'text-[#94A3B8] hover:text-[#EF4444]'
                }`}
              >
                Missing ({missingCount})
              </button>
            )}
          </div>

          {/* Zoom Toggles */}
          <div className="flex items-center space-x-1 bg-[#0A0F1D] p-1 rounded-lg border border-[#1E293B]">
            <button
              onClick={() => setZoom('COMPACT')}
              className={`p-1 rounded transition-colors ${
                zoom === 'COMPACT' ? 'bg-[#1E293B] text-[#06B6D4]' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
              }`}
              title="Compact Zoom (24px)"
              aria-label="Compact Zoom"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom('NORMAL')}
              className={`px-1.5 py-0.5 text-xs font-mono rounded transition-colors ${
                zoom === 'NORMAL' ? 'bg-[#1E293B] text-[#06B6D4]' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
              }`}
              title="100% Zoom (32px)"
            >
              100%
            </button>
            <button
              onClick={() => setZoom('EXPANDED')}
              className={`p-1 rounded transition-colors ${
                zoom === 'EXPANDED' ? 'bg-[#1E293B] text-[#06B6D4]' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
              }`}
              title="Expanded Zoom (44px)"
              aria-label="Expanded Zoom"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid View */}
      <div className="space-y-4">
        {/* Data Chunks Matrix */}
        <div>
          <div className="text-xs font-mono text-[#94A3B8] mb-2 flex items-center justify-between">
            <span>DATA CHUNKS (K={totalCount})</span>
            <span>64,536 Bytes per block</span>
          </div>

          <div className="flex flex-wrap gap-1.5 p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] min-h-[90px] items-center">
            {filteredChunks.map((chunk) => {
              const isSelected = selectedChunkIndex === chunk.index;
              let cellStyle = 'bg-[#064E3B]/70 border-[#10B981]/60 text-[#6EE7B7] hover:border-[#10B981]';
              let symbol = '■';

              if (chunk.status === 'CORRUPTED') {
                cellStyle =
                  'bg-[#78350F]/70 border-[#F59E0B]/80 text-[#FCD34D] hover:border-[#F59E0B] shadow-[0_0_8px_rgba(245,158,11,0.3)] animate-pulse';
                symbol = '▲';
              } else if (chunk.status === 'MISSING') {
                cellStyle =
                  'bg-[#7F1D1D]/70 border-[#EF4444]/80 text-[#FCA5A5] hover:border-[#EF4444] shadow-[0_0_8px_rgba(239,68,68,0.3)]';
                symbol = '✖';
              }

              return (
                <div
                  key={chunk.index}
                  className="relative"
                  onMouseEnter={() => setHoveredChunk(chunk)}
                  onMouseLeave={() => setHoveredChunk(null)}
                >
                  <button
                    onClick={() => onSelectChunk?.(chunk)}
                    className={`${cellSizeClass} rounded flex flex-col items-center justify-center font-mono border transition-all cursor-pointer ${cellStyle} ${
                      isSelected ? 'ring-2 ring-[#06B6D4] ring-offset-1 ring-offset-[#0A0F1D]' : ''
                    }`}
                    title={`Chunk #${chunk.index} (${chunk.status})`}
                    aria-label={`Chunk #${chunk.index} ${chunk.status}`}
                  >
                    <span>{symbol}</span>
                    <span className="text-[9px] opacity-80 leading-none">
                      {chunk.index.toString().padStart(2, '0')}
                    </span>
                  </button>

                  {hoveredChunk?.index === chunk.index && (
                    <ChunkTooltip
                      chunk={chunk}
                      parityShardsAvailable={parityCount}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Parity Chunks Matrix */}
        {parityCount > 0 && (
          <div>
            <div className="text-xs font-mono text-[#94A3B8] mb-2 flex items-center justify-between">
              <span>REED-SOLOMON PARITY SHARDS (GF(2^8) M={parityCount})</span>
              <span className="text-[#3B82F6]">Cold Redundancy Pool</span>
            </div>

            <div className="flex flex-wrap gap-1.5 p-3 rounded-lg bg-[#0A0F1D] border border-[#1E293B] items-center">
              {Array.from({ length: parityCount }, (_, i) => (
                <div
                  key={`parity-${i}`}
                  className="relative"
                  onMouseEnter={() => setHoveredParity(i)}
                  onMouseLeave={() => setHoveredParity(null)}
                >
                  <div
                    className={`${cellSizeClass} rounded flex flex-col items-center justify-center font-mono border bg-[#1E3A8A]/50 border-[#3B82F6]/60 text-[#93C5FD] cursor-help`}
                    title={`Parity Shard P${i}`}
                  >
                    <span>●</span>
                    <span className="text-[9px] opacity-80 leading-none">P{i}</span>
                  </div>

                  {hoveredParity === i && (
                    <ChunkTooltip
                      chunk={null}
                      parityIndex={i}
                      parityShardsAvailable={parityCount}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Visual Legend */}
      <div className="pt-2 border-t border-[#1E293B] flex flex-wrap items-center justify-between text-xs text-[#CBD5E1]">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center space-x-1.5">
            <span className="text-[#10B981] font-mono">■</span>
            <span>Healthy (Verified Exact)</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="text-[#F59E0B] font-mono">▲</span>
            <span>Corrupted (Bit Flips / Tamper)</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="text-[#EF4444] font-mono">✖</span>
            <span>Missing Block (EOF Truncation)</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="text-[#3B82F6] font-mono">●</span>
            <span>Parity Shard (GF-2^8 Ready)</span>
          </div>
        </div>

        <div className="text-[11px] text-[#94A3B8] font-mono">
          Hover cell for forensic offset &amp; flaw telemetry
        </div>
      </div>
    </div>
  );
};
