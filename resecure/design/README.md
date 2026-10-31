# ReSecure Cybersecurity Design System & Token Specification

**Package Path**: `resecure/design/` (and root `design/`)  
**Design Artifact**: `resecure-tokens.json`  
**Compliance Standard**: WCAG 2.1 AA Accessible High-Contrast Obsidian Theme  
**Target Fonts**: `JetBrains Mono` (Hex, Hashes, Code), `Inter` (Typography & UI Chrome)  

---

## 1. Design Philosophy

ReSecure uses an authoritative, high-contrast **Obsidian Cybersecurity Theme** designed for Security Operations Center (SOC) analysts, digital forensics teams, and system administrators. 

### Design Principles:
1. **Cryptographic Clarity**: All hashes, hex offsets, chunk addresses, and binary metrics are rendered in monospace typography (`JetBrains Mono`) with distinct glyph distinctions (e.g., zero `0` vs `O`, one `1` vs `l`).
2. **Visual Invariance Indicators**: Colors strictly map to mathematical and cryptographic states:
   - **Emerald Cyber Green (`#10B981`)**: Verified Pristine, 100% Health, Cryptographic Hash Match ($P(\text{bit error}) = 0$).
   - **Electric Cyan (`#06B6D4`)**: System Activity, Streaming Chunk Calculation, Matrix Inversion Running.
   - **Neon Amber (`#F59E0B`)**: Bit Rot Detected, Parity Available, Non-Destructive Repairable ($E \le M$).
   - **Crimson Alert (`#EF4444`)**: Unrecoverable Corruption, Parity Deficit ($E > M$), Tampered Manifest, Malicious Injection.
3. **WCAG 2.1 AA High Contrast**: All text and interactive controls maintain a contrast ratio $\ge 4.5:1$ against the deep obsidian canvas (`#0A0F1D` / `#0D1117`).

---

## 2. Core Token Hierarchy (`resecure-tokens.json`)

### Color Palette

| Token Key | Hex Value | Semantic Purpose |
| :--- | :--- | :--- |
| `color.bg.canvas` | `#0A0F1D` | Primary deep obsidian background |
| `color.bg.card` | `#111827` | Elevated card & panel surface |
| `color.bg.cardHover` | `#1F2937` | Interactive hover highlight surface |
| `color.border.subtle` | `#1E293B` | Subtle grid and divider borders |
| `color.border.active` | `#06B6D4` | Focused input border & active beacons |
| `color.status.pristine` | `#10B981` | Cryptographically verified healthy chunk |
| `color.status.corrupted`| `#EF4444` | Damaged chunk with checksum mismatch |
| `color.status.missing` | `#F59E0B` | Truncated or unwritten chunk |
| `color.status.parity` | `#8B5CF6` | Forward Error Correction parity shard |
| `color.text.primary` | `#F9FAFB` | High-contrast body text and headers |
| `color.text.secondary`| `#9CA3AF` | Supporting telemetry metrics and labels |
| `color.text.code` | `#38BDF8` | Monospace SHA-256 digests and byte offsets |

---

## 3. Interactive 64KB Chunk Grid Specification

The signature visualization component of ReSecure is the **64KB Chunk Grid Visualizer**.
- Represents a protected file as an $N \times M$ matrix of responsive glyph blocks.
- Each tile represents exactly one 64KB (`65,536` byte) boundary.
- Hovering over a tile displays:
  - Chunk index (`Chunk #0`, `Chunk #1`, etc.)
  - Bounded byte range (e.g. `0x0000..0x3FFF` / `0..65535`)
  - Live SHA-256 vs Manifest SHA-256
  - Health status beacon (`HEALTHY`, `CORRUPTED`, `MISSING`, `RECOVERED`)
- During live recovery, damaged chunks visually transition from Crimson Alert to Electric Cyan (solving matrix) to Emerald Green (verified bit-for-bit).
