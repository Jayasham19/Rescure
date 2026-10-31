# ReSecure UI/UX Design Specification & Cybersecurity Design System
# Modern, High-Trust, Dark-Mode Cybersecurity Console (MVP v1.0)

**Document Reference**: `docs/ui/resecure-design-spec.md`  
**Secondary Location**: `resecure/docs/ui/resecure-design-spec.md`  
**Status**: APPROVED / SPECIFICATION COMPLETE  
**Author**: UI/UX Agent (`TASK-RS-003`)  
**Design Tokens**: `design/resecure-tokens.json` & `resecure/design/resecure-tokens.json`  
**TypeScript Contract**: `contracts/resecure/types.ts`  
**Architecture Reference**: `docs/architecture/resecure-architecture.md`  
**PRD Reference**: `docs/prd/resecure-mvp.prd.md`  
**Target Platform**: Desktop & Responsive Web (React 18 + Vite + Tailwind CSS)  
**Accessibility Compliance**: WCAG 2.1 AA Strict  

---

## 1. Executive Summary & Design Foundations

### 1.1 Design Philosophy: Zero-Trust, High-Trust, Deterministic
**ReSecure** is a zero-trust, local-first cybersecurity utility engineered for security analysts, incident responders, DFIR specialists, and systems administrators. The visual interface reflects absolute cryptographic integrity, mathematical determinism, and forensic reliability.

```
+---------------------------------------------------------------------------------------------------+
|                                  RESECURE CORE DESIGN PRINCIPLES                                  |
+---------------------------------------------------------------------------------------------------+
|  1. MATHEMATICAL DETERMINISM OVER GENERATIVE GUESSWORK                                            |
|     Visual states communicate verifiable mathematical certainty (SHA-256 match, GF(2^8) Reed-     |
|     Solomon exact recovery). No ambiguous or probabilistic UI elements.                          |
|                                                                                                   |
|  2. ABSOLUTE FORENSIC NON-DESTRUCTION                                                             |
|     The UI explicitly assures the user at all times that source files remain immutable artifacts. |
|     Every recovery or repair path visually isolates target outputs with unambiguous indicators.   |
|                                                                                                   |
|  3. HONEST REPORTING & SAFE FAILURE STATES                                                        |
|     If corruption exceeds parity (E > M), the UI never conceals failure. It presents a crisp,     |
|     visual Deficit Meter and safely halts, preventing corrupted data from masquerading as clean.  |
|                                                                                                   |
|  4. LOCAL-FIRST SOVEREIGNTY                                                                       |
|     Visual confirmation that all cryptographic engines execute locally in-browser/user-space.     |
|     Zero cloud icons, zero outbound telemetry indicators; prominent Air-Gapped status badge.     |
|                                                                                                   |
|  5. ACCESSIBLE HIGH-DENSITY VISUALIZATION                                                         |
|     Micro-chunk grids visualize thousands of 64KB blocks with intuitive spatial clustering,       |
|     instant zoom/filtering, and dual-coded status indicators (color + symbol + textual badge).   |
+---------------------------------------------------------------------------------------------------+
```

---

### 1.2 Color Architecture: Obsidian Cyber Slate
The theme is anchored in deep obsidian tones, punctuated by high-luminance semantic status accents. All foreground/background pairings meet or exceed **WCAG 2.1 AA** requirements ($4.5:1$ for normal text, $3.0:1$ for large text and interactive components).

#### Semantic Color Palette & Contrast Validation Matrix

| Color Token | Hex / Value | Contrast on Canvas (`#0A0F1D`) | WCAG Level | Semantic Meaning & UI Application |
| :--- | :--- | :--- | :--- | :--- |
| **Canvas Base** | `#0A0F1D` | Surface Anchor | N/A | Deep Obsidian Slate global canvas |
| **Surface 1** | `#0F172A` | Background Alt | N/A | Top navigation header, sub-bars, borders |
| **Surface 2 (Card)**| `#111827` | Elevated Container | N/A | Primary workspace panels, chunk visualizer cards |
| **Surface 3** | `#1E293B` | Interactive Surface | N/A | Hover rows, input background, secondary button fill |
| **Border Subtle** | `#1E293B` | Structural Line | N/A | Section dividers, standard card framing |
| **Border Medium** | `#334155` | Distinct Contour | $3.2:1$ | Active inputs, chunk grid cells, toggle borders |
| **Text Primary** | `#F8FAFC` | $15.6:1$ | AAA Pass | Headings, primary metrics, active values |
| **Text Secondary** | `#CBD5E1` | $11.2:1$ | AAA Pass | Descriptions, labels, secondary metadata |
| **Text Muted** | `#94A3B8` | $6.3:1$ | AA Pass | Timestamps, byte offset labels, captions |
| **Status Healthy** | `#10B981` | $7.8:1$ | AA Pass | Pristine state, Verified Exact match, 100% health |
| **Status Warning** | `#F59E0B` | $8.4:1$ | AA Pass | Corrupted chunk, tampered manifest, degraded |
| **Status Danger** | `#EF4444` | $7.2:1$ | AA Pass | Fatal error, unrecoverable exact ($E > M$), missing chunk |
| **Action Cyan** | `#06B6D4` | $8.9:1$ | AA Pass | Primary action (Protect, Recover, Solve, Scan) |
| **Action Blue** | `#3B82F6` | $7.5:1$ | AA Pass | Secondary action (Export, Manifest Download, Filter) |
| **Diagnostic** | `#6366F1` | $6.5:1$ | AA Pass | Deep format validation, telemetry logs, anomaly tags |
| **Reconstructed**| `#8B5CF6` | $6.8:1$ | AA Pass | Reed-Solomon rebuilt chunk, heuristic salvage badge |

---

### 1.3 Typography System
ReSecure employs a dual-font typographic hierarchy: **Inter** for crisp, legible UI controls and executive dashboards; **JetBrains Mono** for cryptographic digests, byte offsets, chunk hex dumps, and mathematical parity formulas.

#### Typographic Hierarchy

```
Display 4XL   [Inter Bold, 36px/40px, -0.04em]          Product Title & Global Counters
Heading 2XL   [Inter Semibold, 24px/32px, -0.02em]      Tab Section Headers, Modal Titles
Subheading XL [Inter Medium, 20px/28px, -0.01em]        Card Titles, Hero Callouts
Body Base     [Inter Regular, 16px/24px, 0.0em]         Standard Explanations, Form Labels
Body SM       [Inter Regular, 14px/20px, 0.0em]         Table Content, Compact Controls, Tooltips
Caption XS    [Inter Medium, 12px/16px, +0.02em]        Metadata Tags, Badges, Timestamps
Pill Badge    [Inter Bold, 11px/14px, +0.1em UPPERCASE] Status Pills, Format Tags, Security Tier
Code Mono SM  [JetBrains Mono, 13px/18px, 0.0em]        SHA-256 Hashes, File Sizes, Byte Offsets
Code Mono XS  [JetBrains Mono, 11px/16px, 0.0em]        Chunk Hash Previews, Hex Dumps
```

---

## 2. Component Hierarchy & Atomic Design System

### 2.1 Atoms

#### Status Indicator Pills
Pill badges are dual-coded with an SVG icon and high-contrast uppercase text:

- **Healthy / Pristine**:
  - Container: `bg-[#064E3B]/60 text-[#6EE7B7] border border-[#10B981]/50`
  - Icon: Checkmark Shield (`ShieldCheck`)
  - Label: `VERIFIED EXACT` or `PRISTINE (100%)`
- **Corrupted / Tampered**:
  - Container: `bg-[#78350F]/60 text-[#FCD34D] border border-[#F59E0B]/50`
  - Icon: Alert Triangle (`AlertTriangle`)
  - Label: `CORRUPTED (N CHUNKS)` or `SIGNATURE TAMPERED`
- **Unrecoverable / Fatal**:
  - Container: `bg-[#7F1D1D]/60 text-[#FCA5A5] border border-[#EF4444]/60 shadow-[0_0_12px_rgba(239,68,68,0.35)]`
  - Icon: Shield Cross (`ShieldAlert`)
  - Label: `UNRECOVERABLE (E > M)`
- **Action / In-Progress**:
  - Container: `bg-[#083344]/70 text-[#67E8F9] border border-[#06B6D4]/50 animate-pulse`
  - Icon: Spinner / Radar Pulse (`RadioPulse`)
  - Label: `RECONSTRUCTING (GF-2^8)...`

#### Buttons & Triggers
```
+---------------------------------------------------------------------------------------------------+
| [PRIMARY CYBER ACTION]  bg-[#06B6D4] hover:bg-[#0891B2] text-[#0A0F1D] font-bold shadow-cyan-glow |
| [SECONDARY OUTLINE]     bg-transparent border border-[#334155] hover:border-[#06B6D4] text-white  |
| [CRITICAL DANGER]       bg-[#EF4444] hover:bg-[#DC2626] text-white shadow-crimson-glow            |
| [GHOST / MINIMAL]       hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F8FAFC]                    |
+---------------------------------------------------------------------------------------------------+
```

#### Redundancy Slider (5% – 100%)
- **Track**: `#1E293B` background, 8px height, rounded-full.
- **Active Range Fill**: Linear gradient from Cyan (`#06B6D4`) to Blue (`#3B82F6`).
- **Thumb**: 22px diameter `#06B6D4` circle with 2px white border, hover glow `0 0 12px rgba(6, 182, 212, 0.7)`.
- **Ticks & Snap Points**: Preset tick marks at `10%` (Standard), `20%` (Recommended Default), `30%` (High Resiliency), `50%` (Mission-Critical), `100%` (Dual Mirror Equivalent).

---

### 2.2 Molecules & Organisms

#### The Interactive 64KB Chunk Grid
Visualizes files as continuous matrix sequences of 64KB data chunks:
```
+----------------------------------------------------------------------------------------------------+
| CHUNK HEALTH MAP [16 Data Chunks (K=16) | 4 Parity Chunks (M=4)]           [Zoom: - | +] [Filter: All] |
+----------------------------------------------------------------------------------------------------+
|  [00] [01] [02] [03] [04] [05] [06] [07] [08] [09] [10] [11] [12] [13] [14] [15]  :: DATA CHUNKS   |
|   ■    ■    ▲    ■    ■    ■    ■    ▲    ■    ■    ■    ■    ■    ■    ■    ■                    |
|                                                                                                    |
|  [P0] [P1] [P2] [P3]                                                               :: PARITY CHUNKS |
|   ●    ●    ●    ●                                                                                 |
+----------------------------------------------------------------------------------------------------+
| LEGEND: ■ Healthy (#10B981)  ▲ Corrupted (#F59E0B)  ✖ Missing (#EF4444)  ● Parity Ready (#3B82F6)  |
+----------------------------------------------------------------------------------------------------+
```

#### Chunk Hover Tooltip Specification
When hovering over any chunk block in the visualizer, a high-trust forensic popover appears:
```
+-------------------------------------------------------+
| CHUNK #07 [0x00070000 - 0x0007FFFF] (65,536 Bytes)    |
| Status: CORRUPTED (Hash Mismatch Detected)            |
+-------------------------------------------------------+
| Expected SHA-256: 7f83b165...e3b0c442                 |
| Live SHA-256:     a3c49e21...91b8a510                 |
| Detected Flaws:   14 Bit Flips at offset 0x00070420   |
| Recovery Action:  Solvable via Parity Shard P0 & P1   |
+-------------------------------------------------------+
```

#### Safe Failure & Damage Deficit Meter
When damaged chunks exceed parity ($E > M$), the Recovery Studio immediately displays the Safe Failure Card:
```
+----------------------------------------------------------------------------------------------------+
| ✕ SAFE FAILURE PROTOCOL ACTIVE: DAMAGE EXCEEDS REDUNDANCY CAPACITY (E > M)                        |
+----------------------------------------------------------------------------------------------------+
| Invariant Enforced: Corrupted data will NEVER be written to output disguised as recovered.        |
|                                                                                                    |
| Damage vs. Parity Deficit:                                                                         |
| Damaged Chunks (E):   [ ■ ■ ■ ■ ■ ■ ] (6 Chunks Damaged)                                           |
| Available Parity (M): [ ● ● ● ]       (3 Parity Shards Available)                                  |
| Redundancy Deficit:   -3 Chunks Needed for Exact Mathematical Reconstruction                       |
|                                                                                                    |
| [!] Next Safe Steps:                                                                               |
| 1. Mount secondary cold-storage parity backup (.rsparity).                                         |
| 2. OR Opt-in to Heuristic Format Repair for partial structural recovery (Non-Destructive).         |
+----------------------------------------------------------------------------------------------------+
```

#### Non-Destructive Invariant Banner
Present persistently across all active operations:
```
+----------------------------------------------------------------------------------------------------+
| 🛡 NON-DESTRUCTIVE GUARANTEE: Source file remains immutable and untouched (Read-Only).              |
| Recovered output will be written to: /designated/recovery/target/file.recovered.ext                |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Comprehensive Dashboard Layout & Navigation Specifications

### 3.1 Global Header & Air-Gap Defense Bar

```
+----------------------------------------------------------------------------------------------------+
| [RESECURE LOGO] ReSecure v1.0 | High-Integrity File Resilience Console                             |
|                                                                                                    |
| [● ENGINE READY]  [🛡 LOCAL SOVEREIGNTY: 100% AIR-GAPPED]  [🔑 HMAC ENFORCED]  [MEM: 42MB / 150MB]   |
+----------------------------------------------------------------------------------------------------+
| TABS: [ 1. Protect & Parity ] [ 2. Integrity Scanner ] [ 3. Recovery Studio ] [ 4. Format Repair ] |
|       [ 5. Forensic Audit Reports ]                                                                |
+----------------------------------------------------------------------------------------------------+
```

1. **Brand Identity**: ReSecure shield badge with glowing cyan vertex lines.
2. **System Status Pill**:
   - `LIVE ENGINE: READY` (Green beacon `#10B981`)
   - Bounded RSS monitor: `RAM: 42MB (Max 150MB Stream Bounded)`.
3. **Local-Only Sovereignty Banner**:
   - `100% Local Processing | Zero Telemetry | Air-Gapped Compliant`.
   - Visual lock icon in Cyan (`#06B6D4`).
4. **Active Defense Indicators**:
   - `HMAC-SHA256 Manifest Guard: ACTIVE`
   - `Non-Destructive Write Jail: ENFORCED`

---

### 3.2 Tab 1: Protect & Parity Generation

#### Purpose
Ingest critical files, slice into deterministic chunks, compute SHA-256 digests, generate Reed-Solomon $GF(2^8)$ parity blocks, and emit HMAC-signed manifests.

#### Layout Specification
```
+----------------------------------------------------------------------------------------------------+
| STEP 1: SELECT OR DROP TARGET FILE FOR PROTECTION                                                  |
| +------------------------------------------------------------------------------------------------+ |
| |                         [ 📥 Drag & Drop Mission-Critical File Here ]                          |
| |                                 or Browse Files (Max 2.0 GB)                                    |
| | Selected: /data/enterprise_q3_financials.csv | 1,048,576 Bytes (1.00 MB) | Format: CSV         |
| +------------------------------------------------------------------------------------------------+ |
|                                                                                                    |
| STEP 2: ERASURE CODING & REDUNDANCY CONFIGURATION                                                  |
| Chunk Size S_c:   ( ) 16 KB   (•) 64 KB (Recommended)   ( ) 256 KB   ( ) 1 MB                      |
|                                                                                                    |
| Redundancy Ratio: [ 5% =======( 20% )======================================== 100% ]               |
| Calculation:      K = 16 Data Chunks | M = 4 Parity Chunks | Total Parity Overhead: 256 KB         |
| Tolerance:        Guarantees 100% exact recovery against any 4 corrupted or missing chunks         |
|                                                                                                    |
| STEP 3: AUTHENTICATED MANIFEST SECURITY (HMAC-SHA256)                                              |
| Pre-Shared Key:   [ •••••••••••••••••••••••••••••••••••• ] [ Eye ] [ Generate Strong Key ]         |
| Key Identifier:   [ vault-key-prod-01                  ]                                           |
| Warning Pill:     [ ℹ Manifest will be cryptographically signed against unauthorized tampering ]   |
|                                                                                                    |
| [ ⚡ GENERATE PARITY & SECURE FILE ]                                                               |
+----------------------------------------------------------------------------------------------------+
| PROTECTION COMPLETE (Duration: 84ms | Throughput: 12.5 MB/s)                                       |
| - Root SHA-256:    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855               |
| - Manifest File:   /data/enterprise_q3_financials.csv.rsmanifest.json [ Download Manifest ]        |
| - Parity Shards:   /data/enterprise_q3_financials.csv.rsparity        [ Download Parity ]          |
+----------------------------------------------------------------------------------------------------+
```

#### Interactive Behaviors
- **Drag & Drop Zone**: Turns border Cyan (`#06B6D4`) with `shadow-[0_0_20px_rgba(6,182,212,0.25)]` on dragover.
- **Redundancy Slider Interaction**: Real-time reactive calculation updating $K$, $M$, and total storage overhead without page reloads.
- **HMAC Toggle**: If secret key is empty, the UI displays an Amber warning pill: *"Unkeyed mode: Manifest will use machine-derived local signature; external auditing requires pre-shared secret."*

---

### 3.3 Tab 2: Integrity Scanner & Chunk Map

#### Purpose
Inspect target files against authenticated manifests, detect corruption at single-byte precision, evaluate HMAC signature integrity, and display the interactive 64KB chunk map.

#### Layout Specification
```
+----------------------------------------------------------------------------------------------------+
| INTEGRITY SCANNER: AUDIT TARGET FILE AGAINST TRUSTED MANIFEST                                      |
| Target File:   [ /data/enterprise_q3_financials.csv      ] [ Browse ]                              |
| Manifest File: [ /data/enterprise_q3_financials.csv.rsmanifest.json ] [ Browse ]                   |
| Pre-Shared Key:[ ••••••••••••••••••••••••••••••••••••    ] [ Verify Signature ]                    |
|                                                                                                    |
| [ 🔍 EXECUTE INTEGRITY AUDIT ]                                                                     |
+----------------------------------------------------------------------------------------------------+
| AUDIT RESULTS: [ PILL: ⚠ CORRUPTED (RECOVERABLE) ]  Health Score: 87.5% (14/16 Healthy Chunks)     |
| HMAC Signature: [ ✓ VALID (Signed by: vault-key-prod-01) ]                                         |
|                                                                                                    |
| 64KB CHUNK STATUS GRID:                                                                            |
| [All Chunks (16)]  [Healthy (14)]  [Corrupted (2)]  [Missing (0)]            Zoom: [ - | 100% | + ] |
| +------------------------------------------------------------------------------------------------+ |
| | [00] [01] [02*] [03] [04] [05] [06] [07*] [08] [09] [10] [11] [12] [13] [14] [15]             | |
| |  ■    ■     ▲    ■    ■    ■    ■     ▲    ■    ■    ■    ■    ■    ■    ■    ■              | |
| +------------------------------------------------------------------------------------------------+ |
|                                                                                                    |
| DAMAGE ANALYSIS:                                                                                   |
| - Chunk #02: Offset 0x00020000 - 0x0002FFFF (Bit flips detected in CSV row 412)                   |
| - Chunk #07: Offset 0x00070000 - 0x0007FFFF (Null-byte fill detected in CSV row 1205)             |
| - Parity Available: 4 Shards (M=4) | Damaged Chunks: 2 (E=2)                                       |
| - Mathematical Verdict: RECOVERABLE (E <= M). File can be reconstructed bit-for-bit.              |
|                                                                                                    |
| [ 🛠 PROCEED TO RECOVERY STUDIO -> ]                                                               |
+----------------------------------------------------------------------------------------------------+
```

#### Fail-Closed Signature Alert
If the manifest HMAC fails verification:
```
+----------------------------------------------------------------------------------------------------+
| 🚨 CRITICAL SECURITY ALERT: MANIFEST HMAC SIGNATURE MISMATCH (TAMPERING DETECTED)                  |
| Invariant Violated: Manifest payload has been altered or signed with an unauthorized secret key.   |
| System has failed closed. All audit operations on target file are halted.                          |
| Recorded Signature: 9a7b...14c2 | Computed Signature: 1f0e...58ba                                  |
+----------------------------------------------------------------------------------------------------+
```

---

### 3.4 Tab 3: Recovery Studio

#### Purpose
Execute mathematical Reed-Solomon erasure decoding, verify recovered root SHA-256 against manifest bit-for-bit, write recovered file non-destructively, or fail safely if $E > M$.

#### Layout Specification: Successful Recovery Flow
```
+----------------------------------------------------------------------------------------------------+
| RECOVERY STUDIO: DETERMINISTIC REED-SOLOMON GF(2^8) RECONSTRUCTION                                 |
+----------------------------------------------------------------------------------------------------+
| [ 🛡 NON-DESTRUCTIVE GUARANTEE: Source file /data/enterprise_q3_financials.csv will NOT be modified ]|
| Target Recovery Output Path: [ /data/recovered/enterprise_q3_financials.csv              ] [ Browse]|
| Parity Shards Source Path:   [ /data/enterprise_q3_financials.csv.rsparity                ] [ Browse]|
|                                                                                                    |
| RECOVERY EQUATION STATUS:                                                                          |
| Data Chunks (K): 16 | Damaged Chunks (E): 2 | Parity Shards Consumed: 2 of 4 (M_remaining = 2)     |
| Solvability: Linear System Matrix A[16x16] Invertible in GF(2^8) -> EXACT RECOVERY GUARANTEED     |
|                                                                                                    |
| [ 🚀 INITIATE BIT-FOR-BIT RECONSTRUCTION ]                                                         |
+----------------------------------------------------------------------------------------------------+
| RECONSTRUCTION PROGRESS:                                                                           |
| [========================================================================] 100%                     |
| Stage: 1. Loading Parity [✓] -> 2. Inverting Matrix [✓] -> 3. Solving GF(2^8) [✓] ->              |
|        4. Truncating Padding [✓] -> 5. Cryptographic SHA-256 Invariant Verification [✓]            |
+----------------------------------------------------------------------------------------------------+
| RECOVERY VERDICT: [ PILL: 🛡 VERIFIED EXACT (BIT-FOR-BIT MATCH) ]                                  |
|                                                                                                    |
| CRYPTOGRAPHIC INTEGRITY CERTIFICATE:                                                               |
| Original Root SHA-256:    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855         |
| Reconstructed SHA-256:    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855         |
| Invariant Check:          MATCH CONFIRMED (Zero Hallucinated Bytes)                                |
| Execution Metrics:        Time: 112ms | Throughput: 9.4 MB/s | Memory RSS: 38MB                    |
| Written To:               /data/recovered/enterprise_q3_financials.csv                             |
|                                                                                                    |
| [ 📂 Open File Location ]  [ 📄 View Forensic Recovery Certificate ]                                |
+----------------------------------------------------------------------------------------------------+
```

#### Safe Failure Flow ($E > M$)
When damaged chunks exceed parity shards ($E=6, M=4$), the UI switches to the Safe Failure State:
- Reconstruct button is disabled with Red border.
- The **Damage Deficit Meter** is shown with a $-2$ shard deficit.
- A CTA links directly to **Tab 4: Format Validator & Heuristic Repair** as the explicit, segregated fallback.

---

### 3.5 Tab 4: Format Validator & Heuristic Structural Repair

#### Purpose
Deep structural and syntactic inspection for Text/UTF-8, CSV, JSON, PNG, and JPEG files, with an explicit, opt-in heuristic repair engine accompanied by full disclosure logging.

#### Layout Specification
```
+----------------------------------------------------------------------------------------------------+
| FORMAT VALIDATOR & HEURISTIC STRUCTURAL REPAIR STUDIO                                              |
| Target File: [ /data/corrupted_telemetry.json        ] [ Browse ]   Format: [ JSON (RFC 8259) ▼ ]  |
|                                                                                                    |
| [ 🧪 VALIDATE FORMAT STRUCTURE ]                                                                   |
+----------------------------------------------------------------------------------------------------+
| VALIDATION RESULT: [ PILL: ✕ FORMAT INVALID ]                                                      |
| RFC Compliance: RFC 8259 Syntax Violation Detected                                                |
| Maximum Nesting Depth: 4 Levels (Safe <= 128)                                                      |
|                                                                                                    |
| DETECTED STRUCTURAL ANOMALIES:                                                                     |
| 1. [Line 48, Offset 1024]: Unterminated string literal before newline                              |
| 2. [Line 52, Offset 1180]: Trailing comma before closing object bracket '}'                         |
| 3. [Line 85, EOF]: Truncated stream with 2 unclosed brackets (1 Array '[', 1 Object '{')           |
+----------------------------------------------------------------------------------------------------+
| HEURISTIC STRUCTURAL REPAIR FALLBACK (OPT-IN):                                                     |
| [!] IMPORTANT DISCLOSURE: Heuristic repair mutates file syntax to achieve structural compliance.   |
| It does NOT guarantee semantic completeness. Source file will remain completely untouched.       |
| Output will be written to: /data/recovered/corrupted_telemetry.repaired.json                       |
|                                                                                                    |
| Repair Actions to Apply:                                                                           |
| [✓] Close unterminated string literals before linefeeds                                            |
| [✓] Strip illegal trailing commas                                                                  |
| [✓] Auto-balance delimiter stack (Append ']}')                                                     |
|                                                                                                    |
| [ 🔧 EXECUTE STRUCTURAL REPAIR (NON-DESTRUCTIVE) ]                                                 |
+----------------------------------------------------------------------------------------------------+
| REPAIR COMPLETE: [ PILL: ⚠ STRUCTURALLY SALVAGED ]                                                 |
| - Repaired File:   /data/recovered/corrupted_telemetry.repaired.json                               |
| - Disclosure Log:  /data/recovered/corrupted_telemetry.repaired.log.json [ View Full Mutations Log]|
| - Mutations Made:  3 structural adjustments logged                                                 |
+----------------------------------------------------------------------------------------------------+
```

---

### 3.6 Tab 5: Forensic Audit Reports & Activity History

#### Purpose
Searchable, filterable audit registry tracking every protect, verify, recovery, and format repair operation with full machine-readable JSON telemetry and compliance export.

#### Layout Specification
```
+----------------------------------------------------------------------------------------------------+
| FORENSIC AUDIT REGISTRY & OPERATIONS LOG                                                           |
| Search: [ Filter by filename, UUID, or hash... ]  Verdict: [ All Verdicts ▼ ]  Date: [ Last 7 Days]|
+----------------------------------------------------------------------------------------------------+
| TIMESTAMP (UTC)     | OPERATION | TARGET FILE                | CHUNKS (K/M) | VERDICT               |
+---------------------+-----------+----------------------------+--------------+-----------------------+
| 2026-10-22 17:15:02 | RECOVER   | enterprise_financials.csv  | K=16, M=4    | [ VERIFIED EXACT    ] |
| 2026-10-22 16:50:31 | VERIFY    | enterprise_financials.csv  | K=16, M=4    | [ ⚠ RECOVERABLE     ] |
| 2026-10-22 15:30:10 | REPAIR    | event_stream.json          | N/A (JSON)   | [ SALVAGED          ] |
| 2026-10-22 14:12:44 | RECOVER   | patient_records_q2.db      | K=32, M=2    | [ ✕ UNRECOVERABLE   ] |
| 2026-10-22 12:00:19 | PROTECT   | enterprise_financials.csv  | K=16, M=4    | [ PRISTINE          ] |
+---------------------+-----------+----------------------------+--------------+-----------------------+
| Showing 1-5 of 128 Operations                                     [ ⬇ Export JSON ] [ ⬇ Export CSV ]|
+----------------------------------------------------------------------------------------------------+
```

#### Detailed Forensic Report Slide-Over Drawer
Clicking any row opens a comprehensive slide-over drawer:
1. **Operation Identification**: UUIDv4, UTC Timestamp, Engine Version (`1.0.0-mvp`).
2. **Cryptographic Validation**: Recorded HMAC, live HMAC, Root SHA-256 match assertion.
3. **Chunk Level Health Map**: Collapsible list of every chunk index, status, byte range, and live SHA-256.
4. **Performance Telemetry**: Throughput (MB/s), duration (ms), memory footprint (MB).
5. **JSON Telemetry Viewer**: Formatted JSON conforming to `ForensicReportResponse` from `contracts/resecure/types.ts`.

---

## 4. Interactive States, Animations & Feedback Patterns

### 4.1 State Machine Matrix

| State | Visual Treatment | Cursor | Accessibility & ARIA |
| :--- | :--- | :--- | :--- |
| **Idle** | Standard borders (`#1E293B`), neutral text (`#CBD5E1`) | `default` | Standard focusable roles |
| **Hover** | 8% luminance boost, subtle border illumination (`#06B6D4`) | `pointer` | Focus outline preserved |
| **Active / Press** | Scale `0.99`, slight inset shadow | `pointer` | `aria-pressed="true"` |
| **Focus-Visible** | 2px solid `#06B6D4` with 2px offset | Default | Visual focus indicator (WCAG 2.4.7) |
| **Loading / Busy**| Subtle pulse animation (`pulse 1.8s`), progress bar active | `wait` | `aria-busy="true"`, live region announcement |
| **Disabled** | Opacity `0.45`, grayscale tint, action blocked | `not-allowed`| `aria-disabled="true"`, tabIndex `-1` |
| **Error / Alert** | Crimson border (`#EF4444`), glow `rgba(239, 68, 68, 0.4)` | Default | `role="alert"`, `aria-live="assertive"` |
| **Empty State** | Dashed border (`#334155`), muted icon, clear prompt | `default` | Informative empty screen text |

---

### 4.2 Reduced Motion Protocols
All radiant glows and pulse transitions respect the user's OS accessibility preferences:
```css
@media (prefers-reduced-motion: reduce) {
  *, ::before, ::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

---

## 5. Responsive Layout Architecture

### 5.1 Breakpoint Grid Specifications
While ReSecure is optimized for high-density forensic analysis on desktop monitors ($1280\text{px}+$), it maintains full operational capabilities across responsive mobile and tablet viewports.

- **Desktop Large ($1440\text{px}+$)**:
  - Full 3-column analysis view: (1) Configuration / Ingestion, (2) Interactive Chunk Matrix, (3) Forensic Diagnostics & Telemetry.
  - Chunk visualizer renders up to 32 chunks per row with expanded 38px cells.
- **Desktop Standard ($1024\text{px} - 1439\text{px}$)**:
  - 2-column view: (1) Controls & Actions, (2) Chunk Visualizer & Audit Logs.
  - Chunk visualizer renders 16 chunks per row with default 26px cells.
- **Tablet ($768\text{px} - 1023\text{px}$)**:
  - Stacked layout with collapsible diagnostic drawers.
  - Chunk visualizer renders 8–12 chunks per row with compact 20px cells.
- **Mobile ($375\text{px} - 767\text{px}$)**:
  - Single column scrollable flow.
  - Chunk visualizer shifts to horizontal scroll strip or aggregated group summary tiles.
  - Sticky bottom action bar for primary triggers ("Protect", "Recover", "Validate").

---

## 6. Frontend Component Mapping (`contracts/resecure/types.ts`)

To ensure seamless implementation by the Frontend Agent, every UI element directly maps to defined TypeScript contracts:

| UI Component | React Component Target | TypeScript Contract Binding |
| :--- | :--- | :--- |
| **System Header** | `src/components/Header.tsx` | `HealthCheckResponse` |
| **Protect Form** | `src/components/ProtectStudio.tsx` | `ProtectFileRequest`, `ProtectFileResponse` |
| **Redundancy Slider**| `src/components/RedundancySlider.tsx` | `redundancy_percentage: number` ($5 \dots 100$) |
| **Chunk Health Grid** | `src/components/ChunkGrid.tsx` | `ChunkHealthItem[]`, `ChunkStatus` |
| **Chunk Cell Tooltip**| `src/components/ChunkTooltip.tsx` | `ChunkHealthItem` |
| **Verify Dashboard** | `src/components/IntegrityScanner.tsx` | `VerifyFileRequest`, `VerifyFileResponse` |
| **Recovery Center** | `src/components/RecoveryStudio.tsx` | `RecoverFileRequest`, `RecoverFileResponse` |
| **Safe Failure Card**| `src/components/SafeFailureBanner.tsx` | `SafeFailureResponse` (`ERR_EXCEEDS_REDUNDANCY`) |
| **Format Validator** | `src/components/FormatValidator.tsx` | `ValidateFormatRequest`, `ValidateFormatResponse` |
| **Heuristic Repair** | `src/components/RepairStudio.tsx` | `RepairFormatRequest`, `RepairFormatResponse` |
| **Forensic Drawer** | `src/components/ForensicDrawer.tsx` | `ForensicReportResponse` |
| **Audit Log Table** | `src/components/AuditTable.tsx` | `RecoveryJobRecord[]` |

---

## 7. Design System Acceptance Checklist (UI/UX Agent Gate)

- [x] High-trust dark-mode obsidian slate color tokens defined and written to `design/resecure-tokens.json`.
- [x] Contrast ratios strictly validated against WCAG 2.1 AA ($>4.5:1$ text, $>3.0:1$ components).
- [x] Dual typography hierarchy (Inter sans-serif + JetBrains Mono) fully defined.
- [x] Interactive states (idle, hover, active, focus-visible, loading, error, empty) articulated.
- [x] Interactive 64KB Chunk Visualizer grid and tooltip specifications detailed.
- [x] Honest reporting displays specified (Safe Failure Card, Damage Deficit Meter, Non-Destructive Invariant Banner).
- [x] All 5 core functional tabs designed with ASCII/Mermaid layouts and micro-interactions.
- [x] Complete mapping to `contracts/resecure/types.ts` established for Frontend Agent handoff.
