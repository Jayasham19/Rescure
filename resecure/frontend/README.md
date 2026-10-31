# ReSecure Frontend Web Application & Dashboard

**Package Path**: `resecure/frontend/` (and root `frontend/`)  
**Technology Stack**: React 18, TypeScript 5.6, Vite 5.4, Tailwind CSS 3.4  
**Design System**: Obsidian Dark-Mode Cyber Theme (`resecure-tokens.json`, WCAG 2.1 AA)  
**Port**: `3000` (Default Web Application UI)  

---

## 1. Architectural Mission & User Experience

The ReSecure Frontend is a responsive single-page web application engineered for high-consequence cybersecurity workflows:
1. **Interactive 64KB Chunk Matrix Visualizer**: Dynamically renders file chunk health as a responsive grid of tiles. Each tile represents an isolated 64KB boundary, color-coded by health state (`HEALTHY`, `CORRUPTED`, `MISSING`, `RECOVERED`).
2. **Deterministic Parity Studio**: Interactive 5% to 100% redundancy slider with real-time mathematical calculations showing $K$ (data chunks), $M$ (parity shards), container size overhead, and maximum recoverable chunk threshold.
3. **Forensic Integrity Scanner**: Inspects uploaded files against authenticated `.rsmanifest.json` packages, validating HMAC-SHA256 signatures, highlighting damaged offsets, and classifying damage types.
4. **Exact Recovery Studio**: Guides users through mathematical data reconstruction. Live animated state transitions show matrix inversion in real-time, verifying bit-for-bit SHA-256 match before presenting the recovered artifact for download.
5. **One-Click Diagnostic & Repair Studio**: Unified landing drop zone for drag-and-drop repair of damaged PDFs, images, JSON, CSV, and text files.

---

## 2. Directory & Component Breakdown

```
resecure/frontend/
├── index.html                   # HTML entry point with Obsidian viewport styling
├── package.json                 # Dependencies (React 18, Vite, Lucide-React, Tailwind)
├── tsconfig.json                # Strict TypeScript configuration
├── vite.config.ts               # Vite configuration with contracts alias & proxy rules
├── scripts/
│   └── fallback-build.cjs       # Standalone distribution packager
├── tests/
│   └── verify-frontend.mjs      # Automated Node.js TAP runner (10 invariant tests)
└── src/
    ├── main.tsx                 # React application bootstrap
    ├── App.tsx                  # Root navigation, active view switcher, status beacons
    ├── index.css                # Global Tailwind directives & Obsidian CSS variables
    ├── api/
    │   └── client.ts            # Typed HTTP client binding to FastAPI backend (/api/*)
    ├── types/
    │   └── index.ts             # Contracts-compliant TypeScript type interfaces
    └── components/
        ├── Navbar.tsx           # Obsidian header bar with real-time backend health beacon
        ├── ProtectStudio.tsx    # File ingestion, 5-100% redundancy slider, parity builder
        ├── IntegrityScanner.tsx # Companion manifest auditor & chunk diff inspector
        ├── ChunkGrid.tsx        # High-performance 64KB matrix visualizer with hover tooltips
        ├── RecoveryStudio.tsx   # Reed-Solomon solver, hash verifier, safe failure guard
        ├── FormatValidator.tsx  # Deep syntactic audit & opt-in heuristic salvage panel
        └── TelemetryRegistry.tsx# Relational audit log viewer and JSON export interface
```

---

## 3. Key Component Workflows

### 3.1 Protect Studio (`ProtectStudio.tsx`)
- Drag-and-drop file uploader for files up to 2GB.
- Real-time mathematical computation:
  - Input: File size $S$
  - Data chunks: $K = \lceil S / 65536 \rceil$
  - Parity shards: $M = \lceil K \times (R / 100) \rceil$
  - Failure threshold: $E_{\text{max}} = M$
- Invocations trigger `POST /api/protect`, generating `.rsmanifest.json` and `.rsparity` downloads for the user.

### 3.2 Integrity Scanner & Chunk Grid (`IntegrityScanner.tsx`, `ChunkGrid.tsx`)
- Accepts corrupted or suspect files paired with an `.rsmanifest.json`.
- Displays real-time cryptographic audit results:
  - HMAC-SHA256 signature validity badge (Green for authentic, Red for tampered).
  - Overall health score percentage.
  - Interactive chunk grid where red tiles indicate corrupted byte ranges.
  - Hover tooltips detailing byte range `0xXXXX..0xYYYY` and classified damage pattern.

### 3.3 Recovery Studio (`RecoveryStudio.tsx`)
- Ingests damaged file, manifest, and `.rsparity` container.
- If $E \le M$: Triggers $GF(2^8)$ matrix inversion. UI animates chunk recovery into Emerald Green, checks hash invariance, and provides download link for pristine restored file.
- If $E > M$: Triggers **Safe Failure Protocol**. Shows alert dialog reporting parity deficit ($E - M$), refuses to emit partial corrupted data, and logs forensic incident.

---

## 4. Building & Running

### Development Mode:
```powershell
cd resecure/frontend
npm run dev -- --host 127.0.0.1 --port 3000
```
Runs Vite development server on `http://127.0.0.1:3000`.

### Production Build:
```powershell
cd resecure/frontend
npm run build
```
Compiles TypeScript and outputs optimized production assets to `resecure/frontend/dist/`.

### Automated Frontend Invariant Verification:
```powershell
node resecure/frontend/tests/verify-frontend.mjs
```
Executes 10 automated mathematical and API schema conformance tests.
