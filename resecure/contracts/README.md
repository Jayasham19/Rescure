# ReSecure Contract System & Frozen Specifications

**Package Path**: `resecure/contracts/` (and root `contracts/`)  
**Core Artifacts**: `api.yaml`, `schema.sql`, `types.ts`  
**Purpose**: Single Source of Truth (SSOT) enforcing contract-first engineering, API conformance, database consistency, and universal cross-language typing across Backend (Python) and Frontend (TypeScript).

---

## 1. Architectural Contract-First Tenets

In the CalmStacks Autonomous Agent Factory, no code is written before contracts are frozen:
1. **Contract-First Immutability**: All REST endpoints, request/response models, database entities, and error codes are strictly defined in `contracts/` before sprint execution.
2. **Machine-Readable SSOT**:
   - `api.yaml`: Frozen OpenAPI 3.1.0 specification driving FastAPI schema validation and frontend API clients.
   - `schema.sql`: Relational DDL blueprint for SQLite WAL mode persistence.
   - `types.ts`: Universal TypeScript interfaces ensuring end-to-end type safety between client and server.
3. **Zero Drift Guarantee**: Automated validation scripts (`scripts/validation/Test-Contracts.ps1` and `Test-ReSecureE2E.ps1`) assert that backend Pydantic models, SQL tables, and React state match the contracts 1:1.

---

## 2. Contract Specifications

### 2.1 `api.yaml` (OpenAPI 3.1.0)
Defines all ReSecure REST gateway operations:
- **`POST /api/protect`**: Ingests files up to 2GB, parses redundancy parameter (5% to 100%), emits `.rsmanifest.json` and `.rsparity`. Returns HTTP 201 with file metadata, total chunks $K$, parity chunks $M$, and HMAC signature.
- **`POST /api/verify`**: Validates uploaded file against companion manifest. Verifies HMAC-SHA256 signature, live-computes chunk hashes, and returns health percentage, overall verdict (`PRISTINE`, `RECOVERABLE`, `UNRECOVERABLE`), and corrupted chunk coordinates.
- **`POST /api/recover`**: Executes Reed-Solomon $GF(2^8)$ matrix inversion using `.rsparity`. Verifies recovered file root SHA-256 equals original root hash bit-for-bit. Blocked from overwriting source path (`ERR_NON_DESTRUCTIVE_VIOLATION`). Halts with HTTP 422 (`ERR_EXCEEDS_REDUNDANCY`) if $E > M$.
- **`POST /api/validate-format`**: Deep structural inspection for Text, CSV, JSON, PNG, JPEG, and PDF. Returns detailed diagnostic anomalies with exact byte offsets.
- **`POST /api/repair-format`**: Opt-in structural salvage fallback with detailed mutation logs.
- **`POST /api/one-click-repair`**: Unified pipeline that attempts heuristic repair or cryptographic recovery and produces an unguessable download URL.
- **`GET /api/jobs/{job_id}`**: Asynchronous state machine polling.
- **`GET /api/reports/{job_id}`**: Forensic audit telemetry report export.
- **`GET /api/health`**: Service availability, RSS memory usage, and database connection status.

### 2.2 `schema.sql` (SQLite 3.35+ Relational DDL)
Defines the relational data architecture:
- `files`: File catalog, size, MIME type, format, and master `root_sha256`.
- `manifests`: Parity configuration ($K$, $M$, chunk size, redundancy percentage), HMAC signature, canonical manifest JSON.
- `chunks`: 64KB chunk grid records, byte offsets, live SHA-256, and status (`HEALTHY`, `CORRUPTED`, `MISSING`, `OVERSIZED`).
- `recovery_jobs`: Execution lifecycle state machine (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `UNRECOVERABLE`).
- `corruption_events`: Granular corruption telemetry, damage types, detected byte ranges, and audit timestamps.
- `format_validations`: Format syntax compliance reports and repair logs.

### 2.3 `types.ts` (Universal TypeScript Interfaces)
Defines client-side types corresponding to backend schemas:
- `FileRecord`, `IntegrityManifest`, `ChunkMetadata`
- `VerificationResult`, `CorruptedChunkReport`
- `RecoveryJobState`, `RecoveryResult`
- `FormatValidationReport`, `RepairLogEntry`
- `OneClickRepairResponse`, `SystemHealthStatus`

---

## 3. Contract Conformance Testing

To verify contract compliance:
```powershell
powershell -File .\scripts\validation\Test-Contracts.ps1
```
Asserts that all contract files exist, are non-empty, and compile without syntax errors.
