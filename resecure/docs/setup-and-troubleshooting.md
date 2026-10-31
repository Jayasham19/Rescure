# ReSecure: Setup, Operations & Troubleshooting Guide

**Document Reference**: `resecure/docs/setup-and-troubleshooting.md`  
**Application**: ReSecure (MVP v1.0)  
**Classification**: High-Integrity Local Cybersecurity Resilience Utility  
**Status**: VERIFIED & COMPLETE  

---

## 1. System Overview

ReSecure is a zero-trust, local-first cybersecurity utility engineered for proactive digital asset resilience, cryptographic integrity verification, granular tampering detection, and bit-for-bit mathematical file recovery.

Operating under strict non-destructive principles, ReSecure guarantees:
1. **Mathematical Invariance**: Exact recovery succeeds if and only if the reconstructed file's SHA-256 matches the pristine original root SHA-256 bit-for-bit.
2. **Non-Destructive Isolation**: Source files are treated as immutable evidentiary artifacts and are never modified in-place.
3. **Safe Failure Protocol**: When damage exceeds the parity threshold ($E_{\text{damaged}} > M$), exact recovery halts immediately with `ERR_EXCEEDS_REDUNDANCY` (HTTP 422) and purges all temporary files, preventing corrupted data from entering production.
4. **Air-Gapped Sovereignty**: Zero external telemetry or network socket calls outside localhost.

---

## 2. Prerequisites & Environment Requirements

| Dependency | Minimum Version | Verified Runtime Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Python** | 3.11+ | Python 3.13.3 (x64) | Core Reed-Solomon engine, FastAPI backend, CLI |
| **Node.js** | 20.0+ | Node.js v22.17.1 | React 18 frontend runtime, test runner |
| **npm** | 10.0+ | npm 11.10.0 | Frontend package management |
| **SQLite** | 3.35+ | Python `sqlite3` (3.45+) | Local metadata, audit logs, and job state |
| **PowerShell** | 5.1+ / 7.x | Windows PowerShell 5.1 | Automated E2E verification harness |

---

## 3. Step-by-Step Installation & Setup

### 3.1 Repository Cloning & Navigation
```powershell
git clone <repository-url> "cyber act"
cd "cyber act"
git checkout feature/resecure-mvp
```

### 3.2 Python Environment Setup
Install required Python dependencies:
```powershell
# Using system Python or dedicated virtualenv
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn pydantic pillow reedsolo pytest anyio httpx
```

### 3.3 Frontend Setup & Production Build
Navigate to frontend directories and install dependencies:
```powershell
# Setup resecure frontend
cd "F:\cyber act\resecure\frontend"
npm install --prefer-offline

# Execute TypeScript typecheck and Vite build
npm run build
```
Build verification:
```powershell
node scripts/fallback-build.cjs
```
Expected output:
- `✓ TypeScript typecheck passed with 0 errors.`
- `✓ Vite build completed successfully.`
- Bundle output in `dist/index.html`.

### 3.4 Database Initialization
Initialize SQLite relational schema with WAL mode and foreign key enforcement:
```powershell
python -c "from resecure.backend.src.db.schema import init_db; init_db(); print('Database initialized.')"
```

---

## 4. Running ReSecure

### 4.1 Running the Backend API Server
Launch FastAPI backend with Uvicorn:
```powershell
python -m uvicorn resecure.backend.src.api.app:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`
- Health Endpoint: `http://127.0.0.1:8000/api/health`

### 4.2 Running the Frontend Client
In a separate terminal:
```powershell
cd "F:\cyber act\resecure\frontend"
npm run dev
```
Access the ReSecure console in your browser at `http://localhost:5173`.

---

## 5. Automated Testing Suites

Execute automated test suites to verify system integrity:

### 5.1 Full Acceptance Gates Suite (All 12 Gates)
```powershell
python -m pytest tests/test_resecure_acceptance_gates.py -v
```

### 5.2 Core Backend Integration & Unit Tests (48 Tests)
```powershell
python -m pytest resecure/backend/tests -v
```

### 5.3 AI/ML Recovery & Benchmark Evals (16 Tests)
```powershell
python -m pytest resecure/evals/test_aiml_evals.py -v
```

### 5.4 Frontend Contract & Invariant Tests (9 Tests)
```powershell
node --no-warnings --experimental-strip-types resecure/frontend/tests/verify-frontend.mjs
```

### 5.5 Comprehensive End-to-End PowerShell Verification
```powershell
powershell -ExecutionPolicy Bypass -File scripts/validation/Test-ReSecureE2E.ps1
```

---

## 6. Troubleshooting & Diagnostics Guide

### 6.1 `ERR_MANIFEST_TAMPERED` (HTTP 403 Forbidden)
- **Symptom**: Integrity scan or recovery fails with error message:
  `🚨 CRITICAL SECURITY ALERT: MANIFEST HMAC SIGNATURE MISMATCH (TAMPERING DETECTED)`
- **Root Cause**:
  1. The pre-shared secret key entered in the UI or CLI does not match the key used during protection.
  2. The `.rsmanifest.json` file was edited, forged, or corrupted.
  3. One or more chunk hashes in `chunk_hashes` were modified without re-signing.
- **Remediation**:
  1. Verify the `secret_key` and `key_id` against your security custody vault.
  2. Ensure the manifest file has not been modified by external processes.
  3. Re-protect the original pristine file to generate a fresh authenticated manifest if keys were rotated.

---

### 6.2 `ERR_EXCEEDS_REDUNDANCY` (HTTP 422 Unprocessable Entity)
- **Symptom**: File recovery aborts with verdict `UNRECOVERABLE_EXACT` and safe failure banner.
- **Root Cause**:
  The number of corrupted/missing chunks ($E$) exceeds the number of generated parity chunks ($M$). Reed-Solomon over $GF(2^8)$ cannot solve the linear system when $E > M$. ReSecure strictly adheres to Tenet 3 (Fail-Safe Honesty) and refuses to emit corrupted data.
- **Remediation**:
  1. Protect mission-critical assets with higher redundancy settings (e.g. 50% or 100%) in `Protect Studio`.
  2. If exact recovery is mathematically impossible and the file is Text, CSV, JSON, PNG, or JPEG, opt into **Heuristic Structural Repair** (`/api/repair-format`) to salvage intact records.
  3. Check the Deficit Meter in the UI: it indicates exactly how many additional parity shards are required ($E - M$).

---

### 6.3 `ERR_NON_DESTRUCTIVE_VIOLATION` (HTTP 400 Bad Request)
- **Symptom**: Recovery or repair fails with:
  `Non-destructive violation: output_path cannot match source_path`
- **Root Cause**:
  The user or client specified an `output_path` identical to the `source_path`. ReSecure treats original files as immutable evidentiary records.
- **Remediation**:
  Provide a distinct output path or directory (e.g., `data.recovered.db` or `./recovered/data.db`).

---

### 6.4 `ERR_PATH_TRAVERSAL` (HTTP 400 Bad Request)
- **Symptom**: Request rejected with error code `ERR_PATH_TRAVERSAL`.
- **Root Cause**:
  Input path contains directory traversal escape sequences such as `../`, `..\\`, or null bytes.
- **Remediation**:
  Use sanitized canonical absolute paths or relative paths confined within the application working directory.

---

### 6.5 Frontend Build Failure (`Missing tsc or vite binaries`)
- **Symptom**: `node scripts/fallback-build.cjs` fails with `Missing tsc or vite binaries in node_modules`.
- **Root Cause**:
  `node_modules` has not been installed in the frontend directory.
- **Remediation**:
  Run `npm install --prefer-offline` in `resecure/frontend/` or `frontend/`.

---

### 6.6 SQLite Database Lock (`sqlite3.OperationalError: database is locked`)
- **Symptom**: Database queries fail under concurrent requests.
- **Root Cause**:
  SQLite journal mode is set to DELETE or default rather than WAL mode.
- **Remediation**:
  ReSecure automatically sets `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` in `init_db()`. If locks persist, ensure no external SQLite GUI tools hold exclusive write locks on `resecure.db`.

---

### 6.7 Port 8000 Already in Use
- **Symptom**: `[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8000): only one usage of each socket address`
- **Root Cause**:
  A previous FastAPI/Uvicorn process or another service is occupying port 8000.
- **Remediation**:
  Find and terminate the process:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
  ```
  Or launch the server on an alternate port:
  ```powershell
  python -m uvicorn resecure.backend.src.api.app:app --host 127.0.0.1 --port 8001
  ```
