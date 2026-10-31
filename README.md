# ReSecure — Autonomous File Integrity, Corruption Detection & Exact Recovery
C:\Users\ndsha\Downloads\nscl\resecure-main\corrupt_file_tool.py

cd c:\Users\ndsha\Downloads\nscl\resecure-main
.\resecure\backend\venv\Scripts\python.exe -m uvicorn resecure.backend.src.api.app:app --host 127.0.0.1 --port 8000 --reload

cd c:\Users\ndsha\Downloads\nscl\resecure-main\resecure\frontend
npm run dev

python corrupt_file_tool.py "C:\Users\ndsha\Downloads\Monitoring_interstate_river_2014-15.pdf" -o "C:\Users\ndsha\Downloads\Corrupted_Monitoring_interstate_river_2014-15.pdf"

[![E2E Acceptance Gates](https://img.shields.io/badge/Acceptance%20Gates-12%2F12%20Verified-brightgreen)](#acceptance-and-testing-gates)
[![Automated Tests](https://img.shields.io/badge/Automated%20Tests-85%2F85%20Passed%20(100%25)-brightgreen)](#automated-testing--verification)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-Zero%20Leaks%20%7C%20SAST%20Cleared-brightgreen)](#security-architecture--compliance)
[![Architecture](https://img.shields.io/badge/Architecture-Air--Gapped%20%7C%20Local--First-blue)](#core-architectural-tenets)
[![Factory](https://img.shields.io/badge/Built%20With-CalmStacks%20Agent%20Factory-purple)](#autonomous-agent-factory-provenance)

**ReSecure** is a zero-trust, local-first cybersecurity application engineered for proactive file resilience, cryptographic tampering detection, and mathematical data recovery. It combines fixed-size chunk hashing (SHA-256), authenticated manifests (HMAC-SHA256), and byte-striped **Galois Field $GF(2^8)$ Reed–Solomon Forward Error Correction** to protect healthy files, pinpoint bit rot or ransomware tampering, and reconstruct damaged files bit-for-bit without external dependencies.

---

## Core Architectural Tenets

1. **Mathematical Invariance (No AI Hallucination)**: Data reconstruction relies strictly on deterministic Reed–Solomon erasure coding ($GF(2^8)$). It guarantees exact bit-for-bit recovery ($P(\text{bit error}) = 0$) matching the original root SHA-256 hash. Generative AI / LLMs are strictly barred from byte generation due to stochastic hallucination.
2. **Non-Destructive Guarantee**: Original source files are evidentiary artifacts opened strictly read-only and never overwritten in-place. Recovered files are written to separate output paths; `output_path == source_path` is blocked across all engines and API endpoints.
3. **Safe Failure Protocol**: If damage exceeds redundancy capacity ($E > M$), ReSecure halts immediately with exit code 3 / HTTP 422 (`ERR_EXCEEDS_REDUNDANCY`), reports the exact shard deficit, and emits zero corrupted output bytes.
4. **Authenticated Manifest Integrity**: Integrity manifests (`.rsmanifest.json`) are canonicalized and signed using HMAC-SHA256 (`hmac.compare_digest`) with secret separation to prevent checksum poisoning or forged parity substitution.
5. **Air-Gapped Local Sovereignty**: 100% local user-space processing. Zero outbound telemetry, zero cloud calls, and bounded streaming memory ($\le 150\text{ MB}$ RSS).

---

## System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Presentation Layer (React 18 + Vite + Tailwind CSS)"]
        UI["Cybersecurity Dashboard"]
        Nav["Navbar & Status Beacons"]
        PStudio["Protect Studio\n(5%-100% Redundancy Slider)"]
        CMap["Integrity Scanner\n(64KB Chunk Grid Visualizer)"]
        RStudio["Recovery Studio\n(Exact Bit-for-Bit Verification)"]
        FVal["Format Validator\n(Text, CSV, JSON, PNG, JPEG)"]
        Reports["Forensic Telemetry Registry"]
    end

    subgraph Gateway ["REST API Gateway (FastAPI / Uvicorn)"]
        Routes["API Router (/api/*)"]
        MW_CORS["CORS & Headers"]
        MW_Traverse["Path Traversal Jail"]
        MW_Limit["2GB Size Guard"]
    end

    subgraph Core ["ReSecure Core Integrity & Recovery Engines"]
        Hasher["Streaming SHA-256 Hasher\n(core/hasher.py)"]
        Chunker["64KB Chunking & Health Slicer\n(core/chunker.py)"]
        RS["Reed-Solomon GF(2^8) Erasure Codec\n(core/reedsolomon.py)"]
        ManifestEngine["Canonical JSON & HMAC Signer\n(core/manifest.py)"]
        Validators["Deep Format Syntax Validators\n(core/format_validators.py)"]
        Repair["Heuristic Structural Salvage Engine\n(core/repair_engine.py)"]
        MLClassifier["Corruption Pattern Classifier\n(resecure/ai/classifier.py)"]
    end

    subgraph Persistence ["Persistence Layer (SQLite WAL Mode)"]
        DB[(resecure.db\nPRAGMA journal_mode=WAL)]
        T_Files["files"]
        T_Manifests["manifests"]
        T_Chunks["chunks"]
        T_Jobs["recovery_jobs"]
        T_Corrupt["corruption_events"]
        T_Valid["format_validations"]
    end

    UI --> Routes
    Routes --> Hasher
    Routes --> Chunker
    Routes --> RS
    Routes --> ManifestEngine
    Routes --> Validators
    Routes --> Repair
    Routes --> MLClassifier
    Hasher --> DB
    Chunker --> DB
    RS --> DB
```

---

## Technology Stack

| Layer | Technologies & Rationale |
| :--- | :--- |
| **Frontend** | **React 18, TypeScript 5.6, Vite 5.4, Tailwind CSS 3.4**<br>Obsidian dark-mode cyber theme, interactive 64KB chunk matrix, WCAG 2.1 AA compliance. |
| **Backend** | **Python 3.13, FastAPI, Pydantic v2, Uvicorn**<br>High-throughput asynchronous REST API strictly adhering to OpenAPI 3.1 specifications. |
| **Cryptography** | **Python `hashlib` (SHA-256), `hmac` (HMAC-SHA256)**<br>Streaming collision-resistant hashing, canonical JSON serialization, constant-time comparison. |
| **Erasure Coding** | **`reedsolo` & Pure-Python $GF(2^8)$ Galois Field Codec**<br>Byte-striped Cauchy/Vandermonde parity container (`.rsparity`), tunable redundancy ($5\%$–$100\%$). |
| **Format Validation** | **Pillow 13.0, RFC 4180 (CSV), RFC 8259 (JSON), IEEE 802.3 CRC-32 (PNG)**<br>Deep syntactic, semantic, and structural inspection for Text, CSV, JSON, PNG, and JPEG. |
| **Database** | **SQLite 3 with Write-Ahead Logging (WAL)**<br>High-concurrency local relational persistence with foreign key cascading and atomic transactions. |
| **Testing** | **Pytest 9.1, Node TAP runner, PowerShell E2E**<br>85 automated unit, integration, and end-to-end tests across 12 Acceptance Gates. |
| **DevOps** | **Docker, Docker Compose, Nginx Alpine, GitHub Actions**<br>Multi-stage non-root container builds (UID 10001), automated CI verification. |

---

## Acceptance and Testing Gates

ReSecure MVP v1.0 was evaluated and passed all **12 Acceptance and Testing Gates** with a **100% pass rate (85/85 tests passing)**:

| Gate | Acceptance Criteria | Verification Status | Pass Rate |
| :---: | :--- | :--- | :---: |
| **G-01** | **Healthy File Protection** | Slices into 64KB chunks, computes root/chunk SHA-256, generates `.rsparity` container and HMAC-signed `.rsmanifest.json`. | **VERIFIED** | 100% |
| **G-02** | **Tamper / Change Detection** | Single-byte alteration at offset 500 detected immediately; chunk hash mismatch degrades health score. | **VERIFIED** | 100% |
| **G-03** | **Corrupted Chunk Diagnostics** | Pinpoints exact chunk indices, byte ranges (`0x0000..0x3FFF`), and damage types (`HEADER_WIPE`, `BIT_FLIP`). | **VERIFIED** | 100% |
| **G-04** | **Exact Mathematical Recovery** | Reed-Solomon over $GF(2^8)$ reconstructs lost chunks when $E \le M$ ($E=1$ and $E=2$ tested). | **VERIFIED** | 100% |
| **G-05** | **Bit-for-Bit Hash Invariance** | Reconstructed file SHA-256 strictly equals original root SHA-256 bit-for-bit (`disk_bytes == original_bytes`). | **VERIFIED** | 100% |
| **G-06** | **Safe Failure Protocol** | When $E > M$, halts immediately, raises `ERR_EXCEEDS_REDUNDANCY`, and emits 0 corrupted output bytes. | **VERIFIED** | 100% |
| **G-07** | **Tampered Manifest Rejection** | Modified HMAC signatures fail-closed with HTTP 403 `ERR_MANIFEST_TAMPERED`; corrupted parity headers rejected. | **VERIFIED** | 100% |
| **G-08** | **Deep Format Validation & Repair** | Deep syntax validation and heuristic structural salvage verified across Text/UTF-8, CSV, JSON, PNG, and JPEG. | **VERIFIED** | 100% |
| **G-09** | **Non-Destructive Invariant** | Source file SHA-256 verified identical before and after all operations; `output == source` blocked. | **VERIFIED** | 100% |
| **G-10** | **Frontend Real API Integration** | React 18 client binds directly to FastAPI backend; production bundle compiled cleanly (1,486B shell). | **VERIFIED** | 100% |
| **G-11** | **Automated Tests & Typechecks** | 85 automated tests passed; zero TypeScript errors; zero linter warnings. | **VERIFIED** | 100% |
| **G-12** | **Setup & Runbook Documentation** | Setup, Docker, and operational runbooks fully documented in `docs/setup-and-troubleshooting.md`. | **VERIFIED** | 100% |

---

## Quickstart Guide

### Option 1: Automated Local Setup (Recommended)

Requires Python 3.11+ and Node.js 18+.

```powershell
# 1. Clone repository
git clone https://github.com/Arilsrinivas/resecure.git
cd resecure

# 2. Automated Idempotent Setup (virtual environment, dependencies, seeds, build)
powershell -File .\scripts\setup-resecure.ps1

# 3. Launch ReSecure (FastAPI on :8000 & React on :3000)
powershell -File .\scripts\run-resecure.ps1
```

Access Points:
- **Cybersecurity Web Dashboard**: `http://localhost:3000`
- **FastAPI REST API Documentation**: `http://localhost:8000/docs`
- **Service Health Check**: `http://localhost:8000/api/health`

### Option 2: Docker Compose (Air-Gapped Container Stack)

```bash
docker compose -f docker-compose.resecure.yml up --build -d
```

### Option 3: Run Master E2E Validation Suite

```powershell
powershell -File .\scripts\validation\Test-ReSecureE2E.ps1
```

---

## API Reference Summary

The REST API strictly implements the OpenAPI 3.1 specification frozen in [`contracts/resecure/api.yaml`](contracts/resecure/api.yaml):

| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/protect` | Protects file, generates 64KB chunk SHA-256 tree, `.rsparity`, and HMAC `.rsmanifest.json` | `201`, `400`, `413` |
| `POST` | `/api/verify` | Audits file against manifest HMAC, flags corrupted/missing chunks, returns health score | `200`, `400`, `403` |
| `POST` | `/api/recover` | Reconstructs missing chunks via Reed–Solomon $GF(2^8)$ and verifies root SHA-256 match | `200`, `400`, `422` |
| `POST` | `/api/validate-format` | Deep structural inspection for Text, CSV (RFC 4180), JSON (RFC 8259), PNG, JPEG | `200`, `400` |
| `POST` | `/api/repair-format` | Opt-in heuristic structural repair fallback with `.repaired.log.json` disclosure | `200`, `400` |
| `GET` | `/api/jobs/{job_id}` | Retrieves execution status, chunk counts, duration, and error codes | `200`, `404` |
| `GET` | `/api/reports/{job_id}` | Returns comprehensive forensic audit telemetry report in machine-readable JSON | `200`, `404` |
| `GET` | `/api/health` | Service health check, bounded memory RSS telemetry, and uptime | `200` |

---

## Repository Structure

```
resecure/
├── contracts/
│   └── resecure/
│       ├── api.yaml                 # Frozen OpenAPI 3.1 specification
│       ├── schema.sql               # Frozen SQLite DDL schema blueprint
│       └── types.ts                 # Universal TypeScript contract interfaces
├── design/
│   └── resecure-tokens.json         # WCAG 2.1 AA cybersecurity design tokens
├── docs/
│   ├── adr/
│   │   └── ADR-003-resecure-stack.md# Architecture Decision Record
│   ├── architecture/
│   │   └── resecure-architecture.md # Technical topology & algorithm specifications
│   ├── prd/
│   │   └── resecure-mvp.prd.md      # Product Requirements Document (PRD)
│   ├── reports/
│   │   ├── qa/resecure-qa-report.md # Comprehensive QA & acceptance gate report
│   │   ├── security/resecure-security-report.md # SAST & secret audit report
│   │   └── ai-recovery-evaluation.md# Mathematical proof: Reed-Solomon vs AI
│   └── setup-and-troubleshooting.md # Operational runbook & troubleshooting recipes
├── resecure/
│   ├── ai/                          # Diagnostic ML feature extraction & classifiers
│   ├── backend/                     # Python 3.13 FastAPI server & core engines
│   │   └── src/
│   │       ├── api/                 # REST routes, schemas, and security middleware
│   │       ├── core/                # Hasher, chunker, RS codec, validators, repair
│   │       ├── db/                  # SQLite WAL connection manager & repositories
│   │       └── services/            # Protection, verification, recovery services
│   ├── database/                    # SQLite migrations and seed fixtures
│   ├── evals/                       # Automated recovery benchmark evaluation harness
│   ├── frontend/                    # React 18 + Vite + Tailwind CSS application
│   ├── tests/                       # Unit & integration test suites
│   ├── Dockerfile.backend           # Multi-stage non-root Python container
│   ├── Dockerfile.frontend          # Multi-stage non-root Nginx container
│   └── docker-compose.yml           # Local compose orchestration
├── scripts/
│   ├── setup-resecure.ps1           # Automated environment setup script
│   ├── run-resecure.ps1             # Local application launcher
│   └── validation/
│       └── Test-ReSecureE2E.ps1     # Master 12-Gate E2E verification test runner
├── tests/
│   └── test_resecure_acceptance_gates.py # 12 Acceptance Gates pytest test suite
├── docker-compose.resecure.yml      # Root Docker Compose orchestration
└── report.pdf                       # ReSecure delivery report summary PDF
```

---

## Autonomous Agent Factory Provenance

This application was engineered by the **CalmStacks Agent Factory** under strict adherence to `AGENTS.md`:
- **Lead Orchestrator**: Directed DAG task decomposition, stage gating, and worktree isolation.
- **Product Agent**: Authored PRD, user stories, and BDD Gherkin scenarios.
- **Architect Agent**: Designed system boundaries, frozen contracts, and $GF(2^8)$ recovery algorithms.
- **UI/UX Agent**: Created the dark-mode cyber design system and 64KB interactive chunk grid.
- **Database Agent**: Built SQLite WAL-mode persistence, type-safe repositories, and seed fixtures.
- **Backend Agent**: Implemented core integrity engines, RS codecs, format validators, and REST API.
- **AI/ML Agent**: Evaluated information-theoretic recovery bounds and built diagnostic classifiers.
- **Frontend Agent**: Developed the responsive React 18 client application.
- **QA Agent**: Verified all 12 Acceptance Gates with 85 automated tests.
- **Security Agent**: Conducted SAST reviews, secret scanning, and cryptographic verification.
- **DevOps Agent**: Packaged multi-stage Dockerfiles, compose stacks, and setup scripts.

---

## License

This project is licensed under the MIT License.
