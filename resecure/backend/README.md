# ReSecure Backend Service & Core Cryptographic Engines

**Package Path**: `resecure/backend/` (and root `backend/`)  
**Technology Stack**: Python 3.13, FastAPI 0.115+, Pydantic v2, Uvicorn, SQLite 3 (WAL Mode), reedsolo, Pillow, PyPDF  
**API Specification**: OpenAPI 3.1 (`contracts/resecure/api.yaml`)  
**Port**: `8000` (Default REST API Gateway)  

---

## 1. Architectural Mission & Tenets

The ReSecure Backend is a high-throughput, zero-trust, local-first REST API and algorithmic engine designed for:
1. **Mathematical Invariance**: 100% deterministic Reed–Solomon erasure coding over Galois Field $GF(2^8)$. Bit-for-bit file reconstruction matching pristine SHA-256 hashes ($P(\text{bit error}) = 0$).
2. **Non-Destructive Isolation**: Source files are opened strictly in read-only mode (`O_RDONLY`). Output files are written to isolated destination paths. `output_path == source_path` is structurally blocked across all engines and API endpoints (`HTTP 400 ERR_NON_DESTRUCTIVE_VIOLATION`).
3. **Safe Failure Protocol**: If corrupted chunks $E$ exceed parity capacity $M$ ($E > M$), recovery immediately halts, raises `ERR_EXCEEDS_REDUNDANCY` (HTTP 422), and writes 0 corrupted output bytes to disk.
4. **Authenticated Manifest Integrity**: Manifests (`.rsmanifest.json`) are canonicalized (RFC 8785 style) and signed using HMAC-SHA256 (`hmac.compare_digest`) with secret separation to eliminate checksum poisoning or forged parity substitution.
5. **Air-Gapped Bounded Resources**: 100% local user space execution. Memory usage is bounded at $\le 150\text{ MB}$ RSS via 64KB fixed-size streaming buffers.

---

## 2. Directory & Module Decomposition

```
resecure/backend/
├── src/
│   ├── main.py                  # CLI entry point to launch Uvicorn server
│   ├── config.py                # Environment configurations (Pydantic Settings)
│   ├── api/                     # REST API Layer
│   │   ├── app.py               # FastAPI application factory, CORS, exception handlers
│   │   ├── middleware.py        # Path traversal jail, 2GB size guard, security headers
│   │   ├── routes.py            # Endpoints: /protect, /verify, /recover, /validate, /repair
│   │   └── schemas.py           # Pydantic v2 request/response validation schemas
│   ├── core/                    # Pure Algorithmic Integrity & Repair Engines
│   │   ├── hasher.py            # Streaming SHA-256 hasher (64KB chunks)
│   │   ├── chunker.py           # 64KB file slicer, offset calculator, reassembler
│   │   ├── reedsolomon.py       # GF(2^8) Reed-Solomon codec & .rsparity container parser
│   │   ├── manifest.py          # Canonical JSON serialization & HMAC-SHA256 signer
│   │   ├── format_validators.py # Deep syntax inspection (Text, CSV, JSON, PNG, JPEG, PDF)
│   │   └── repair_engine.py     # Heuristic structural salvage & .repaired.log.json logger
│   ├── db/                      # Persistence Layer (SQLite 3 WAL)
│   │   ├── connection.py        # Connection manager (PRAGMA foreign_keys, journal_mode=WAL)
│   │   ├── schema.py            # Database tables, triggers, and index definitions
│   │   ├── models.py            # Dataclasses & ORM-like entities
│   │   └── repository.py        # Thread-safe CRUD operations for files, manifests, chunks, jobs
│   └── services/                # Application Services & Workflow Orchestration
│       ├── protection_service.py # Slices, hashes, generates parity, signs manifest
│       ├── verification_service.py # Compares chunk hashes, validates HMAC, flags corruption
│       ├── recovery_service.py  # Solves GF(2^8) erasure equations, checks root hash match
│       └── format_service.py    # Bridges format validators and heuristic repair engine
├── tests/                       # Pytest Unit & Integration Test Suite (59 automated tests)
│   ├── test_chunker.py          # Fixed 64KB boundary slicing and offset tests
│   ├── test_hasher.py           # Streaming SHA-256 and boundary remainder tests
│   ├── test_reedsolomon.py      # GF(2^8) parity generation, matrix inversion, safe failure
│   ├── test_manifest.py         # Canonical serialization and HMAC tamper detection
│   ├── test_format_validators.py# Deep format syntax audits (Text, CSV, JSON, PNG, JPEG)
│   ├── test_repair_engine.py    # Heuristic salvage tests and disclosure verification
│   ├── test_database.py         # SQLite WAL schema, foreign keys, cascades, and seeds
│   ├── test_non_destructive.py  # Invariant testing ensuring source files remain untouched
│   ├── test_one_click_repair.py # End-to-end multi-format repair workflow tests
│   └── test_pdf_pipeline.py     # ISO 32000 PDF validation, zero-fill defense, RS recovery
└── requirements.txt             # Production dependencies (FastAPI, reedsolo, Pillow, PyPDF)
```

---

## 3. Deep Dive into Core Engines

### 3.1 Streaming Hasher (`src/core/hasher.py`)
- Slices files into uniform chunks of 64KB (`65,536` bytes).
- Streams bytes in real-time through Python `hashlib.sha256()`.
- Calculates both individual chunk SHA-256 hashes and the master **Root SHA-256 Hash**.
- Handles non-uniform file sizes cleanly: if a file is 130KB, chunk 0 is 64KB, chunk 1 is 64KB, and chunk 2 is 2KB remainder. `hash_bytes(full_file) == root_sha256(chunks)` is guaranteed.

### 3.2 Reed-Solomon $GF(2^8)$ Erasure Codec (`src/core/reedsolomon.py`)
- Operates over Galois Field $GF(2^8) = GF(256)$ with irreducible generator polynomial:
  $$p(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\text{hex } 0x11D, \text{ decimal } 285)$$
- Calculates parity count $M = \lceil K \times (\text{redundancy\_percent} / 100) \rceil$, clamped between 1 and 255.
- Byte-stripes chunks across Cauchy/Vandermonde generator matrices.
- Serializes parity chunks into a binary `.rsparity` container with a 34-byte packed binary header:
  ```
  [0..7]   Magic bytes: b"RSPARITY"
  [8..9]   Version: uint16 (1)
  [10..13] Chunk size: uint32 (65536)
  [14..15] Data chunks K: uint16
  [16..17] Parity chunks M: uint16
  [18..33] Reserved: 16 null bytes
  [34..]   Parity payload: M * chunk_size bytes
  ```
- **Recovery Invariant**:
  - When damaged chunks $E \le M$: Gaussian elimination / matrix inversion over $GF(2^8)$ reconstructs every missing byte exactly.
  - When $E > M$: Raises `RedundancyExceededError`, reports deficit $E - M$, and halts without emitting partial corrupt bytes.

### 3.3 Authenticated Manifest Engine (`src/core/manifest.py`)
- Creates `.rsmanifest.json` containing metadata, root hash, chunk hash array, and parity info.
- Canonicalizes JSON using deterministic key sorting (`sort_keys=True`) and compact separators (`separators=(',', ':')`) to guarantee identical serialization across all platforms.
- Signs payload with HMAC-SHA256 (`hmac.new(secret, payload, hashlib.sha256).hexdigest()`).
- Verifies signatures via `hmac.compare_digest` (constant-time comparison) to prevent timing side-channel attacks.

### 3.4 Deep Format Validators (`src/core/format_validators.py`)
- **TEXT**: Validates UTF-8 / ASCII compliance. Rejects control characters, rogue null bytes (`\x00`), and unbalanced transcoding sequences.
- **CSV**: RFC 4180 validator. Detects unescaped quotes, ragged column counts across rows, and delimiter collisions.
- **JSON**: RFC 8259 validator. Detects unclosed braces/brackets, trailing commas, single-quoted strings, and non-UTF-8 characters.
- **PNG**: RFC 2083 / ISO 15948 validator. Checks 8-byte magic header (`\x89PNG\r\n\x1a\n`), validates `IHDR`, verifies chunk IEEE 802.3 CRC-32 checksums, checks `IDAT` compression streams, and asserts terminal `IEND` chunk.
- **JPEG**: ISO/IEC 10918-1 validator. Asserts Start of Image marker (`0xFFD8`), parses frame segments (`SOF0`, `SOF2`), validates Huffman and quantization tables (`DHT`, `DQT`), and asserts End of Image (`0xFFD9`).
- **PDF**: ISO 32000 validator. Validates `%PDF-` preamble, null-byte saturation ratios, cross-reference tables (`xref`), trailer dictionaries, and page tree catalogs via `pypdf`.

### 3.5 Structural Salvage & Repair Engine (`src/core/repair_engine.py`)
- Provides opt-in heuristic repair for non-cryptographic salvage:
  - Text: Filters out corruption nulls and repairs UTF-8 replacement characters.
  - CSV: Normalizes ragged columns with empty strings and escapes raw quotes.
  - JSON: Truncates dangling trailing commas and balances open curly/square brackets.
  - PNG: Reconstructs wiped magic headers and appends missing `IEND` chunks.
  - JPEG: Synthesizes missing `0xFFD8` SOI and `0xFFD9` EOI markers.
  - PDF: Strips corrupt preambles and reconstructs EOF markers.
- **Audit Disclosure**: Every repair generates a companion `.repaired.log.json` detailing the exact byte offsets, mutations performed, and integrity trade-offs.

---

## 4. REST API Endpoint Reference

| Method | Endpoint | Description | Status Codes |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/protect` | Slices file into 64KB chunks, generates `.rsparity` container, and emits HMAC-signed `.rsmanifest.json` | `201`, `400`, `413` |
| `POST` | `/api/verify` | Audits file against manifest HMAC signature, pinpoints corrupted chunks, computes health score | `200`, `400`, `403` |
| `POST` | `/api/recover` | Solves $GF(2^8)$ erasure equations, reconstructs damaged chunks, verifies root SHA-256 | `200`, `400`, `422` |
| `POST` | `/api/validate-format` | Deep structural inspection for Text, CSV, JSON, PNG, JPEG, and PDF | `200`, `400` |
| `POST` | `/api/repair-format` | Opt-in heuristic structural repair with `.repaired.log.json` disclosure | `200`, `400` |
| `POST` | `/api/one-click-repair` | Automated end-to-end diagnostic, validation, repair, and safe download generator | `200`, `400`, `422` |
| `GET` | `/api/jobs/{job_id}` | Query execution state, chunk counts, duration, and error codes | `200`, `404` |
| `GET` | `/api/reports/{job_id}`| Full machine-readable forensic telemetry report | `200`, `404` |
| `GET` | `/api/download-repaired/{filename}` | Secure download for repaired files (0-byte files strictly blocked) | `200`, `404`, `422` |
| `GET` | `/api/health` | Service health, database status, memory RSS telemetry, disk space | `200` |

---

## 5. Verification & Testing

To run the backend test suite:
```powershell
# Run all 59 backend unit and integration tests
.\resecure\backend\venv\Scripts\python.exe -m pytest resecure/backend/tests -v

# Run with code coverage report
.\resecure\backend\venv\Scripts\python.exe -m pytest resecure/backend/tests --cov=resecure.backend.src
```
All 59 unit and integration tests pass with zero failures and zero skipped tests.
