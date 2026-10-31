# ReSecure Acceptance & Testing Gates Test Suite

**Package Path**: `tests/`  
**Core Runner**: Pytest 9.1+  
**Primary Suite**: `test_resecure_acceptance_gates.py`  
**Evaluation Standard**: CalmStacks Agent Factory Definition of Done (DoD) & PRD Acceptance Gates  

---

## 1. Overview & Verification Philosophy

ReSecure's testing harness enforces the **Zero Fabrication Rule**: no feature or mathematical claim is accepted based on assertion alone. Every capability is subject to rigorous, reproducible automated tests.

The test suite evaluates the entire system against **12 Mandatory Acceptance Gates**, spanning cryptographic hashing, Galois Field linear algebra, manifest tampering, format parsing, non-destructive isolation, API contracts, and documentation.

---

## 2. The 12 Mandatory Acceptance Gates Explained

| Gate ID | Gate Name | Automated Test Function | Acceptance Criteria |
| :---: | :--- | :--- | :--- |
| **G-01** | **Healthy File Protection** | `test_gate_01_healthy_file_protected_successfully` | Slices payload into uniform 64KB chunks (`DEFAULT_CHUNK_SIZE=65536`). Computes individual and root SHA-256 hashes. Generates binary `.rsparity` container with valid 34-byte header (`magic: RSPARITY`). Canonicalizes and signs `.rsmanifest.json` via HMAC-SHA256. |
| **G-02** | **Tamper / Change Detection** | `test_gate_02_changed_file_detected_through_hash_verification` | Introduces single-byte alteration at offset 500 (`byte ^= 0xFF`). Live chunk hash calculation detects delta immediately. Degrades health score and transitions verdict from `PRISTINE` to `RECOVERABLE`. |
| **G-03** | **Corrupted Chunk Diagnostics**| `test_gate_03_corrupted_chunks_identified_with_offsets_and_types` | Injects null header wipe at Chunk 0 (`0x0000..0x3FFF`) and bit flip at Chunk 2 (`0x8000..0xBFFF`). Audits return exact chunk indices `[0, 2]`, bounded byte ranges, and damage classifications (`HEADER_WIPE`, `BIT_FLIP`). |
| **G-04** | **Exact Mathematical Recovery** | `test_gate_04_damaged_file_reconstructed_when_damage_within_budget` | When damaged chunks $E \le$ parity shards $M$, Reed-Solomon codec over $GF(2^8)$ executes Gaussian elimination / matrix inversion to reconstruct all lost bytes. Tested at $E=1 \le M=2$ and $E=2 == M=2$. Verdict returns `VERIFIED_EXACT`. |
| **G-05** | **Bit-for-Bit Hash Invariance** | `test_gate_05_recovered_file_matches_original_root_sha256` | Reconstructed file SHA-256 strictly equals pristine root SHA-256. Non-uniform binary payload (54,321 bytes) asserts `hash_verified_exact == True` and bitwise equality (`disk_bytes == original_bytes`). |
| **G-06** | **Safe Failure Protocol** | `test_gate_06_recovery_fails_safely_when_damage_exceeds_redundancy` | When $E > M$, system halts, raises `ERR_EXCEEDS_REDUNDANCY` (HTTP 422), reports exact deficit $E - M$, and purges staging. Emits exactly 0 corrupted output bytes. |
| **G-07** | **Tampered Manifest Rejection** | `test_gate_07_invalid_manifests_and_tampered_packages_rejected` | Tests 4 threat vectors: (A) altered HMAC signature -> HTTP 403 `ERR_MANIFEST_TAMPERED`; (B) altered chunk hash with unmodified signature -> HTTP 403; (C) malformed JSON -> parse error; (D) corrupted parity magic -> `ValueError`. |
| **G-08** | **Deep Format Validation & Repair** | `test_gate_08_text_and_image_validation_and_repair` | Validates clean vs damaged files across 5 formats: Text (UTF-8/nulls), CSV (RFC 4180/ragged rows), JSON (RFC 8259/unclosed braces), PNG (CRC-32/wiped magic), JPEG (SOI/EOI markers). Verifies heuristic repairs restore validity. |
| **G-09** | **Non-Destructive Guarantee** | `test_gate_09_original_file_never_overwritten` | Source file SHA-256 recorded before operations. Verified identical after protect, verify, recover, and repair. Prohibits `output_path == source_path` across all engines (`NonDestructiveViolationError` / HTTP 400). |
| **G-10** | **Frontend Real API Integration** | `test_gate_10_frontend_workflows_use_real_backend_results` | Verifies FastAPI client bindings, validates Pydantic schemas against contracts, checks `dist/index.html` production build. |
| **G-11** | **Automated Tests & Typechecks** | `test_gate_11_automated_test_suites_execution` | Asserts that all unit test suites, eval benchmarks, and frontend invariant tests pass with 0 failures and 0 skips. |
| **G-12** | **Setup & Runbook Documentation** | `test_gate_12_setup_and_troubleshooting_documented` | Asserts existence and completeness of operational runbooks: setup guide, troubleshooting recipes, ADRs, PRD, and security reports. |

---

## 3. Running the Acceptance Gates

```powershell
# Run all 12 Acceptance Gates
.\resecure\backend\venv\Scripts\python.exe -m pytest tests/test_resecure_acceptance_gates.py -v
```
**Result**: 12/12 PASSED (100% Pass Rate).
