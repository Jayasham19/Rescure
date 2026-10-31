"""
CalmStacks ReSecure Test Suite - REST API & Endpoint Integration Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_api
Contract: contracts/resecure/api.yaml
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from resecure.backend.src.api.app import app
from resecure.backend.src.db.schema import init_db


def make_temp_file(suffix: str = ".dat", content: bytes = b"") -> str:
    """Creates a temporary file, writes initial content, and immediately closes the file descriptor."""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
        if content:
            tf.write(content)
        path = tf.name
    return path


class TestAPIEndpoints(unittest.TestCase):
    """Verifies all FastAPI REST endpoints against the contracts/resecure/api.yaml contract."""

    @classmethod
    def setUpClass(cls) -> None:
        init_db()
        cls.client = TestClient(app)

    def test_health_endpoint(self) -> None:
        """Verifies GET /api/health."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["version"], "1.0.0")
        self.assertTrue(data["database_connected"])
        self.assertIn("memory_rss_mb", data)
        self.assertIn("timestamp", data)

    def test_protect_and_verify_flow(self) -> None:
        """Verifies POST /api/protect followed by POST /api/verify."""
        payload = b"CRITICAL_DATA_FOR_API_TESTING_" * 1000
        src_path = make_temp_file(suffix=".dat", content=payload)

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                # 1. Protect file
                protect_req = {
                    "source_path": src_path,
                    "redundancy_percentage": 25,
                    "chunk_size_bytes": 16384,
                    "output_dir": out_dir,
                    "secret_key": "api-test-key-2026",
                    "key_id": "key-01",
                }
                res_protect = self.client.post("/api/protect", json=protect_req)
                self.assertEqual(res_protect.status_code, 201)
                prot_data = res_protect.json()

                self.assertIn("job_id", prot_data)
                self.assertIn("manifest_path", prot_data)
                self.assertIn("parity_path", prot_data)
                self.assertEqual(prot_data["redundancy_percentage"], 25)
                self.assertEqual(len(prot_data["root_sha256"]), 64)
                self.assertTrue(Path(prot_data["manifest_path"]).is_file())
                self.assertTrue(Path(prot_data["parity_path"]).is_file())

                # 2. Verify clean file
                verify_req = {
                    "source_path": src_path,
                    "manifest_path": prot_data["manifest_path"],
                    "secret_key": "api-test-key-2026",
                }
                res_verify = self.client.post("/api/verify", json=verify_req)
                self.assertEqual(res_verify.status_code, 200)
                ver_data = res_verify.json()

                self.assertTrue(ver_data["manifest_hmac_valid"])
                self.assertEqual(ver_data["verdict"], "PRISTINE")
                self.assertEqual(ver_data["health_percentage"], 100.0)
                self.assertEqual(ver_data["corrupted_chunks"], 0)

                # 3. Check job status endpoint
                job_id = prot_data["job_id"]
                res_job = self.client.get(f"/api/jobs/{job_id}")
                self.assertEqual(res_job.status_code, 200)
                job_data = res_job.json()
                self.assertEqual(job_data["status"], "COMPLETED")
                self.assertEqual(job_data["job_type"], "PROTECT")

                # 4. Check forensic report endpoint
                res_report = self.client.get(f"/api/reports/{job_id}")
                self.assertEqual(res_report.status_code, 200)
                rep_data = res_report.json()
                self.assertEqual(rep_data["operation_id"], job_id)
                self.assertEqual(rep_data["tool_version"], "ReSecure MVP v1.0.0")
                self.assertTrue(rep_data["cryptography"]["manifest_hmac_valid"])

            finally:
                Path(src_path).unlink(missing_ok=True)

    def test_verify_manifest_tampering(self) -> None:
        """Verifies that POST /api/verify with wrong key or tampered manifest returns 403."""
        src_path = make_temp_file(suffix=".txt", content=b"Integrity Testing")

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                res_protect = self.client.post("/api/protect", json={
                    "source_path": src_path,
                    "output_dir": out_dir,
                    "secret_key": "legit-key",
                })
                prot_data = res_protect.json()

                # Verify with wrong key -> 403
                res_bad = self.client.post("/api/verify", json={
                    "source_path": src_path,
                    "manifest_path": prot_data["manifest_path"],
                    "secret_key": "wrong-tampered-key",
                })
                self.assertEqual(res_bad.status_code, 403)
                err = res_bad.json()
                self.assertEqual(err["error_code"], "ERR_MANIFEST_TAMPERED")
            finally:
                Path(src_path).unlink(missing_ok=True)

    def test_recover_endpoint_success(self) -> None:
        """Verifies POST /api/recover reconstructs corrupted file bit-for-bit."""
        payload = b"A" * 16384 + b"B" * 16384 + b"C" * 16384
        src_path = make_temp_file(suffix=".dat", content=payload)
        rec_path = make_temp_file(suffix=".rec.dat", content=b"")

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                # Protect with 50% redundancy (3 chunks -> 2 parity chunks)
                res_prot = self.client.post("/api/protect", json={
                    "source_path": src_path,
                    "redundancy_percentage": 50,
                    "chunk_size_bytes": 16384,
                    "output_dir": out_dir,
                    "secret_key": "rec-key",
                })
                prot_data = res_prot.json()

                # Corrupt chunk 1 in source file
                corrupted = bytearray(payload)
                corrupted[16384:32768] = b"\x00" * 16384
                Path(src_path).write_bytes(corrupted)

                # Call /api/recover
                res_rec = self.client.post("/api/recover", json={
                    "source_path": src_path,
                    "manifest_path": prot_data["manifest_path"],
                    "parity_path": prot_data["parity_path"],
                    "output_path": rec_path,
                    "secret_key": "rec-key",
                })
                self.assertEqual(res_rec.status_code, 200)
                rec_data = res_rec.json()
                self.assertTrue(rec_data["hash_verified_exact"])
                self.assertEqual(rec_data["verdict"], "VERIFIED_EXACT")
                self.assertEqual(rec_data["original_root_sha256"], rec_data["recovered_root_sha256"])

                # Assert recovered file matches original payload
                self.assertEqual(Path(rec_path).read_bytes(), payload)
            finally:
                Path(src_path).unlink(missing_ok=True)
                Path(rec_path).unlink(missing_ok=True)

    def test_recover_damage_exceeds_redundancy_returns_422(self) -> None:
        """Verifies that excessive damage returns 422 SafeFailureResponse with ERR_EXCEEDS_REDUNDANCY."""
        payload = b"ChunkZero" * 2000 + b"ChunkOne" * 2000 + b"ChunkTwo" * 2000
        src_path = make_temp_file(suffix=".dat", content=payload)
        rec_path = make_temp_file(suffix=".rec.dat", content=b"")

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                # 1 parity chunk
                res_prot = self.client.post("/api/protect", json={
                    "source_path": src_path,
                    "redundancy_percentage": 10,
                    "chunk_size_bytes": 16384,
                    "output_dir": out_dir,
                })
                prot_data = res_prot.json()

                # Corrupt 2 chunks (wiping file completely)
                Path(src_path).write_bytes(b"\x00" * len(payload))

                res_rec = self.client.post("/api/recover", json={
                    "source_path": src_path,
                    "manifest_path": prot_data["manifest_path"],
                    "parity_path": prot_data["parity_path"],
                    "output_path": rec_path,
                })
                self.assertEqual(res_rec.status_code, 422)
                fail_data = res_rec.json()
                self.assertEqual(fail_data["error_code"], "ERR_EXCEEDS_REDUNDANCY")
                self.assertEqual(fail_data["verdict"], "UNRECOVERABLE_EXACT")
                self.assertGreater(fail_data["deficit"], 0)
            finally:
                Path(src_path).unlink(missing_ok=True)
                Path(rec_path).unlink(missing_ok=True)

    def test_recover_non_destructive_guard_returns_400(self) -> None:
        """Verifies that output_path == source_path returns 400 Bad Request."""
        src_path = make_temp_file(suffix=".dat", content=b"Test")
        try:
            res = self.client.post("/api/recover", json={
                "source_path": src_path,
                "manifest_path": src_path,
                "parity_path": src_path,
                "output_path": src_path,
            })
            self.assertEqual(res.status_code, 400)
            self.assertEqual(res.json()["error_code"], "ERR_NON_DESTRUCTIVE_VIOLATION")
        finally:
            Path(src_path).unlink(missing_ok=True)

    def test_validate_and_repair_format_endpoints(self) -> None:
        """Verifies POST /api/validate-format and POST /api/repair-format."""
        p_src = make_temp_file(suffix=".json", content=b'{"status": "damaged", "data": [1, 2, ')
        p_out = make_temp_file(suffix=".repaired.json", content=b"")

        try:
            # 1. Validate
            val_res = self.client.post("/api/validate-format", json={
                "source_path": p_src,
                "format": "JSON",
            })
            self.assertEqual(val_res.status_code, 200)
            self.assertFalse(val_res.json()["is_valid"])

            # 2. Repair
            rep_res = self.client.post("/api/repair-format", json={
                "source_path": p_src,
                "output_path": p_out,
                "format": "JSON",
            })
            self.assertEqual(rep_res.status_code, 200)
            rep_data = rep_res.json()
            self.assertEqual(rep_data["verdict"], "STRUCTURALLY_SALVAGED")
            self.assertGreater(rep_data["mutations_count"], 0)

            # Assert repaired output is valid JSON
            val_after = self.client.post("/api/validate-format", json={
                "source_path": p_out,
                "format": "JSON",
            })
            self.assertEqual(val_after.status_code, 200)
            self.assertTrue(val_after.json()["is_valid"])

            # Clean up disclosure log
            Path(rep_data["log_path"]).unlink(missing_ok=True)
        finally:
            Path(p_src).unlink(missing_ok=True)
            Path(p_out).unlink(missing_ok=True)

    def test_path_traversal_middleware(self) -> None:
        """Verifies PathTraversalGuardMiddleware rejects path escape sequences."""
        res = self.client.post("/api/protect", json={
            "source_path": "../../etc/passwd",
        })
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error_code"], "ERR_PATH_TRAVERSAL")
