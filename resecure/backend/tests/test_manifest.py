"""
CalmStacks ReSecure Test Suite - Manifest Authentication & HMAC Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_manifest
"""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from resecure.backend.src.core.manifest import (
    canonical_json_dumps,
    create_manifest_dict,
    read_manifest_file,
    sign_manifest,
    verify_manifest,
    write_manifest_file,
)


class TestManifest(unittest.TestCase):
    """Verifies canonical JSON serialization, HMAC-SHA256 signatures, and tamper detection."""

    def setUp(self) -> None:
        self.sample_chunks = [
            {"index": 0, "offset": 0, "size_bytes": 65536, "sha256": "a" * 64},
            {"index": 1, "offset": 65536, "size_bytes": 32768, "sha256": "b" * 64},
        ]
        self.secret_key = "test-secret-key-resecure-2026"

    def test_canonical_json_serialization(self) -> None:
        """Verifies deterministic sorting of keys and elimination of spaces."""
        obj1 = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
        obj2 = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}

        c1 = canonical_json_dumps(obj1)
        c2 = canonical_json_dumps(obj2)
        self.assertEqual(c1, c2)
        self.assertNotIn(": ", c1)
        self.assertNotIn(", ", c1)

    def test_manifest_creation_and_signing(self) -> None:
        """Verifies full manifest generation, signing, and verification."""
        manifest = create_manifest_dict(
            filename="financial_q3.csv",
            file_size_bytes=98304,
            file_format="CSV",
            mime_type="text/csv",
            root_sha256="c" * 64,
            chunk_size_bytes=65536,
            data_chunks_k=2,
            parity_chunks_m=1,
            redundancy_percentage=50,
            parity_file_name="financial_q3.csv.rsparity",
            chunks=self.sample_chunks,
            secret_key=self.secret_key,
            key_id="k-audit-1",
        )

        self.assertIn("authentication", manifest)
        self.assertEqual(manifest["authentication"]["key_id"], "k-audit-1")
        self.assertIn("hmac_signature", manifest["authentication"])
        self.assertEqual(len(manifest["authentication"]["hmac_signature"]), 64)

        # Verification with correct key passes
        self.assertTrue(verify_manifest(manifest, secret_key=self.secret_key))

        # Verification with wrong key fails
        self.assertFalse(verify_manifest(manifest, secret_key="wrong-secret-key"))

    def test_tamper_detection(self) -> None:
        """Verifies that altering any property in manifest invalidates HMAC."""
        manifest = create_manifest_dict(
            filename="data.json",
            file_size_bytes=65536,
            file_format="JSON",
            mime_type="application/json",
            root_sha256="d" * 64,
            chunk_size_bytes=65536,
            data_chunks_k=1,
            parity_chunks_m=1,
            redundancy_percentage=100,
            parity_file_name="data.json.rsparity",
            chunks=[self.sample_chunks[0]],
            secret_key=self.secret_key,
        )

        self.assertTrue(verify_manifest(manifest, secret_key=self.secret_key))

        # Tampering with file size
        tampered_size = copy.deepcopy(manifest)
        tampered_size["metadata"]["file_size_bytes"] = 12345
        self.assertFalse(verify_manifest(tampered_size, secret_key=self.secret_key))

        # Tampering with chunk hash
        tampered_chunk = copy.deepcopy(manifest)
        tampered_chunk["integrity"]["chunks"][0]["sha256"] = "f" * 64
        self.assertFalse(verify_manifest(tampered_chunk, secret_key=self.secret_key))

        # Tampering with root hash
        tampered_root = copy.deepcopy(manifest)
        tampered_root["integrity"]["root_sha256"] = "e" * 64
        self.assertFalse(verify_manifest(tampered_root, secret_key=self.secret_key))

    def test_file_persistence(self) -> None:
        """Verifies writing and reading manifest file from disk."""
        manifest = create_manifest_dict(
            filename="persisted.txt",
            file_size_bytes=65536,
            file_format="TEXT",
            mime_type="text/plain",
            root_sha256="1" * 64,
            chunk_size_bytes=65536,
            data_chunks_k=1,
            parity_chunks_m=1,
            redundancy_percentage=20,
            parity_file_name="persisted.txt.rsparity",
            chunks=[self.sample_chunks[0]],
            secret_key=self.secret_key,
        )

        with tempfile.NamedTemporaryFile(suffix=".rsmanifest.json", delete=False) as tf:
            tmp_path = tf.name

        try:
            write_manifest_file(tmp_path, manifest)
            loaded = read_manifest_file(tmp_path)
            self.assertEqual(loaded["metadata"]["original_filename"], "persisted.txt")
            self.assertTrue(verify_manifest(loaded, secret_key=self.secret_key))
        finally:
            Path(tmp_path).unlink(missing_ok=True)
