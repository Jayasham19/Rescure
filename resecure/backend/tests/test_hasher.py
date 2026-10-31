"""
CalmStacks ReSecure Test Suite - Hasher & Streaming Chunk Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_hasher
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from resecure.backend.src.core.hasher import (
    DEFAULT_CHUNK_SIZE,
    hash_bytes,
    hash_file,
    hash_file_chunks,
    verify_chunk_hash,
)


class TestHasher(unittest.TestCase):
    """Verifies streaming SHA-256 calculation, chunk hashing, and boundary conditions."""

    def test_hash_bytes(self) -> None:
        """Verifies hash_bytes matches hashlib standard SHA-256."""
        data = b"CalmStacks ReSecure Cybersecurity Engine 2026"
        expected = hashlib.sha256(data).hexdigest()
        self.assertEqual(hash_bytes(data), expected)

    def test_hash_file_and_chunking(self) -> None:
        """Verifies full-file streaming hash matches whole-file hash."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
            # 192 KB file -> exactly 3 chunks of 64KB
            payload = b"A" * 65536 + b"B" * 65536 + b"C" * 65536
            tf.write(payload)
            tmp_path = tf.name

        try:
            expected_root = hashlib.sha256(payload).hexdigest()
            computed_root = hash_file(tmp_path)
            self.assertEqual(computed_root, expected_root)

            root_hash, chunks, file_size = hash_file_chunks(tmp_path, chunk_size=65536)
            self.assertEqual(root_hash, expected_root)
            self.assertEqual(file_size, len(payload))
            self.assertEqual(len(chunks), 3)

            # Check individual chunk hashes and offsets
            self.assertEqual(chunks[0]["offset"], 0)
            self.assertEqual(chunks[0]["size_bytes"], 65536)
            self.assertEqual(chunks[0]["sha256"], hashlib.sha256(b"A" * 65536).hexdigest())

            self.assertEqual(chunks[1]["offset"], 65536)
            self.assertEqual(chunks[1]["size_bytes"], 65536)
            self.assertEqual(chunks[1]["sha256"], hashlib.sha256(b"B" * 65536).hexdigest())

            self.assertEqual(chunks[2]["offset"], 131072)
            self.assertEqual(chunks[2]["size_bytes"], 65536)
            self.assertEqual(chunks[2]["sha256"], hashlib.sha256(b"C" * 65536).hexdigest())

            self.assertTrue(verify_chunk_hash(b"A" * 65536, chunks[0]["sha256"]))
            self.assertFalse(verify_chunk_hash(b"X" * 65536, chunks[0]["sha256"]))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_zero_byte_file(self) -> None:
        """Verifies handling of 0-byte empty file."""
        with tempfile.NamedTemporaryFile(suffix=".empty", delete=False) as tf:
            tmp_path = tf.name

        try:
            empty_sha = hashlib.sha256(b"").hexdigest()
            root_hash, chunks, size = hash_file_chunks(tmp_path)
            self.assertEqual(root_hash, empty_sha)
            self.assertEqual(size, 0)
            self.assertEqual(len(chunks), 1)
            self.assertEqual(chunks[0]["size_bytes"], 0)
            self.assertEqual(chunks[0]["sha256"], empty_sha)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_partial_chunk(self) -> None:
        """Verifies handling of files with uneven final chunk (e.g. 100KB with 64KB chunk size)."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
            payload = b"Z" * 100000
            tf.write(payload)
            tmp_path = tf.name

        try:
            root_hash, chunks, size = hash_file_chunks(tmp_path, chunk_size=65536)
            self.assertEqual(size, 100000)
            self.assertEqual(len(chunks), 2)
            self.assertEqual(chunks[0]["size_bytes"], 65536)
            self.assertEqual(chunks[1]["size_bytes"], 34464)
            self.assertEqual(chunks[1]["offset"], 65536)
            self.assertEqual(root_hash, hashlib.sha256(payload).hexdigest())
        finally:
            Path(tmp_path).unlink(missing_ok=True)
