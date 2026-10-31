"""
CalmStacks ReSecure Test Suite - Non-Destructive Invariant Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_non_destructive
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from resecure.backend.src.core.chunker import audit_file_chunks, slice_file_into_chunks
from resecure.backend.src.core.hasher import hash_file, hash_file_chunks
from resecure.backend.src.core.reedsolomon import ReedSolomonCodec
from resecure.backend.src.core.repair_engine import repair_file_format


class TestNonDestructiveInvariant(unittest.TestCase):
    """
    CRITICAL TENET: Non-Destructive Guarantee.
    Verifies that the original source file's SHA-256 hash remains 100% UNCHANGED
    before, during, and after EVERY operation:
    1. Chunk hashing & manifest generation
    2. Verification & corruption detection
    3. Reed-Solomon parity recovery
    4. Heuristic structural repair
    """

    def setUp(self) -> None:
        self.chunk_size = 16384
        self.codec = ReedSolomonCodec(chunk_size=self.chunk_size, redundancy_percentage=50)

    def test_source_remains_unmodified_throughout_lifecycle(self) -> None:
        """Asserts bit-for-bit invariance of input files across all operations."""
        source_content = b"CRITICAL_FORENSIC_ARTIFACT_DO_NOT_TOUCH_" * 500

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_src, \
             tempfile.NamedTemporaryFile(suffix=".rsparity", delete=False) as f_parity, \
             tempfile.NamedTemporaryFile(suffix=".recovered.csv", delete=False) as f_rec, \
             tempfile.NamedTemporaryFile(suffix=".repaired.csv", delete=False) as f_rep:
            src_path = f_src.name
            parity_path = f_parity.name
            recovered_path = f_rec.name
            repaired_path = f_rep.name

        try:
            Path(src_path).write_bytes(source_content)
            original_sha256 = hashlib.sha256(source_content).hexdigest()

            # 1. Protection & Hashing
            root_sha, chunks_meta, file_size = hash_file_chunks(src_path, chunk_size=self.chunk_size)
            chunks_data, _ = slice_file_into_chunks(src_path, chunk_size=self.chunk_size)
            parity_chunks = self.codec.encode_chunks(chunks_data, parity_chunks_m=2)
            self.codec.write_parity_container(parity_path, len(chunks_data), parity_chunks)

            # ASSERT: source file untouched
            self.assertEqual(hash_file(src_path), original_sha256)

            # 2. Verification audit
            audit_res = audit_file_chunks(
                file_path=src_path,
                manifest_chunks=chunks_meta,
                original_file_size=file_size,
                chunk_size=self.chunk_size,
            )
            self.assertEqual(audit_res["healthy_chunks"], len(chunks_meta))

            # ASSERT: source file untouched
            self.assertEqual(hash_file(src_path), original_sha256)

            # 3. Recovery operation
            rec_res = self.codec.recover_file_to_path(
                source_path=src_path,
                manifest_chunks=chunks_meta,
                parity_path=parity_path,
                output_path=recovered_path,
                original_root_sha256=original_sha256,
                original_file_size=file_size,
                damaged_indices=[],
            )
            self.assertTrue(rec_res["hash_verified_exact"])

            # ASSERT: source file untouched
            self.assertEqual(hash_file(src_path), original_sha256)

            # 4. Heuristic repair operation
            rep_res = repair_file_format(
                source_path=src_path,
                output_path=repaired_path,
                format_name="CSV",
            )
            self.assertEqual(rep_res["verdict"], "STRUCTURALLY_SALVAGED")

            # ASSERT: source file untouched
            self.assertEqual(hash_file(src_path), original_sha256)

            # Clean up disclosure log
            Path(rep_res["log_path"]).unlink(missing_ok=True)
        finally:
            for p in (src_path, parity_path, recovered_path, repaired_path):
                Path(p).unlink(missing_ok=True)
