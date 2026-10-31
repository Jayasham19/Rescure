"""
CalmStacks ReSecure Test Suite - Reed-Solomon Codec & Erasure Recovery Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_reedsolomon
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from resecure.backend.src.core.chunker import slice_file_into_chunks
from resecure.backend.src.core.hasher import hash_file, hash_file_chunks
from resecure.backend.src.core.reedsolomon import (
    IntegrityInvariantError,
    NonDestructiveViolationError,
    RedundancyExceededError,
    ReedSolomonCodec,
    calculate_parity_count,
)


class TestReedSolomonCodec(unittest.TestCase):
    """Verifies Reed-Solomon parity generation, erasure decoding, and safety invariants."""

    def setUp(self) -> None:
        self.chunk_size = 16384  # 16 KB chunks for high test execution speed
        self.codec = ReedSolomonCodec(chunk_size=self.chunk_size, redundancy_percentage=40)

    def test_calculate_parity_count(self) -> None:
        """Verifies calculation of M parity chunks given K and redundancy ratio."""
        # 10 chunks at 20% = 2 parity chunks
        self.assertEqual(calculate_parity_count(10, 20), 2)
        # 5 chunks at 20% = 1 parity chunk
        self.assertEqual(calculate_parity_count(5, 20), 1)
        # 4 chunks at 50% = 2 parity chunks
        self.assertEqual(calculate_parity_count(4, 50), 2)
        # 1 chunk minimum parity is 1
        self.assertEqual(calculate_parity_count(1, 10), 1)

    def test_parity_container_io(self) -> None:
        """Verifies writing and reading .rsparity container."""
        # 3 data chunks, 2 parity chunks
        c1 = b"A" * self.chunk_size
        c2 = b"B" * self.chunk_size
        c3 = b"C" * self.chunk_size
        data_chunks = [c1, c2, c3]

        parity_chunks = self.codec.encode_chunks(data_chunks, parity_chunks_m=2)
        self.assertEqual(len(parity_chunks), 2)
        self.assertEqual(len(parity_chunks[0]), self.chunk_size)
        self.assertEqual(len(parity_chunks[1]), self.chunk_size)

        with tempfile.NamedTemporaryFile(suffix=".rsparity", delete=False) as tf:
            parity_path = tf.name

        try:
            self.codec.write_parity_container(parity_path, len(data_chunks), parity_chunks)
            chunk_size, k, m, read_parity = self.codec.read_parity_container(parity_path)
            self.assertEqual(chunk_size, self.chunk_size)
            self.assertEqual(k, 3)
            self.assertEqual(m, 2)
            self.assertEqual(read_parity[0], parity_chunks[0])
            self.assertEqual(read_parity[1], parity_chunks[1])
        finally:
            Path(parity_path).unlink(missing_ok=True)

    def test_exact_recovery_single_damaged_chunk(self) -> None:
        """Verifies bit-for-bit exact reconstruction when 1 chunk is corrupted."""
        # Create a 4-chunk file (64KB total with 16KB chunk size)
        pristine_payload = b"FIRST_CHUNK_" * (16384 // 12) + b"\x00" * (16384 % 12)
        pristine_payload += b"SECOND_CHUNK" * (16384 // 12) + b"\x00" * (16384 % 12)
        pristine_payload += b"THIRD_CHUNK_" * (16384 // 12) + b"\x00" * (16384 % 12)
        pristine_payload += b"FOURTH_CHUNK" * (16384 // 12) + b"\x00" * (16384 % 12)

        with tempfile.NamedTemporaryFile(suffix=".orig", delete=False) as f_orig, \
             tempfile.NamedTemporaryFile(suffix=".corrupt", delete=False) as f_bad, \
             tempfile.NamedTemporaryFile(suffix=".rsparity", delete=False) as f_parity, \
             tempfile.NamedTemporaryFile(suffix=".recovered", delete=False) as f_rec:
            orig_path = f_orig.name
            bad_path = f_bad.name
            parity_path = f_parity.name
            recovered_path = f_rec.name

        try:
            Path(orig_path).write_bytes(pristine_payload)
            root_sha, chunks_meta, file_size = hash_file_chunks(orig_path, chunk_size=self.chunk_size)

            # Generate parity container (4 data chunks, 2 parity chunks)
            chunks_data, _ = slice_file_into_chunks(orig_path, chunk_size=self.chunk_size)
            parity_chunks = self.codec.encode_chunks(chunks_data, parity_chunks_m=2)
            self.codec.write_parity_container(parity_path, len(chunks_data), parity_chunks)

            # Simulate corruption: overwrite chunk index 1 with random garbage
            bad_data = bytearray(pristine_payload)
            bad_offset = 1 * self.chunk_size
            bad_data[bad_offset:bad_offset + self.chunk_size] = b"\xFF" * self.chunk_size
            Path(bad_path).write_bytes(bad_data)

            # Perform recovery
            result = self.codec.recover_file_to_path(
                source_path=bad_path,
                manifest_chunks=chunks_meta,
                parity_path=parity_path,
                output_path=recovered_path,
                original_root_sha256=root_sha,
                original_file_size=file_size,
                damaged_indices=[1],
            )

            self.assertTrue(result["hash_verified_exact"])
            self.assertEqual(result["verdict"], "VERIFIED_EXACT")
            self.assertEqual(result["parity_shards_consumed"], 1)
            self.assertEqual(result["parity_shards_remaining"], 1)

            # Assert reconstructed file on disk is identical bit-for-bit to pristine original
            recovered_bytes = Path(recovered_path).read_bytes()
            self.assertEqual(recovered_bytes, pristine_payload)
            self.assertEqual(hashlib.sha256(recovered_bytes).hexdigest(), root_sha)
        finally:
            for p in (orig_path, bad_path, parity_path, recovered_path):
                Path(p).unlink(missing_ok=True)

    def test_exact_recovery_multiple_damaged_chunks(self) -> None:
        """Verifies exact reconstruction when 2 chunks are damaged (E == M)."""
        pristine_payload = b"CHUNK0_DATA_" * 1365 + b"END0"
        pristine_payload += b"CHUNK1_DATA_" * 1365 + b"END1"
        pristine_payload += b"CHUNK2_DATA_" * 1365 + b"END2"
        pristine_payload += b"CHUNK3_DATA_" * 1365 + b"END3"

        with tempfile.NamedTemporaryFile(suffix=".orig", delete=False) as f_orig, \
             tempfile.NamedTemporaryFile(suffix=".corrupt", delete=False) as f_bad, \
             tempfile.NamedTemporaryFile(suffix=".rsparity", delete=False) as f_parity, \
             tempfile.NamedTemporaryFile(suffix=".recovered", delete=False) as f_rec:
            orig_path = f_orig.name
            bad_path = f_bad.name
            parity_path = f_parity.name
            recovered_path = f_rec.name

        try:
            Path(orig_path).write_bytes(pristine_payload)
            root_sha, chunks_meta, file_size = hash_file_chunks(orig_path, chunk_size=self.chunk_size)

            chunks_data, _ = slice_file_into_chunks(orig_path, chunk_size=self.chunk_size)
            parity_chunks = self.codec.encode_chunks(chunks_data, parity_chunks_m=2)
            self.codec.write_parity_container(parity_path, len(chunks_data), parity_chunks)

            # Corrupt chunks 0 and 2
            bad_data = bytearray(pristine_payload)
            bad_data[0:1000] = b"\x00" * 1000  # corrupt chunk 0
            offset_2 = 2 * self.chunk_size
            bad_data[offset_2:offset_2 + 1000] = b"\xAA" * 1000  # corrupt chunk 2
            Path(bad_path).write_bytes(bad_data)

            # Recover both
            result = self.codec.recover_file_to_path(
                source_path=bad_path,
                manifest_chunks=chunks_meta,
                parity_path=parity_path,
                output_path=recovered_path,
                original_root_sha256=root_sha,
                original_file_size=file_size,
                damaged_indices=[0, 2],
            )

            self.assertTrue(result["hash_verified_exact"])
            self.assertEqual(Path(recovered_path).read_bytes(), pristine_payload)
        finally:
            for p in (orig_path, bad_path, parity_path, recovered_path):
                Path(p).unlink(missing_ok=True)

    def test_safe_failure_when_damage_exceeds_parity(self) -> None:
        """Verifies that damage > M raises RedundancyExceededError and aborts without outputting corrupt data."""
        pristine_payload = b"X" * (self.chunk_size * 3)

        with tempfile.NamedTemporaryFile(suffix=".orig", delete=False) as f_orig, \
             tempfile.NamedTemporaryFile(suffix=".corrupt", delete=False) as f_bad, \
             tempfile.NamedTemporaryFile(suffix=".rsparity", delete=False) as f_parity, \
             tempfile.NamedTemporaryFile(suffix=".recovered", delete=False) as f_rec:
            orig_path = f_orig.name
            bad_path = f_bad.name
            parity_path = f_parity.name
            recovered_path = f_rec.name

        try:
            Path(orig_path).write_bytes(pristine_payload)
            root_sha, chunks_meta, file_size = hash_file_chunks(orig_path, chunk_size=self.chunk_size)

            chunks_data, _ = slice_file_into_chunks(orig_path, chunk_size=self.chunk_size)
            # 1 parity chunk
            parity_chunks = self.codec.encode_chunks(chunks_data, parity_chunks_m=1)
            self.codec.write_parity_container(parity_path, len(chunks_data), parity_chunks)

            # 2 damaged chunks, but only 1 parity chunk available
            with self.assertRaises(RedundancyExceededError) as ctx:
                self.codec.recover_file_to_path(
                    source_path=bad_path,
                    manifest_chunks=chunks_meta,
                    parity_path=parity_path,
                    output_path=recovered_path,
                    original_root_sha256=root_sha,
                    original_file_size=file_size,
                    damaged_indices=[0, 1],
                )

            err = ctx.exception
            self.assertEqual(err.damaged_count, 2)
            self.assertEqual(err.parity_available, 1)
            self.assertEqual(err.deficit, 1)
            self.assertEqual(err.damaged_indices, [0, 1])

            # Output file must NOT have been created or modified
            # Size of recovered_path should remain 0 (from NamedTemporaryFile) or not exist
            self.assertEqual(Path(recovered_path).stat().st_size, 0)
        finally:
            for p in (orig_path, bad_path, parity_path, recovered_path):
                Path(p).unlink(missing_ok=True)

    def test_non_destructive_invariant_violation(self) -> None:
        """Verifies that setting output_path == source_path raises NonDestructiveViolationError."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
            path = tf.name

        try:
            with self.assertRaises(NonDestructiveViolationError):
                self.codec.recover_file_to_path(
                    source_path=path,
                    manifest_chunks=[],
                    parity_path=path,
                    output_path=path,
                    original_root_sha256="0" * 64,
                    original_file_size=0,
                    damaged_indices=[],
                )
        finally:
            Path(path).unlink(missing_ok=True)
