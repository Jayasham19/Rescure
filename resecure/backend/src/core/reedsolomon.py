"""
CalmStacks ReSecure Core Engine - Reed-Solomon GF(2^8) Codec
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.reedsolomon
"""

from __future__ import annotations

import math
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import reedsolo

from .chunker import DEFAULT_CHUNK_SIZE, pad_chunk, slice_file_into_chunks
from .hasher import hash_bytes, hash_file

RSPARITY_MAGIC = b"RSPARITY"
RSPARITY_VERSION = 1
HEADER_FORMAT = "<8sHIHH16s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 34 bytes


class ReedSolomonError(Exception):
    """Base exception for Reed-Solomon codec errors."""
    pass


class RedundancyExceededError(ReedSolomonError):
    """Raised when damaged chunks exceed available parity chunks."""

    def __init__(
        self,
        damaged_count: int,
        parity_available: int,
        deficit: int,
        damaged_indices: List[int],
        message: Optional[str] = None,
    ) -> None:
        self.damaged_count = damaged_count
        self.parity_available = parity_available
        self.deficit = deficit
        self.damaged_indices = damaged_indices
        msg = message or (
            f"Damage ({damaged_count} chunks) exceeds available parity shards "
            f"({parity_available} chunks). Deficit: {deficit} chunks."
        )
        super().__init__(msg)


class IntegrityInvariantError(ReedSolomonError):
    """Raised when reconstructed file hash does not match original root hash."""
    pass


class NonDestructiveViolationError(ReedSolomonError):
    """Raised when output path matches source path."""
    pass


def calculate_parity_count(data_chunks_k: int, redundancy_percent: int) -> int:
    """Calculates number of parity chunks M given K and redundancy percentage (5-100%)."""
    if data_chunks_k <= 0:
        return 1
    pct = max(5, min(100, redundancy_percent))
    m = math.ceil(data_chunks_k * (pct / 100.0))
    return max(1, m)


class ReedSolomonCodec:
    """
    Byte-striped Galois Field GF(2^8) Reed-Solomon Erasure/Parity Codec.
    Provides forward error correction, .rsparity container I/O, exact erasure decoding,
    and strict cryptographic verification.
    """

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        redundancy_percentage: int = 20,
    ) -> None:
        self.chunk_size = chunk_size
        self.redundancy_percentage = max(5, min(100, redundancy_percentage))

    def encode_chunks(
        self,
        data_chunks: List[bytes],
        parity_chunks_m: Optional[int] = None,
    ) -> List[bytes]:
        """
        Generates M parity chunks from K data chunks using byte-striping over GF(2^8).
        Every data chunk is zero-padded to self.chunk_size in memory.
        """
        k = len(data_chunks)
        if k == 0:
            raise ValueError("Cannot encode empty chunk list")

        m = parity_chunks_m or calculate_parity_count(k, self.redundancy_percentage)
        # Ensure k + m <= 255 for standard GF(2^8) single block
        if k + m > 255:
            # For large files with many chunks, process in sub-blocks of size 128
            return self._encode_subblocks(data_chunks, m)

        # Pad all chunks to uniform chunk_size
        padded_chunks = [pad_chunk(c, self.chunk_size) for c in data_chunks]

        rsc = reedsolo.RSCodec(nsym=m)
        parity_chunks = [bytearray(self.chunk_size) for _ in range(m)]

        # Byte-stripe across all K chunks
        for j in range(self.chunk_size):
            stripe = bytes([padded_chunks[i][j] for i in range(k)])
            codeword = rsc.encode(stripe)
            for p_idx in range(m):
                parity_chunks[p_idx][j] = codeword[k + p_idx]

        return [bytes(p) for p in parity_chunks]

    def _encode_subblocks(
        self,
        data_chunks: List[bytes],
        total_m: int,
        block_size: int = 128,
    ) -> List[bytes]:
        """Encodes large chunk sets by partitioning into independent GF(2^8) blocks."""
        k = len(data_chunks)
        blocks = [data_chunks[i:i + block_size] for i in range(0, k, block_size)]
        all_parity: List[bytes] = []

        # Distribute parity chunks proportionally
        for block in blocks:
            blk_k = len(block)
            blk_m = max(1, math.ceil(total_m * (blk_k / k)))
            blk_parity = self.encode_chunks(block, parity_chunks_m=blk_m)
            all_parity.extend(blk_parity)

        return all_parity

    def write_parity_container(
        self,
        parity_path: Union[str, Path],
        data_chunks_k: int,
        parity_chunks: List[bytes],
    ) -> str:
        """
        Serializes parity chunks into standard .rsparity binary container.
        """
        path = Path(parity_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        m = len(parity_chunks)
        header = struct.pack(
            HEADER_FORMAT,
            RSPARITY_MAGIC,
            RSPARITY_VERSION,
            self.chunk_size,
            data_chunks_k,
            m,
            b"\x00" * 16,
        )

        with path.open("wb") as f:
            f.write(header)
            for chunk in parity_chunks:
                if len(chunk) < self.chunk_size:
                    chunk = pad_chunk(chunk, self.chunk_size)
                f.write(chunk)

        return str(path)

    @staticmethod
    def read_parity_container(
        parity_path: Union[str, Path],
    ) -> Tuple[int, int, int, List[bytes]]:
        """
        Reads and parses .rsparity binary container.

        Returns:
            (chunk_size, data_chunks_k, parity_chunks_m, list_of_parity_chunks)
        """
        path = Path(parity_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Parity container not found: {parity_path}")

        file_size = path.stat().st_size
        if file_size < HEADER_SIZE:
            raise ValueError(f"Corrupt parity container: file size {file_size} < header size {HEADER_SIZE}")

        with path.open("rb") as f:
            header_bytes = f.read(HEADER_SIZE)
            magic, version, chunk_size, k, m, reserved = struct.unpack(HEADER_FORMAT, header_bytes)

            if magic != RSPARITY_MAGIC:
                raise ValueError(f"Invalid parity magic header: expected {RSPARITY_MAGIC}, got {magic}")

            expected_data_len = m * chunk_size
            actual_data_len = file_size - HEADER_SIZE
            if actual_data_len < expected_data_len:
                raise ValueError(
                    f"Truncated parity container: expected {expected_data_len} data bytes, found {actual_data_len}"
                )

            parity_chunks: List[bytes] = []
            for _ in range(m):
                chunk = f.read(chunk_size)
                parity_chunks.append(chunk)

        return chunk_size, k, m, parity_chunks

    def decode_erasures(
        self,
        data_chunks: List[Optional[bytes]],
        parity_chunks: List[bytes],
        damaged_indices: List[int],
        original_file_size: int,
    ) -> List[bytes]:
        """
        Exact erasure decoding using Reed-Solomon over GF(2^8).
        Reconstructs missing or corrupted chunks when len(damaged_indices) <= len(parity_chunks).
        """
        k = len(data_chunks)
        m = len(parity_chunks)
        damaged_count = len(damaged_indices)

        if damaged_count > m:
            deficit = damaged_count - m
            raise RedundancyExceededError(
                damaged_count=damaged_count,
                parity_available=m,
                deficit=deficit,
                damaged_indices=sorted(damaged_indices),
            )

        if damaged_count == 0:
            # Nothing damaged, verify and return clean chunks
            clean_chunks: List[bytes] = []
            for i, c in enumerate(data_chunks):
                if c is None:
                    raise ValueError(f"Chunk at index {i} is None but not in damaged_indices")
                clean_chunks.append(c)
            return clean_chunks

        # Ensure all data chunks are padded to chunk_size
        prepared_chunks: List[bytes] = []
        for i in range(k):
            if i in damaged_indices or data_chunks[i] is None:
                prepared_chunks.append(b"\x00" * self.chunk_size)
            else:
                prepared_chunks.append(pad_chunk(data_chunks[i], self.chunk_size))

        prepared_parity = [pad_chunk(p, self.chunk_size) for p in parity_chunks]

        rsc = reedsolo.RSCodec(nsym=m)
        reconstructed_chunks = {idx: bytearray(self.chunk_size) for idx in damaged_indices}

        # Solve striping for each byte position j
        erase_pos = list(damaged_indices)

        try:
            for j in range(self.chunk_size):
                buf = bytearray(k + m)
                for i in range(k):
                    buf[i] = prepared_chunks[i][j]
                for p_idx in range(m):
                    buf[k + p_idx] = prepared_parity[p_idx][j]

                decoded, _, _ = rsc.decode(buf, erase_pos=erase_pos, only_erasures=True)
                for idx in damaged_indices:
                    reconstructed_chunks[idx][j] = decoded[idx]
        except reedsolo.ReedSolomonError as exc:
            raise RedundancyExceededError(
                damaged_count=len(damaged_indices),
                parity_available=m,
                deficit=1,
                damaged_indices=sorted(damaged_indices),
            ) from exc

        # Assemble recovered chunk list
        final_chunks: List[bytes] = []
        for i in range(k):
            if i in damaged_indices:
                final_chunks.append(bytes(reconstructed_chunks[i]))
            else:
                final_chunks.append(prepared_chunks[i])

        return final_chunks

    def recover_file_to_path(
        self,
        source_path: Union[str, Path],
        manifest_chunks: List[Dict[str, Any]],
        parity_path: Union[str, Path],
        output_path: Union[str, Path],
        original_root_sha256: str,
        original_file_size: int,
        damaged_indices: List[int],
    ) -> Dict[str, Any]:
        """
        Executes end-to-end exact file recovery adhering strictly to:
        1. Non-destructive invariant: output_path != source_path.
        2. Safe failure: if damage > parity, raises RedundancyExceededError.
        3. Bit-for-bit mathematical verification: recovered SHA-256 == original_root_sha256.
        """
        src = Path(source_path).resolve()
        out = Path(output_path).resolve()

        if src == out:
            raise NonDestructiveViolationError(
                f"Non-Destructive Invariant Violation: output_path '{out}' must not equal source_path '{src}'"
            )

        chunk_size, k_parity, m, parity_chunks = self.read_parity_container(parity_path)
        self.chunk_size = chunk_size
        k = len(manifest_chunks)

        if len(damaged_indices) > m:
            raise RedundancyExceededError(
                damaged_count=len(damaged_indices),
                parity_available=m,
                deficit=len(damaged_indices) - m,
                damaged_indices=sorted(damaged_indices),
            )

        # Read available live data chunks from source file
        live_file_size = src.stat().st_size if src.exists() else 0
        raw_chunks: List[Optional[bytes]] = []

        with src.open("rb") as f:
            for idx in range(k):
                expected = manifest_chunks[idx]
                offset = expected["offset"]
                size = expected["size_bytes"]
                if idx in damaged_indices:
                    raw_chunks.append(None)
                elif offset >= live_file_size:
                    raw_chunks.append(None)
                else:
                    f.seek(offset)
                    data = f.read(size)
                    raw_chunks.append(data)

        # Decode erasures
        recovered_chunks = self.decode_erasures(
            data_chunks=raw_chunks,
            parity_chunks=parity_chunks,
            damaged_indices=damaged_indices,
            original_file_size=original_file_size,
        )

        # Write to staging temporary file in the target directory
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path_str = tempfile.mkstemp(
            prefix=f".{out.name}.tmp.",
            dir=str(out.parent),
        )
        tmp_path = Path(tmp_path_str)

        try:
            with open(tmp_fd, "wb") as f_out:
                bytes_written = 0
                for idx, c in enumerate(recovered_chunks):
                    if bytes_written >= original_file_size:
                        break
                    # Last chunk may need truncation to original file size
                    remaining = original_file_size - bytes_written
                    to_write = c[:min(len(c), remaining)]
                    f_out.write(to_write)
                    bytes_written += len(to_write)

            # Strictly verify computed SHA-256 against manifest root SHA-256
            recovered_sha256 = hash_file(tmp_path)
            if recovered_sha256.lower() != original_root_sha256.lower():
                raise IntegrityInvariantError(
                    f"Cryptographic Invariant Violation: Reconstructed SHA-256 ({recovered_sha256}) "
                    f"does not match original root SHA-256 ({original_root_sha256})"
                )

            # Atomic commit to target output path
            if out.exists():
                out.unlink()
            tmp_path.replace(out)

            return {
                "source_path": str(src),
                "output_path": str(out),
                "original_root_sha256": original_root_sha256,
                "recovered_root_sha256": recovered_sha256,
                "hash_verified_exact": True,
                "verdict": "VERIFIED_EXACT",
                "parity_shards_consumed": len(damaged_indices),
                "parity_shards_remaining": m - len(damaged_indices),
            }

        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            raise
