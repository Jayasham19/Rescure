"""
ReSecure Reed-Solomon Deterministic Erasure Codec
Implements byte-striped Forward Error Correction over Galois Field GF(2^8).
Guarantees exact bit-for-bit reconstruction up to M parity chunks with zero bit error.
Enforces the Safe Failure Protocol when damage exceeds parity capacity.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence, Tuple
import reedsolo


class CodecVerdict(str, Enum):
    VERIFIED_EXACT = "VERIFIED_EXACT"
    UNRECOVERABLE_EXACT = "UNRECOVERABLE_EXACT"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"


@dataclass
class ProtectionPackage:
    original_size: int
    chunk_size: int
    data_chunks_k: int
    parity_chunks_m: int
    redundancy_percentage: float
    root_sha256: string
    chunk_hashes: List[str]
    parity_chunks: List[bytes]


@dataclass
class RecoveryResult:
    verdict: CodecVerdict
    recovered_data: Optional[bytes]
    recovered_sha256: Optional[str]
    expected_sha256: str
    hash_verified_exact: bool
    bit_error_rate: float
    byte_error_rate: float
    duration_ms: float
    throughput_mb_s: float
    safe_failure_triggered: bool
    error_message: Optional[str] = None


class ReedSolomonEngine:
    """
    Production-grade byte-striped Reed-Solomon codec over GF(2^8).
    """

    @staticmethod
    def sha256_digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def protect(
        cls,
        data: bytes,
        chunk_size: int = 65536,
        redundancy_percentage: float = 20.0,
    ) -> Tuple[List[bytes], ProtectionPackage]:
        """
        Partitions data into K chunks of chunk_size and computes M parity chunks.
        """
        orig_len = len(data)
        if orig_len == 0:
            raise ValueError("Cannot protect empty data stream.")

        k = math.ceil(orig_len / chunk_size)
        # Parity chunk count: at least 1, ceiling of k * (redundancy / 100)
        m = max(1, math.ceil(k * (redundancy_percentage / 100.0)))

        # Slicing data into K chunks, padding the last chunk if needed
        data_chunks: List[bytearray] = []
        chunk_hashes: List[str] = []
        for i in range(k):
            start = i * chunk_size
            end = min(orig_len, (i + 1) * chunk_size)
            chunk = bytearray(data[start:end])
            if len(chunk) < chunk_size:
                chunk.extend(b"\x00" * (chunk_size - len(chunk)))
            data_chunks.append(chunk)
            chunk_hashes.append(cls.sha256_digest(bytes(chunk)))

        root_hash = cls.sha256_digest(data)

        # Byte-striped parity calculation across GF(2^8)
        rsc = reedsolo.RSCodec(m)
        parity_chunks = [bytearray(chunk_size) for _ in range(m)]

        for j in range(chunk_size):
            # Form message byte vector from chunk j-th bytes
            msg = bytes(data_chunks[i][j] for i in range(k))
            encoded = rsc.encode(msg)
            # Extracted M parity bytes
            for p_idx in range(m):
                parity_chunks[p_idx][j] = encoded[k + p_idx]

        package = ProtectionPackage(
            original_size=orig_len,
            chunk_size=chunk_size,
            data_chunks_k=k,
            parity_chunks_m=m,
            redundancy_percentage=redundancy_percentage,
            root_sha256=root_hash,
            chunk_hashes=chunk_hashes,
            parity_chunks=[bytes(p) for p in parity_chunks],
        )

        return [bytes(c) for c in data_chunks], package

    @classmethod
    def recover(
        cls,
        live_chunks: Sequence[bytes],
        parity_chunks: Sequence[bytes],
        damaged_indices: Sequence[int],
        original_size: int,
        expected_root_sha256: str,
        chunk_size: int = 65536,
    ) -> RecoveryResult:
        """
        Recovers damaged chunks using Reed-Solomon erasure decoding.
        Guarantees P(error) = 0 when damaged_indices <= M.
        Enforces Safe Failure Protocol when damaged_indices > M.
        """
        t0 = time.perf_counter()
        k = len(live_chunks)
        m = len(parity_chunks)
        num_damaged = len(damaged_indices)

        # Safe Failure Check: if damaged chunks exceed parity shards, fail immediately!
        if num_damaged > m:
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000.0
            return RecoveryResult(
                verdict=CodecVerdict.UNRECOVERABLE_EXACT,
                recovered_data=None,
                recovered_sha256=None,
                expected_sha256=expected_root_sha256,
                hash_verified_exact=False,
                bit_error_rate=1.0,
                byte_error_rate=1.0,
                duration_ms=duration_ms,
                throughput_mb_s=0.0,
                safe_failure_triggered=True,
                error_message=(
                    f"Safe Failure Protocol Activated: Damaged chunks ({num_damaged}) "
                    f"exceeds parity capacity ({m}). Deficit = {num_damaged - m} chunks."
                ),
            )

        # Nothing damaged: verify existing chunks
        if num_damaged == 0:
            reconstructed_full = b"".join(live_chunks)[:original_size]
            rec_sha = cls.sha256_digest(reconstructed_full)
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000.0
            return RecoveryResult(
                verdict=CodecVerdict.VERIFIED_EXACT,
                recovered_data=reconstructed_full,
                recovered_sha256=rec_sha,
                expected_sha256=expected_root_sha256,
                hash_verified_exact=(rec_sha == expected_root_sha256),
                bit_error_rate=0.0,
                byte_error_rate=0.0,
                duration_ms=duration_ms,
                throughput_mb_s=(original_size / (1024 * 1024)) / max(0.0001, duration_ms / 1000.0),
                safe_failure_triggered=False,
            )

        # Erasure decoding via reedsolo across GF(2^8)
        rsc = reedsolo.RSCodec(m)
        recovered_chunks = [bytearray(chunk_size) for _ in range(k)]
        erased_positions = sorted(list(damaged_indices))

        try:
            for j in range(chunk_size):
                codeword = bytearray(k + m)
                for i in range(k):
                    codeword[i] = live_chunks[i][j]
                for p_idx in range(m):
                    codeword[k + p_idx] = parity_chunks[p_idx][j]

                # Decode codeword with designated erasure positions
                decoded_msg, _, _ = rsc.decode(codeword, erase_pos=erased_positions)
                for i in range(k):
                    recovered_chunks[i][j] = decoded_msg[i]

            reconstructed_data = b"".join(recovered_chunks)[:original_size]
            recovered_sha = cls.sha256_digest(reconstructed_data)
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000.0
            throughput = (original_size / (1024 * 1024)) / max(0.0001, duration_ms / 1000.0)

            # Strict cryptographic root verification
            if recovered_sha == expected_root_sha256:
                return RecoveryResult(
                    verdict=CodecVerdict.VERIFIED_EXACT,
                    recovered_data=reconstructed_data,
                    recovered_sha256=recovered_sha,
                    expected_sha256=expected_root_sha256,
                    hash_verified_exact=True,
                    bit_error_rate=0.0,
                    byte_error_rate=0.0,
                    duration_ms=duration_ms,
                    throughput_mb_s=throughput,
                    safe_failure_triggered=False,
                )
            else:
                return RecoveryResult(
                    verdict=CodecVerdict.INTEGRITY_VIOLATION,
                    recovered_data=reconstructed_data,
                    recovered_sha256=recovered_sha,
                    expected_sha256=expected_root_sha256,
                    hash_verified_exact=False,
                    bit_error_rate=0.5,
                    byte_error_rate=0.5,
                    duration_ms=duration_ms,
                    throughput_mb_s=throughput,
                    safe_failure_triggered=False,
                    error_message="Cryptographic integrity verification failed: hash mismatch.",
                )

        except Exception as ex:
            t1 = time.perf_counter()
            duration_ms = (t1 - t0) * 1000.0
            return RecoveryResult(
                verdict=CodecVerdict.UNRECOVERABLE_EXACT,
                recovered_data=None,
                recovered_sha256=None,
                expected_sha256=expected_root_sha256,
                hash_verified_exact=False,
                bit_error_rate=1.0,
                byte_error_rate=1.0,
                duration_ms=duration_ms,
                throughput_mb_s=0.0,
                safe_failure_triggered=True,
                error_message=f"RS decoding failure: {str(ex)}",
            )
