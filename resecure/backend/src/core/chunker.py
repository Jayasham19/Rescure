"""
CalmStacks ReSecure Core Engine - Chunker & Health Evaluator
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.chunker
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

DEFAULT_CHUNK_SIZE = 65536  # 64 KB
ALLOWED_CHUNK_SIZES = (16384, 65536, 262144, 1048576)


def pad_chunk(chunk_data: bytes, target_size: int) -> bytes:
    """Zero-pads a chunk to target_size if shorter, or returns as-is."""
    if len(chunk_data) >= target_size:
        return chunk_data
    return chunk_data + b"\x00" * (target_size - len(chunk_data))


def slice_file_into_chunks(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    pad_final_chunk: bool = False,
) -> Tuple[List[bytes], int]:
    """
    Reads a file into discrete byte chunks.

    Returns:
        (chunks_list, original_file_size)
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {file_path}")

    file_size = path.stat().st_size
    if file_size == 0:
        data = b"\x00" * chunk_size if pad_final_chunk else b""
        return [data], 0

    chunks: List[bytes] = []
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            if pad_final_chunk and len(chunk) < chunk_size:
                chunk = pad_chunk(chunk, chunk_size)
            chunks.append(chunk)

    return chunks, file_size


def classify_corruption(
    chunk_index: int,
    offset: int,
    expected_size: int,
    actual_data: Optional[bytes],
    live_file_size: int,
    expected_file_size: int,
) -> str:
    """
    Identifies the category of data corruption:
    - ZERO_FILL: all live bytes are null (0x00)
    - HEADER_WIPE: corruption located at offset 0 (file header)
    - TRUNCATION: file is truncated before or within this chunk
    - INJECTION: file size exceeds expected file size
    - BIT_FLIP: default non-zero modification
    """
    if actual_data is None or len(actual_data) == 0:
        return "TRUNCATION"

    if live_file_size < expected_file_size and offset + len(actual_data) == live_file_size:
        return "TRUNCATION"

    if live_file_size > expected_file_size:
        return "INJECTION"

    if offset == 0:
        return "HEADER_WIPE"

    if all(b == 0 for b in actual_data):
        return "ZERO_FILL"

    return "BIT_FLIP"


def audit_file_chunks(
    file_path: Union[str, Path],
    manifest_chunks: List[Dict[str, Any]],
    original_file_size: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, Any]:
    """
    Audits a live file against expected chunk hashes recorded in manifest.
    Categorizes each chunk into HEALTHY, CORRUPTED, MISSING, or OVERSIZED.

    Returns dictionary conforming to VerifyFileResponse telemetry.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {file_path}")

    live_file_size = path.stat().st_size
    total_k = len(manifest_chunks)

    healthy_count = 0
    corrupted_count = 0
    missing_count = 0
    oversized_count = 0
    corrupted_indices: List[int] = []
    chunk_health_map: List[Dict[str, Any]] = []
    corruption_events: List[Dict[str, Any]] = []

    # Map expected chunks by index
    expected_map = {c["index"]: c for c in manifest_chunks}

    with path.open("rb") as f:
        for idx in range(total_k):
            expected = expected_map.get(idx)
            if not expected:
                continue

            expected_sha = expected.get("sha256") or expected.get("chunk_sha256")
            expected_offset = expected["offset"]
            expected_size = expected["size_bytes"]

            if expected_offset >= live_file_size:
                # File is truncated before this chunk starts
                status = "MISSING"
                missing_count += 1
                corrupted_indices.append(idx)
                chunk_health_map.append({
                    "index": idx,
                    "offset": expected_offset,
                    "size_bytes": expected_size,
                    "expected_sha256": expected_sha,
                    "live_sha256": None,
                    "status": status,
                })
                corruption_events.append({
                    "chunk_index": idx,
                    "offset_bytes": expected_offset,
                    "expected_sha256": expected_sha,
                    "actual_sha256": None,
                    "corruption_type": "TRUNCATION",
                    "byte_length": expected_size,
                })
                continue

            # Read live chunk
            f.seek(expected_offset)
            live_bytes = f.read(expected_size)
            live_sha = hashlib.sha256(live_bytes).hexdigest()

            if len(live_bytes) < expected_size:
                status = "MISSING"
                missing_count += 1
                corrupted_indices.append(idx)
                corruption_type = "TRUNCATION"
            elif live_sha.lower() == expected_sha.lower():
                status = "HEALTHY"
                healthy_count += 1
                corruption_type = None
            else:
                status = "CORRUPTED"
                corrupted_count += 1
                corrupted_indices.append(idx)
                corruption_type = classify_corruption(
                    chunk_index=idx,
                    offset=expected_offset,
                    expected_size=expected_size,
                    actual_data=live_bytes,
                    live_file_size=live_file_size,
                    expected_file_size=original_file_size,
                )

            chunk_health_map.append({
                "index": idx,
                "offset": expected_offset,
                "size_bytes": len(live_bytes),
                "expected_sha256": expected_sha,
                "live_sha256": live_sha,
                "status": status,
            })

            if corruption_type is not None:
                corruption_events.append({
                    "chunk_index": idx,
                    "offset_bytes": expected_offset,
                    "expected_sha256": expected_sha,
                    "actual_sha256": live_sha,
                    "corruption_type": corruption_type,
                    "byte_length": len(live_bytes),
                })

    # Check for oversized trailing bytes
    if live_file_size > original_file_size:
        oversized_count = 1
        extra_bytes = live_file_size - original_file_size
        chunk_health_map.append({
            "index": total_k,
            "offset": original_file_size,
            "size_bytes": extra_bytes,
            "expected_sha256": "0" * 64,
            "live_sha256": None,
            "status": "OVERSIZED",
        })
        corruption_events.append({
            "chunk_index": total_k,
            "offset_bytes": original_file_size,
            "expected_sha256": "0" * 64,
            "actual_sha256": None,
            "corruption_type": "INJECTION",
            "byte_length": extra_bytes,
        })

    health_pct = round((healthy_count / total_k) * 100.0, 2) if total_k > 0 else 0.0

    return {
        "total_chunks_k": total_k,
        "healthy_chunks": healthy_count,
        "corrupted_chunks": corrupted_count,
        "missing_chunks": missing_count,
        "oversized_chunks": oversized_count,
        "corrupted_indices": corrupted_indices,
        "health_percentage": health_pct,
        "chunk_health_map": chunk_health_map,
        "corruption_events": corruption_events,
    }
