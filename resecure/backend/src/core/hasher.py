"""
CalmStacks ReSecure Core Engine - Cryptographic Hasher
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.hasher
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

DEFAULT_CHUNK_SIZE = 65536  # 64 KB


def hash_bytes(data: bytes) -> str:
    """Computes lowercase 64-character SHA-256 hex digest for given byte sequence."""
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Computes full-file SHA-256 hash using streaming chunks to keep memory bounded (<= 150MB RSS).
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {file_path}")

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_file_chunks(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Tuple[str, List[Dict[str, Any]], int]:
    """
    Sequentially streams the file, calculating both the full root SHA-256
    and individual fixed-size chunk hashes in a single pass.

    Returns:
        (root_sha256, chunk_hashes, total_file_size_bytes)
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {file_path}")

    file_size = path.stat().st_size
    root_hasher = hashlib.sha256()
    chunks: List[Dict[str, Any]] = []

    # Handle 0-byte file edge case
    if file_size == 0:
        empty_hash = hashlib.sha256(b"").hexdigest()
        chunks.append({
            "index": 0,
            "offset": 0,
            "size_bytes": 0,
            "sha256": empty_hash,
        })
        return empty_hash, chunks, 0

    chunk_index = 0
    offset = 0

    with path.open("rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            root_hasher.update(data)
            chunk_hash = hashlib.sha256(data).hexdigest()
            chunks.append({
                "index": chunk_index,
                "offset": offset,
                "size_bytes": len(data),
                "sha256": chunk_hash,
            })
            offset += len(data)
            chunk_index += 1

    return root_hasher.hexdigest(), chunks, file_size


def verify_chunk_hash(chunk_data: bytes, expected_sha256: str) -> bool:
    """Verifies that chunk_data matches expected SHA-256 digest."""
    return hashlib.sha256(chunk_data).hexdigest().lower() == expected_sha256.lower()
