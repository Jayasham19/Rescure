"""
CalmStacks ReSecure Application Tier - Protection Service
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.services.protection_service
"""

from __future__ import annotations

import datetime
import math
import mimetypes
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.chunker import DEFAULT_CHUNK_SIZE, pad_chunk, slice_file_into_chunks
from ..core.format_validators import detect_file_format
from ..core.hasher import hash_file_chunks
from ..core.manifest import create_manifest_dict, write_manifest_file
from ..core.reedsolomon import ReedSolomonCodec, calculate_parity_count
from ..db.connection import get_connection_manager
from ..db.models import ChunkModel, FileModel, ManifestModel, RecoveryJobModel
from ..db.repository import ReSecureRepository

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2.0 GB limit


class PayloadTooLargeError(Exception):
    """Raised when input file exceeds maximum allowed size (2.0 GB)."""
    pass


class ProtectionService:
    """Orchestrates cryptographic protection, RS parity generation, manifest signing, and DB cataloging."""

    def __init__(self, repo: Optional[ReSecureRepository] = None) -> None:
        self.repo = repo or ReSecureRepository(get_connection_manager())

    def protect_file(
        self,
        source_path: Union[str, Path],
        redundancy_percentage: int = 20,
        chunk_size_bytes: int = DEFAULT_CHUNK_SIZE,
        output_dir: Optional[Union[str, Path]] = None,
        secret_key: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Slices file, computes SHA-256 chunk/root hashes, generates Reed-Solomon parity,
        writes .rsparity and .rsmanifest.json, and commits metadata to SQLite.
        """
        start_time = time.perf_counter()
        src = Path(source_path).resolve()

        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        file_size = src.stat().st_size
        if file_size > MAX_FILE_SIZE_BYTES:
            raise PayloadTooLargeError(
                f"File size ({file_size} bytes) exceeds maximum permitted limit ({MAX_FILE_SIZE_BYTES} bytes / 2.0 GB)"
            )

        # Determine output directory
        target_dir = Path(output_dir).resolve() if output_dir else src.parent
        target_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = target_dir / f"{src.name}.rsmanifest.json"
        parity_path = target_dir / f"{src.name}.rsparity"

        # 1. Chunk hashing & root SHA-256 calculation
        root_sha256, chunk_hashes, size = hash_file_chunks(src, chunk_size=chunk_size_bytes)
        total_k = len(chunk_hashes)

        # 2. Reed-Solomon parity generation
        codec = ReedSolomonCodec(chunk_size=chunk_size_bytes, redundancy_percentage=redundancy_percentage)
        chunks_data, _ = slice_file_into_chunks(src, chunk_size=chunk_size_bytes)
        parity_chunks_m = calculate_parity_count(total_k, redundancy_percentage)
        parity_chunks = codec.encode_chunks(chunks_data, parity_chunks_m=parity_chunks_m)

        # 3. Write parity container (.rsparity)
        codec.write_parity_container(parity_path, total_k, parity_chunks)

        # 4. Generate & sign manifest (.rsmanifest.json)
        detected_format = detect_file_format(src)
        mime_type, _ = mimetypes.guess_type(str(src))
        mime_type = mime_type or "application/octet-stream"

        manifest_dict = create_manifest_dict(
            filename=src.name,
            file_size_bytes=size,
            file_format=detected_format,
            mime_type=mime_type,
            root_sha256=root_sha256,
            chunk_size_bytes=chunk_size_bytes,
            data_chunks_k=total_k,
            parity_chunks_m=parity_chunks_m,
            redundancy_percentage=redundancy_percentage,
            parity_file_name=parity_path.name,
            chunks=chunk_hashes,
            secret_key=secret_key,
            key_id=key_id,
        )
        write_manifest_file(manifest_path, manifest_dict)

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # 5. Persist to database
        file_id = str(uuid.uuid4())
        manifest_id = str(uuid.uuid4())
        job_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        file_model = FileModel(
            file_id=file_id,
            filename=src.name,
            file_size=size,
            root_sha256=root_sha256,
            mime_type=mime_type,
            file_path=str(src),
            file_format=detected_format,
            created_at=now_iso,
            updated_at=now_iso,
        )
        self.repo.files.create(file_model)

        hmac_sig = manifest_dict["authentication"]["hmac_signature"]
        manifest_model = ManifestModel(
            manifest_id=manifest_id,
            file_id=file_id,
            total_chunks=total_k,
            chunk_size=chunk_size_bytes,
            redundancy_percent=redundancy_percentage,
            parity_chunks=parity_chunks_m,
            hmac_signature=hmac_sig,
            key_id=key_id or manifest_dict["authentication"].get("key_id"),
            raw_manifest_json=manifest_path.read_text(encoding="utf-8"),
            parity_file_path=str(parity_path),
            manifest_version="1.0.0",
            algorithm="Reed-Solomon-GF256",
            created_at=now_iso,
        )
        self.repo.manifests.create(manifest_model)

        # Bulk create chunk records
        db_chunks: List[ChunkModel] = []
        for ch in chunk_hashes:
            db_chunks.append(
                ChunkModel(
                    chunk_id=str(uuid.uuid4()),
                    manifest_id=manifest_id,
                    chunk_index=ch["index"],
                    offset_bytes=ch["offset"],
                    size_bytes=ch["size_bytes"],
                    chunk_sha256=ch["sha256"],
                    is_parity=0,
                    live_sha256=ch["sha256"],
                    status="HEALTHY",
                    last_verified_at=now_iso,
                )
            )

        # Also store parity chunk records
        for p_idx, p_chunk in enumerate(parity_chunks):
            db_chunks.append(
                ChunkModel(
                    chunk_id=str(uuid.uuid4()),
                    manifest_id=manifest_id,
                    chunk_index=p_idx,
                    offset_bytes=p_idx * chunk_size_bytes,
                    size_bytes=len(p_chunk),
                    chunk_sha256=root_sha256[:32] + f"{p_idx:032x}",
                    is_parity=1,
                    live_sha256=root_sha256[:32] + f"{p_idx:032x}",
                    status="HEALTHY",
                    last_verified_at=now_iso,
                )
            )

        self.repo.chunks.create_batch(db_chunks)

        # Log completion job
        job_model = RecoveryJobModel(
            job_id=job_id,
            file_id=file_id,
            manifest_id=manifest_id,
            job_type="PROTECT",
            status="COMPLETED",
            corrupted_chunks_count=0,
            recovered_chunks_count=0,
            original_sha256=root_sha256,
            recovered_sha256=root_sha256,
            sha256_match=1,
            output_path=str(parity_path),
            started_at=now_iso,
            completed_at=now_iso,
            duration_ms=duration_ms,
            progress_pct=100.0,
            source_path=str(src),
            parity_consumed=0,
            verdict="PRISTINE",
        )
        self.repo.jobs.create(job_model)

        return {
            "job_id": job_id,
            "file_id": file_id,
            "manifest_path": str(manifest_path),
            "parity_path": str(parity_path),
            "root_sha256": root_sha256,
            "total_chunks_k": total_k,
            "parity_chunks_m": parity_chunks_m,
            "redundancy_percentage": redundancy_percentage,
            "hmac_signature": hmac_sig,
            "duration_ms": duration_ms,
        }
