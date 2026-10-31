"""
CalmStacks ReSecure Application Tier - Verification Service
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.services.verification_service
"""

from __future__ import annotations

import datetime
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.chunker import audit_file_chunks
from ..core.manifest import ManifestTamperedError, read_manifest_file, verify_manifest
from ..db.connection import get_connection_manager
from ..db.models import CorruptionEventModel, RecoveryJobModel
from ..db.repository import ReSecureRepository


class VerificationService:
    """Orchestrates manifest HMAC authentication, chunk-level health audit, and telemetry reporting."""

    def __init__(self, repo: Optional[ReSecureRepository] = None) -> None:
        self.repo = repo or ReSecureRepository(get_connection_manager())

    def verify_file(
        self,
        source_path: Union[str, Path],
        manifest_path: Union[str, Path],
        secret_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validates manifest HMAC, checks live file chunks, categorizes chunk health,
        records corruption events, and persists verification job status.
        """
        start_time = time.perf_counter()
        src = Path(source_path).resolve()
        mf_path = Path(manifest_path).resolve()

        if not mf_path.is_file():
            raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

        if not src.is_file():
            raise FileNotFoundError(f"Target source file not found: {source_path}")

        # 1. Manifest HMAC verification
        manifest_dict = read_manifest_file(mf_path)
        is_hmac_valid = verify_manifest(manifest_dict, secret_key=secret_key)

        if not is_hmac_valid:
            raise ManifestTamperedError(
                f"Security Alert: Manifest HMAC verification failed for '{mf_path}'. "
                f"Manifest may have been tampered with or incorrect key was supplied."
            )

        # 2. Extract manifest parameters
        meta = manifest_dict.get("metadata", {})
        original_size = meta.get("file_size_bytes", 0)
        ec = manifest_dict.get("erasure_coding", {})
        chunk_size = ec.get("chunk_size_bytes", 65536)
        parity_chunks_m = ec.get("parity_chunks_m", 0)

        integrity = manifest_dict.get("integrity", {})
        manifest_chunks = integrity.get("chunks", [])

        # 3. Stream & audit live file
        audit_results = audit_file_chunks(
            file_path=src,
            manifest_chunks=manifest_chunks,
            original_file_size=original_size,
            chunk_size=chunk_size,
        )

        total_k = audit_results["total_chunks_k"]
        healthy_count = audit_results["healthy_chunks"]
        corrupted_count = audit_results["corrupted_chunks"]
        missing_count = audit_results["missing_chunks"]
        oversized_count = audit_results.get("oversized_chunks", 0)
        damaged_total = corrupted_count + missing_count

        # 4. Formulate operational verdict
        if healthy_count == total_k and oversized_count == 0:
            verdict = "PRISTINE"
        elif damaged_total <= parity_chunks_m:
            verdict = "RECOVERABLE"
        else:
            verdict = "UNRECOVERABLE_EXACT"

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # 5. Persist to database
        job_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        job_model = RecoveryJobModel(
            job_id=job_id,
            job_type="VERIFY",
            status="COMPLETED",
            corrupted_chunks_count=corrupted_count,
            recovered_chunks_count=0,
            original_sha256=integrity.get("root_sha256"),
            started_at=now_iso,
            completed_at=now_iso,
            duration_ms=duration_ms,
            progress_pct=100.0,
            source_path=str(src),
            parity_consumed=0,
            verdict=verdict,
        )
        self.repo.jobs.create(job_model)

        # Persist corruption events
        corruption_events = audit_results.get("corruption_events", [])
        if corruption_events:
            event_models: List[CorruptionEventModel] = []
            for ev in corruption_events:
                event_models.append(
                    CorruptionEventModel(
                        event_id=str(uuid.uuid4()),
                        job_id=job_id,
                        chunk_index=ev["chunk_index"],
                        offset_bytes=ev["offset_bytes"],
                        expected_sha256=ev["expected_sha256"],
                        actual_sha256=ev["actual_sha256"],
                        corruption_type=ev["corruption_type"],
                        byte_length=ev["byte_length"],
                        detected_at=now_iso,
                    )
                )
            self.repo.corruption_events.create_batch(event_models)

        return {
            "job_id": job_id,
            "source_path": str(src),
            "manifest_hmac_valid": True,
            "verdict": verdict,
            "health_percentage": audit_results["health_percentage"],
            "total_chunks_k": total_k,
            "healthy_chunks": healthy_count,
            "corrupted_chunks": corrupted_count,
            "missing_chunks": missing_count,
            "corrupted_indices": audit_results["corrupted_indices"],
            "parity_chunks_available": parity_chunks_m,
            "chunk_health_map": audit_results["chunk_health_map"],
            "duration_ms": duration_ms,
        }
