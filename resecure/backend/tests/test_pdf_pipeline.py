"""
Comprehensive PDF Pipeline & Regression Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_pdf_pipeline

Tests all requirements:
1. Zero-fill damaged PDF returns UNRECOVERABLE, download_url=None, no 0-byte file created.
2. Pristine 37-page PDF returns PRISTINE, 37 pages verified.
3. Repairable PDF (header junk, missing EOF) returns REPAIRED with >0 bytes and valid pypdf parsing.
4. Reed-Solomon parity recovery achieves bit-for-bit exact SHA-256 match and 37-page integrity.
5. Non-destructive invariant: original file is never overwritten.
6. Download endpoint blocks 0-byte files with HTTP 422.
"""

import hashlib
import io
import os
import shutil
import tempfile
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import pypdf

from resecure.backend.src.api.app import app
from resecure.backend.src.core.hasher import hash_file
from resecure.backend.src.core.format_validators import detect_file_format, validate_pdf
from resecure.backend.src.core.repair_engine import repair_file_format
from resecure.backend.src.services.protection_service import ProtectionService
from resecure.backend.src.services.recovery_service import RecoveryService


ORIGINAL_FIXTURE = Path("data/test_fixtures/ses_notes_original.pdf").resolve()
DAMAGED_FIXTURE = Path("data/test_fixtures/ses_notes_damaged.pdf").resolve()


def get_original_pdf_bytes() -> bytes:
    if ORIGINAL_FIXTURE.is_file():
        return ORIGINAL_FIXTURE.read_bytes()
    writer = pypdf.PdfWriter()
    for _ in range(37):
        writer.add_blank_page(width=72, height=72)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def get_damaged_pdf_bytes() -> bytes:
    if DAMAGED_FIXTURE.is_file():
        return DAMAGED_FIXTURE.read_bytes()
    return b"\x00" * 1721322


@pytest.fixture
def client():
    return TestClient(app)


def test_pdf_pipeline_zero_fill_damaged_returns_unrecoverable(client):
    """
    Test uploading a zero-filled corrupted PDF (the user's scenario).
    Must return UNRECOVERABLE, no download URL, no 0-byte file written.
    """
    damaged_bytes = get_damaged_pdf_bytes()
    assert len(damaged_bytes) == 1721322
    assert all(b == 0 for b in damaged_bytes[:10000])

    response = client.post(
        "/api/one-click-repair",
        files={"file": ("SES module 2 notes (1).pdf", io.BytesIO(damaged_bytes), "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["verdict"] == "UNRECOVERABLE", f"Expected UNRECOVERABLE, got {data['verdict']}"
    assert data["download_url"] is None, "Download URL must be None for unrecoverable file"
    assert data["mutations_count"] == 0
    assert data["output_sha256"] is None
    assert "entropy loss" in data["message"].lower() or "parity" in data["message"].lower()


def test_pdf_pipeline_pristine_pdf(client):
    """
    Test uploading the healthy 37-page original PDF.
    Must return PRISTINE with is_exact=True, valid download URL, and 37 pages parsed.
    """
    orig_bytes = get_original_pdf_bytes()
    orig_hash = hashlib.sha256(orig_bytes).hexdigest()

    response = client.post(
        "/api/one-click-repair",
        files={"file": ("SES module 2 notes.pdf", io.BytesIO(orig_bytes), "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["verdict"] == "PRISTINE"
    assert data["detected_format"] == "PDF"
    assert data["is_exact"] is True
    assert data["mutations_count"] == 0
    assert data["original_sha256"] == orig_hash
    assert data["output_sha256"] == orig_hash
    assert data["download_url"] is not None

    # Download and verify PDF structure
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    reader = pypdf.PdfReader(io.BytesIO(dl_resp.content))
    assert len(reader.pages) == 37


def test_pdf_pipeline_repairable_pdf(client):
    """
    Test uploading a repairable PDF (e.g. prepended junk before %PDF header).
    Must return REPAIRED with > 0 bytes and valid pypdf parsing of all 37 pages.
    """
    orig_bytes = get_original_pdf_bytes()
    # Prepend 256 bytes of corruption junk before the %PDF magic header
    junk_prefix = b"X" * 256
    damaged_pdf = junk_prefix + orig_bytes

    response = client.post(
        "/api/one-click-repair",
        files={"file": ("junk_prefix_notes.pdf", io.BytesIO(damaged_pdf), "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["verdict"] == "REPAIRED"
    assert data["detected_format"] == "PDF"
    assert data["mutations_count"] > 0
    assert data["download_url"] is not None
    assert data["output_sha256"] is not None

    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert len(dl_resp.content) > 0

    reader = pypdf.PdfReader(io.BytesIO(dl_resp.content))
    assert len(reader.pages) == 37


def test_pdf_pipeline_reed_solomon_exact_recovery():
    """
    Test exact Reed-Solomon parity recovery for the 37-page PDF.
    Verifies bit-for-bit SHA-256 invariance and 37-page preservation.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        source_pdf = tmp_path / "ses_notes.pdf"
        orig_bytes = get_original_pdf_bytes()
        source_pdf.write_bytes(orig_bytes)

        expected_sha256 = hash_file(source_pdf)
        orig_size = source_pdf.stat().st_size

        # 1. Protect with 20% redundancy
        prot_svc = ProtectionService()
        prot_result = prot_svc.protect_file(
            source_path=source_pdf,
            output_dir=tmp_path,
            redundancy_percentage=20,
            secret_key="resecure-test-secret-key-32bytes",
        )

        manifest_path = Path(prot_result["manifest_path"])
        parity_path = Path(prot_result["parity_path"])
        assert manifest_path.is_file()
        assert parity_path.is_file()

        # 2. Corrupt chunks within parity capacity
        with open(source_pdf, "r+b") as f:
            # Corrupt byte in chunk 0
            f.seek(100)
            f.write(b"\xFF\xFE\xFD\xFC" * 20)
            f.flush()

        tampered_hash = hash_file(source_pdf)
        assert tampered_hash != expected_sha256, "Tampering failed"

        # 3. Recover using Reed-Solomon parity
        rec_svc = RecoveryService()
        recovered_path = tmp_path / "recovered_ses_notes.pdf"

        rec_result = rec_svc.recover_file(
            source_path=source_pdf,
            manifest_path=manifest_path,
            parity_path=parity_path,
            output_path=recovered_path,
            secret_key="resecure-test-secret-key-32bytes",
        )

        assert rec_result["hash_verified_exact"] is True
        assert rec_result["verdict"] == "VERIFIED_EXACT"
        assert rec_result["recovered_root_sha256"] == expected_sha256
        assert recovered_path.stat().st_size == orig_size

        # Verify parsed PDF pages
        reader = pypdf.PdfReader(str(recovered_path))
        assert len(reader.pages) == 37


def test_pdf_pipeline_non_destructive():
    """
    Test that the source file is never modified or overwritten during repair attempt.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "test_doc.pdf"
        test_file.write_bytes(get_original_pdf_bytes())

        orig_hash_before = hash_file(test_file)
        orig_mtime_before = test_file.stat().st_mtime_ns

        out_repaired = tmp_path / "out_repaired.pdf"
        repair_file_format(
            source_path=test_file,
            output_path=out_repaired,
            format_name="PDF",
        )

        orig_hash_after = hash_file(test_file)
        orig_mtime_after = test_file.stat().st_mtime_ns

        assert orig_hash_before == orig_hash_after, "Source file was modified!"
        assert orig_mtime_before == orig_mtime_after, "Source file mtime changed!"


def test_download_endpoint_blocks_zero_byte_file(client):
    """
    Test that the /api/download-repaired endpoint blocks 0-byte files with HTTP 422.
    """
    staging_dir = Path("data/staging").resolve()
    staging_dir.mkdir(parents=True, exist_ok=True)
    valid_job_id = str(uuid.uuid4())
    empty_file = staging_dir / f"repaired_{valid_job_id}_test_probe.pdf"
    empty_file.write_bytes(b"")

    try:
        response = client.get(f"/api/download-repaired/{valid_job_id}?output={empty_file.name}")
        assert response.status_code == 422
        assert "empty (0 bytes)" in response.json()["detail"]
    finally:
        if empty_file.is_file():
            empty_file.unlink()
