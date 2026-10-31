"""
Unit & Integration Tests for One-Click Repair Endpoint
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_one_click_repair
"""

import io
import json
import os
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from resecure.backend.src.api.app import app
from resecure.backend.src.core.hasher import hash_file
from resecure.backend.src.services.protection_service import ProtectionService
from resecure.backend.src.db.connection import get_connection_manager
from resecure.backend.src.db.repository import ReSecureRepository


@pytest.fixture
def client():
    return TestClient(app)


def test_one_click_repair_corrupted_json(client):
    """Test repairing a damaged JSON file with unclosed braces/strings."""
    broken_json = b'{"status": "active", "nodes": [1, 2, 3'  # missing ] and }
    
    response = client.post(
        "/api/one-click-repair",
        files={"file": ("damaged_config.json", io.BytesIO(broken_json), "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "damaged_config.json"
    assert data["detected_format"] == "JSON"
    assert data["verdict"] == "REPAIRED"
    assert data["is_exact"] is False  # Heuristic repair does not pretend exact recovery
    assert data["mutations_count"] > 0
    assert data["download_url"] is not None
    assert "repaired" in data["download_url"]

    # Test downloading the repaired file
    download_res = client.get(data["download_url"])
    assert download_res.status_code == 200
    # Output should parse as valid JSON
    repaired_obj = json.loads(download_res.content)
    assert repaired_obj["status"] == "active"
    assert repaired_obj["nodes"] == [1, 2, 3]


def test_one_click_repair_corrupted_csv(client):
    """Test repairing a damaged CSV file with ragged rows."""
    broken_csv = b"id,name,role\n1,Alice,Admin\n2,Bob\n3,Charlie,User\n"
    
    response = client.post(
        "/api/one-click-repair",
        files={"file": ("users.csv", io.BytesIO(broken_csv), "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["detected_format"] == "CSV"
    assert data["verdict"] == "REPAIRED"
    assert data["download_url"] is not None

    download_res = client.get(data["download_url"])
    assert download_res.status_code == 200
    lines = download_res.content.decode("utf-8").strip().splitlines()
    assert len(lines) == 4
    # Check that Bob's ragged row has been padded with empty column
    assert lines[2] == "2,Bob,"


def test_one_click_repair_pristine_file(client):
    """Test that an already healthy file is identified as PRISTINE with no unwanted mutations."""
    healthy_json = b'{"status": "ok", "version": "1.0"}'
    
    response = client.post(
        "/api/one-click-repair",
        files={"file": ("healthy.json", io.BytesIO(healthy_json), "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "PRISTINE"
    assert data["mutations_count"] == 0
    assert data["is_exact"] is True


def test_one_click_repair_unsupported_binary(client):
    """Test that an unsupported binary format is handled safely and honestly."""
    random_binary = os.urandom(256)
    
    response = client.post(
        "/api/one-click-repair",
        files={"file": ("unknown.dat", io.BytesIO(random_binary), "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "UNSUPPORTED"
    assert data["download_url"] is None
    assert "not supported for heuristic structural repair" in data["message"]


def test_one_click_repair_non_destructive(client):
    """Test that source files are never overwritten or mutated."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = Path(tmp_dir) / "original_telemetry.json"
        content = b'{"server": "alpha", "load": 42'  # broken JSON
        test_file.write_bytes(content)
        original_hash = hash_file(test_file)

        response = client.post(
            "/api/one-click-repair",
            data={"source_path": str(test_file)},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "REPAIRED"

        # Verify original file on disk is completely untouched!
        assert test_file.exists()
        assert test_file.read_bytes() == content
        assert hash_file(test_file) == original_hash
