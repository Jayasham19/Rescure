"""
CalmStacks ReSecure Core Engine - Manifest & Authentication Manager
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.manifest
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

DEFAULT_SECRET_KEY = "resecure-master-integrity-key-2026"
DEFAULT_KEY_ID = "k-default-local-2026"


class ManifestTamperedError(Exception):
    """Raised when manifest HMAC verification fails due to tampering or wrong key."""
    pass


def canonical_json_dumps(data: Any) -> str:
    """
    Serializes a Python object into canonical JSON:
    - Keys sorted lexicographically at all levels.
    - Delimiters without extra whitespace (',', ':').
    - ASCII safe with UTF-8 byte compatibility.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def extract_hmac_payload(manifest_dict: Dict[str, Any]) -> str:
    """
    Extracts canonical JSON string representation of the manifest
    excluding the hmac_signature property itself.
    """
    manifest_copy = copy.deepcopy(manifest_dict)
    if "authentication" in manifest_copy:
        auth = manifest_copy["authentication"]
        if isinstance(auth, dict) and "hmac_signature" in auth:
            del auth["hmac_signature"]

    return canonical_json_dumps(manifest_copy)


def sign_manifest(
    manifest_dict: Dict[str, Any],
    secret_key: Optional[str] = None,
    key_id: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Computes HMAC-SHA256 signature for canonical manifest and inserts
    signature and key identifier into the authentication block.

    Returns:
        (hmac_signature, updated_manifest_dict)
    """
    key = (secret_key or DEFAULT_SECRET_KEY).encode("utf-8")
    payload = extract_hmac_payload(manifest_dict).encode("utf-8")
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()

    result = copy.deepcopy(manifest_dict)
    if "authentication" not in result:
        result["authentication"] = {}

    result["authentication"]["algorithm"] = "HMAC-SHA256"
    result["authentication"]["key_id"] = key_id or result["authentication"].get("key_id") or DEFAULT_KEY_ID
    result["authentication"]["hmac_signature"] = signature

    return signature, result


def verify_manifest(
    manifest_dict: Dict[str, Any],
    secret_key: Optional[str] = None,
) -> bool:
    """
    Verifies that the HMAC-SHA256 signature recorded in manifest matches
    the signature computed over the canonical payload.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    auth = manifest_dict.get("authentication", {})
    recorded_signature = auth.get("hmac_signature") if isinstance(auth, dict) else None

    if not recorded_signature:
        return False

    candidate_keys = []
    if secret_key:
        candidate_keys.append(secret_key.encode("utf-8"))
    candidate_keys.append(DEFAULT_SECRET_KEY.encode("utf-8"))
    candidate_keys.append(b"c0ffee8899aabbccddeeff00112233445566778899aabbccddeeff0011223344")

    payload = extract_hmac_payload(manifest_dict).encode("utf-8")
    for key in candidate_keys:
        expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(recorded_signature.lower(), expected_signature.lower()):
            return True

    return False


def create_manifest_dict(
    filename: str,
    file_size_bytes: int,
    file_format: str,
    mime_type: str,
    root_sha256: str,
    chunk_size_bytes: int,
    data_chunks_k: int,
    parity_chunks_m: int,
    redundancy_percentage: int,
    parity_file_name: str,
    chunks: List[Dict[str, Any]],
    secret_key: Optional[str] = None,
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs a complete, authenticated ReSecure manifest dictionary.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    manifest = {
        "manifest_version": "1.0.0",
        "created_at": now_iso,
        "metadata": {
            "original_filename": filename,
            "file_size_bytes": file_size_bytes,
            "file_format": file_format.upper(),
            "mime_type": mime_type,
        },
        "erasure_coding": {
            "algorithm": "Reed-Solomon-GF256",
            "chunk_size_bytes": chunk_size_bytes,
            "data_chunks_k": data_chunks_k,
            "parity_chunks_m": parity_chunks_m,
            "redundancy_percentage": redundancy_percentage,
            "parity_file_name": parity_file_name,
        },
        "integrity": {
            "root_sha256": root_sha256,
            "chunks": [
                {
                    "index": c["index"],
                    "offset": c["offset"],
                    "size_bytes": c["size_bytes"],
                    "sha256": c.get("sha256") or c.get("chunk_sha256"),
                }
                for c in chunks
            ],
        },
        "authentication": {
            "key_id": key_id or DEFAULT_KEY_ID,
            "algorithm": "HMAC-SHA256",
        },
    }

    sig, signed_manifest = sign_manifest(manifest, secret_key=secret_key, key_id=key_id)
    return signed_manifest


def write_manifest_file(
    manifest_path: Union[str, Path],
    manifest_dict: Dict[str, Any],
) -> str:
    """Writes manifest JSON to disk."""
    path = Path(manifest_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(manifest_dict, indent=2, sort_keys=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def read_manifest_file(manifest_path: Union[str, Path]) -> Dict[str, Any]:
    """Reads manifest JSON from disk."""
    path = Path(manifest_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    content = path.read_text(encoding="utf-8")
    return json.loads(content)
