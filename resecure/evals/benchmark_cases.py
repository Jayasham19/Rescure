"""
ReSecure Evaluation Benchmark Suite: Test Case Generator
Generates synthetic and realistic test corruption scenarios across
Text, CSV, JSON, PNG, and JPEG assets with fine-grained ground truth metadata.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

from resecure.ai.classifier import CorruptionType
from resecure.ai.format_detector import FileFormat
from resecure.evals.codec import ProtectionPackage, ReedSolomonEngine


@dataclass
class BenchmarkTestCase:
    """Comprehensive test case definition with full ground truth."""
    case_id: str
    format: FileFormat
    corruption_type: CorruptionType
    description: str
    original_data: bytes
    corrupted_data: bytes
    expected_root_sha256: str
    corrupted_root_sha256: str
    chunk_size: int
    data_chunks_k: int
    parity_chunks_m: int
    redundancy_percentage: float
    damaged_chunk_indices: List[int]
    is_recoverable_by_rs: bool  # len(damaged_indices) <= parity_chunks_m
    original_chunks: List[bytes]
    corrupted_chunks: List[bytes]
    parity_chunks: List[bytes]
    metadata: Dict[str, Any] = field(default_factory=dict)


def generate_pristine_text() -> bytes:
    """Generates realistic technical document / policy text."""
    return (
        "# ReSecure Zero-Trust Security Policy\n"
        "Version: 2.4.0\n"
        "Classification: CONFIDENTIAL / CYBER DEFENSE\n\n"
        "1. PRINCIPLE OF LEAST PRIVILEGE\n"
        "All worker agents and processes must operate under strictly scoped identities.\n"
        "Direct socket execution and outbound cloud telemetry are forbidden in air-gapped zones.\n\n"
        "2. CRYPTOGRAPHIC DATA INTEGRITY ASSURANCE\n"
        "Data stores must enforce SHA-256 root manifests and HMAC authentication.\n"
        "Deterministic Reed-Solomon forward error correction over GF(2^8) must take precedence\n"
        "over non-deterministic probabilistic approximations.\n\n"
        "3. SAFE FAILURE SPECIFICATION\n"
        "When detected corruption exceeds available parity redundancy (E > M), the system\n"
        "must trigger an atomic fail-closed halt and refuse to emit corrupted payload.\n\n"
        "4. INCIDENT AUDIT TRAIL\n"
        "Every file modification, recovery attempt, and chunk verification event must be logged\n"
        "with monotonic microsecond timestamps and immutable hash chain pointers.\n"
        "Authorized by: CISO Cryptographic Assurance Group.\n"
    ).encode("utf-8")


def generate_pristine_csv() -> bytes:
    """Generates realistic financial transaction ledger CSV."""
    rows = [
        "tx_id,timestamp_utc,source_account,dest_account,amount_usd,currency,fee_usd,status,auth_code",
    ]
    random.seed(42)
    accounts = [f"ACC-{1000 + i}" for i in range(10)]
    for tx_num in range(1001, 1026):
        src = random.choice(accounts)
        dst = random.choice([a for a in accounts if a != src])
        amount = round(random.uniform(50.0, 9500.0), 2)
        fee = round(amount * 0.0015, 2)
        auth = hashlib.sha256(f"{tx_num}-{src}-{dst}-{amount}".encode()).hexdigest()[:8].upper()
        rows.append(f"{tx_num},2026-10-22T14:{tx_num % 60:02d}:00Z,{src},{dst},{amount:.2f},USD,{fee:.2f},SETTLED,{auth}")
    return "\r\n".join(rows).encode("utf-8")


def generate_pristine_json() -> bytes:
    """Generates complex structured enterprise configuration JSON."""
    payload = {
        "$schema": "https://calmstacks.dev/schemas/resecure-node-config.v1.json",
        "node_id": "RS-GATEWAY-NODE-077",
        "cluster": "us-east-cyber-enclave",
        "active": True,
        "max_concurrent_jobs": 8,
        "quarantine_retention_days": 30,
        "cryptographic_policies": {
            "root_hash_algorithm": "SHA-256",
            "hmac_key_derivation": "PBKDF2-HMAC-SHA256",
            "erasure_coding": {
                "algorithm": "Reed-Solomon-GF256",
                "default_redundancy_pct": 25.0,
                "chunk_size_bytes": 65536,
                "safe_failure_enforced": True,
            },
        },
        "monitored_directories": [
            {"path": "/var/resecure/vault", "scan_interval_sec": 60, "priority": "HIGH"},
            {"path": "/var/resecure/backups", "scan_interval_sec": 300, "priority": "MEDIUM"},
            {"path": "/etc/resecure/keys", "scan_interval_sec": 10, "priority": "CRITICAL"},
        ],
        "telemetry_metrics": {
            "uptime_seconds": 1845920,
            "total_files_protected": 45190,
            "corruptions_repaired": 142,
            "safe_failures_recorded": 3,
            "average_throughput_mb_s": 84.75,
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


def generate_pristine_png() -> bytes:
    """Generates valid binary PNG image with color gradient and standard chunks."""
    img = Image.new("RGB", (64, 64), color=(30, 45, 90))
    # Draw simple gradient pattern
    pixels = img.load()
    for x in range(64):
        for y in range(64):
            pixels[x, y] = (int(x * 3.8), int(y * 3.8), int((x + y) * 1.9))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_pristine_jpeg() -> bytes:
    """Generates valid binary JPEG image with standard JFIF/DQT/DHT markers."""
    img = Image.new("RGB", (64, 64), color=(180, 50, 40))
    pixels = img.load()
    for x in range(64):
        for y in range(64):
            pixels[x, y] = (int(x * 3.5), int((64 - y) * 3.5), int(128))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


class BenchmarkCaseFactory:
    """
    Factory creating systematic test suites across all formats and corruption patterns.
    """

    @classmethod
    def create_suite(cls) -> List[BenchmarkTestCase]:
        cases: List[BenchmarkTestCase] = []

        # Ground truth assets
        pristine_assets = {
            FileFormat.TEXT: generate_pristine_text(),
            FileFormat.CSV: generate_pristine_csv(),
            FileFormat.JSON: generate_pristine_json(),
            FileFormat.PNG: generate_pristine_png(),
            FileFormat.JPEG: generate_pristine_jpeg(),
        }

        # 1. Single Bit Flip across all formats (Within Redundancy: 1 chunk damaged <= M)
        for fmt, data in pristine_assets.items():
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_BIT_FLIP",
                fmt=fmt,
                corruption_type=CorruptionType.BIT_FLIP,
                description=f"Single bit flip in middle chunk of {fmt.value} file",
                data=data,
                mutator=cls._mutate_bit_flip,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 2. Ransomware Header Wipe across all formats (Within Redundancy: Chunk 0 wiped <= M)
        for fmt, data in pristine_assets.items():
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_HEADER_WIPE",
                fmt=fmt,
                corruption_type=CorruptionType.HEADER_WIPE,
                description=f"Ransomware wiped magic bytes and header in chunk 0 of {fmt.value}",
                data=data,
                mutator=cls._mutate_header_wipe,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 3. Zero Fill across all formats (Within Redundancy: 1 chunk zeroed <= M)
        for fmt, data in pristine_assets.items():
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_ZERO_FILL",
                fmt=fmt,
                corruption_type=CorruptionType.ZERO_FILL,
                description=f"Zero-fill block wipe in chunk 1 of {fmt.value}",
                data=data,
                mutator=cls._mutate_zero_fill,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 4. Truncation across all formats (Within Redundancy: trailing chunk missing <= M)
        for fmt, data in pristine_assets.items():
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_TRUNCATION",
                fmt=fmt,
                corruption_type=CorruptionType.TRUNCATION,
                description=f"Network drop truncation removing final chunk of {fmt.value}",
                data=data,
                mutator=cls._mutate_truncation,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 5. Ransomware Encryption across all formats (Within Redundancy: 1 chunk encrypted <= M)
        for fmt, data in pristine_assets.items():
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_RANSOMWARE_ENCRYPTION",
                fmt=fmt,
                corruption_type=CorruptionType.RANSOMWARE_ENCRYPTION,
                description=f"Ransomware high-entropy encrypted chunk overwrite in {fmt.value}",
                data=data,
                mutator=cls._mutate_ransomware_encryption,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 6. Line Ending Corruption (Text-family: TEXT, CSV, JSON)
        for fmt in [FileFormat.TEXT, FileFormat.CSV, FileFormat.JSON]:
            data = pristine_assets[fmt]
            case = cls._build_case(
                case_id=f"CASE_{fmt.value}_LINE_ENDING",
                fmt=fmt,
                corruption_type=CorruptionType.LINE_ENDING_CORRUPTION,
                description=f"CRLF <-> LF line ending transcoding corruption in {fmt.value}",
                data=data,
                mutator=cls._mutate_line_endings,
                redundancy_pct=25.0,
            )
            cases.append(case)

        # 7. Multi-Chunk Wipe: RECOVERABLE (E = 2 <= M = 2 with 50% redundancy)
        for fmt in [FileFormat.CSV, FileFormat.JSON, FileFormat.PNG]:
            data = pristine_assets[fmt]
            case = cls._build_multi_chunk_case(
                case_id=f"CASE_{fmt.value}_MULTI_CHUNK_RECOVERABLE",
                fmt=fmt,
                description=f"2 chunks wiped with 50% redundancy (E=2 <= M=2) in {fmt.value}",
                data=data,
                damaged_count=2,
                redundancy_pct=50.0,
                is_recoverable=True,
            )
            cases.append(case)

        # 8. Multi-Chunk Wipe: UNRECOVERABLE / SAFE FAILURE (E = 3 > M = 1 with 20% redundancy)
        for fmt in [FileFormat.TEXT, FileFormat.CSV, FileFormat.PNG]:
            data = pristine_assets[fmt]
            case = cls._build_multi_chunk_case(
                case_id=f"CASE_{fmt.value}_SAFE_FAILURE_EXCEEDS_PARITY",
                fmt=fmt,
                description=f"3 chunks wiped exceeding parity M=1 (Safe Failure Protocol test)",
                data=data,
                damaged_count=3,
                redundancy_pct=20.0,
                is_recoverable=False,
            )
            cases.append(case)

        return cases

    @classmethod
    def _build_case(
        cls,
        case_id: str,
        fmt: FileFormat,
        corruption_type: CorruptionType,
        description: str,
        data: bytes,
        mutator: Any,
        redundancy_pct: float,
    ) -> BenchmarkTestCase:
        # Dynamically select chunk size so we have ~4-8 chunks for comprehensive erasure testing
        total_len = len(data)
        # Select chunk size: roughly total_len / 4, bounded
        chunk_size = max(64, min(512, total_len // 4))

        orig_chunks, package = ReedSolomonEngine.protect(
            data, chunk_size=chunk_size, redundancy_percentage=redundancy_pct
        )

        corrupted_chunks, damaged_indices, corrupted_data = mutator(
            orig_chunks, data, chunk_size, package.parity_chunks_m
        )

        is_recoverable = len(damaged_indices) <= package.parity_chunks_m

        return BenchmarkTestCase(
            case_id=case_id,
            format=fmt,
            corruption_type=corruption_type,
            description=description,
            original_data=data,
            corrupted_data=corrupted_data,
            expected_root_sha256=package.root_sha256,
            corrupted_root_sha256=hashlib.sha256(corrupted_data).hexdigest(),
            chunk_size=chunk_size,
            data_chunks_k=package.data_chunks_k,
            parity_chunks_m=package.parity_chunks_m,
            redundancy_percentage=redundancy_pct,
            damaged_chunk_indices=damaged_indices,
            is_recoverable_by_rs=is_recoverable,
            original_chunks=orig_chunks,
            corrupted_chunks=corrupted_chunks,
            parity_chunks=package.parity_chunks,
        )

    @classmethod
    def _build_multi_chunk_case(
        cls,
        case_id: str,
        fmt: FileFormat,
        description: str,
        data: bytes,
        damaged_count: int,
        redundancy_pct: float,
        is_recoverable: bool,
    ) -> BenchmarkTestCase:
        total_len = len(data)
        chunk_size = max(64, min(256, total_len // 6))

        orig_chunks, package = ReedSolomonEngine.protect(
            data, chunk_size=chunk_size, redundancy_percentage=redundancy_pct
        )

        k = package.data_chunks_k
        m = package.parity_chunks_m

        if not is_recoverable:
            # Ensure damaged_count > m
            damaged_count = max(damaged_count, m + 1)
        else:
            # Ensure damaged_count <= m
            damaged_count = min(damaged_count, m)

        damaged_indices = list(range(min(k, damaged_count)))
        corr_chunks = [bytearray(c) for c in orig_chunks]
        for idx in damaged_indices:
            corr_chunks[idx] = bytearray(b"\x00" * chunk_size)

        corrupted_data = b"".join(corr_chunks)[:total_len]

        return BenchmarkTestCase(
            case_id=case_id,
            format=fmt,
            corruption_type=CorruptionType.MULTI_CHUNK_WIPE,
            description=description,
            original_data=data,
            corrupted_data=corrupted_data,
            expected_root_sha256=package.root_sha256,
            corrupted_root_sha256=hashlib.sha256(corrupted_data).hexdigest(),
            chunk_size=chunk_size,
            data_chunks_k=k,
            parity_chunks_m=m,
            redundancy_percentage=redundancy_pct,
            damaged_chunk_indices=damaged_indices,
            is_recoverable_by_rs=is_recoverable,
            original_chunks=orig_chunks,
            corrupted_chunks=[bytes(c) for c in corr_chunks],
            parity_chunks=package.parity_chunks,
        )

    @staticmethod
    def _mutate_bit_flip(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        corr_chunks = [bytearray(c) for c in orig_chunks]
        target_chunk = len(orig_chunks) // 2
        # Flip 1 bit at offset 16 in target_chunk
        offset = min(16, chunk_size - 1)
        corr_chunks[target_chunk][offset] ^= 0x01
        corrupted_data = b"".join(corr_chunks)[:len(data)]
        return [bytes(c) for c in corr_chunks], [target_chunk], corrupted_data

    @staticmethod
    def _mutate_header_wipe(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        corr_chunks = [bytearray(c) for c in orig_chunks]
        # Overwrite chunk 0 with zeros (simulating ransomware wiping magic bytes)
        corr_chunks[0] = bytearray(b"\x00" * chunk_size)
        corrupted_data = b"".join(corr_chunks)[:len(data)]
        return [bytes(c) for c in corr_chunks], [0], corrupted_data

    @staticmethod
    def _mutate_zero_fill(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        corr_chunks = [bytearray(c) for c in orig_chunks]
        target_chunk = 1 if len(orig_chunks) > 1 else 0
        corr_chunks[target_chunk] = bytearray(b"\x00" * chunk_size)
        corrupted_data = b"".join(corr_chunks)[:len(data)]
        return [bytes(c) for c in corr_chunks], [target_chunk], corrupted_data

    @staticmethod
    def _mutate_truncation(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        corr_chunks = [bytearray(c) for c in orig_chunks]
        target_chunk = len(orig_chunks) - 1
        # In live file, trailing chunk is missing completely
        corr_chunks[target_chunk] = bytearray(b"\x00" * chunk_size)
        # Truncate raw data stream
        corrupted_data = data[: target_chunk * chunk_size]
        return [bytes(c) for c in corr_chunks], [target_chunk], corrupted_data

    @staticmethod
    def _mutate_ransomware_encryption(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        corr_chunks = [bytearray(c) for c in orig_chunks]
        target_chunk = 1 if len(orig_chunks) > 1 else 0
        # Cryptographic pseudo-random bytes (high entropy ~8.0 bits/byte)
        random_bytes = bytearray(os.urandom(chunk_size))
        corr_chunks[target_chunk] = random_bytes
        corrupted_data = b"".join(corr_chunks)[:len(data)]
        return [bytes(c) for c in corr_chunks], [target_chunk], corrupted_data

    @staticmethod
    def _mutate_line_endings(
        orig_chunks: List[bytes], data: bytes, chunk_size: int, parity_m: int
    ) -> Tuple[List[bytes], List[int], bytes]:
        # Mutate CRLF to LF or vice versa
        if b"\r\n" in data:
            corrupted_data = data.replace(b"\r\n", b"\n")
        else:
            corrupted_data = data.replace(b"\n", b"\r\n")

        # Re-slice into chunks
        k = len(orig_chunks)
        corr_chunks: List[bytes] = []
        damaged_indices: List[int] = []
        for i in range(k):
            start = i * chunk_size
            end = min(len(corrupted_data), (i + 1) * chunk_size)
            chunk = corrupted_data[start:end]
            if len(chunk) < chunk_size:
                chunk = chunk.ljust(chunk_size, b"\x00")
            corr_chunks.append(chunk)
            if chunk != orig_chunks[i]:
                damaged_indices.append(i)

        return corr_chunks, damaged_indices, corrupted_data
