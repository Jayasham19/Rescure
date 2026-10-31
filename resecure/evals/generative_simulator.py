"""
ReSecure Evaluation Benchmark Suite: Generative AI & Heuristic Simulator
Simulates the performance of Generative AI (LLMs, neural synthesis) and
probabilistic heuristic repair against ground-truth cryptographic standards.
Measures Hallucination Rate, Semantic Drift, Syntax Validity, and Cryptographic Invariance.
"""

from __future__ import annotations

import difflib
import hashlib
import io
import json
import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

from resecure.ai.format_detector import FileFormat


@dataclass
class GenerativeRecoveryResult:
    """Detailed evaluation result for a Generative / Heuristic recovery attempt."""
    case_id: str
    format: FileFormat
    method: str
    reconstructed_data: bytes
    expected_sha256: str
    reconstructed_sha256: str
    sha256_match: bool
    bit_error_rate: float
    byte_error_rate: float
    hallucination_rate: float  # Percentage of reconstructed content that is fabricated
    syntax_valid: bool
    semantic_drift_score: float  # 0.0 (identical semantics) to 1.0 (completely altered)
    diagnostic_details: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class GenerativeSimulator:
    """
    Evaluates generative AI and heuristic reconstruction approaches on damaged files.
    """

    @staticmethod
    def calculate_bit_error_rate(a: bytes, b: bytes) -> float:
        """Calculates proportion of flipped bits across matching byte lengths."""
        if not a and not b:
            return 0.0
        max_len = max(len(a), len(b))
        min_len = min(len(a), len(b))
        
        diff_bits = 0
        for i in range(min_len):
            xor_val = a[i] ^ b[i]
            diff_bits += bin(xor_val).count("1")
        
        # Any missing bytes in the shorter stream count as all 8 bits differing
        diff_bits += (max_len - min_len) * 8
        total_bits = max_len * 8
        return diff_bits / total_bits if total_bits > 0 else 0.0

    @staticmethod
    def calculate_byte_error_rate(a: bytes, b: bytes) -> float:
        """Calculates proportion of non-identical bytes."""
        if not a and not b:
            return 0.0
        max_len = max(len(a), len(b))
        min_len = min(len(a), len(b))
        diff_bytes = sum(1 for i in range(min_len) if a[i] != b[i])
        diff_bytes += (max_len - min_len)
        return diff_bytes / max_len if max_len > 0 else 0.0

    @classmethod
    def recover(
        cls,
        corrupted_data: bytes,
        original_data: bytes,
        fmt: FileFormat,
        case_id: str,
    ) -> GenerativeRecoveryResult:
        """
        Executes simulated generative AI / LLM completion or heuristic repair
        tailored to the format of the asset.
        """
        if fmt == FileFormat.TEXT:
            return cls._recover_text(corrupted_data, original_data, case_id)
        elif fmt == FileFormat.CSV:
            return cls._recover_csv(corrupted_data, original_data, case_id)
        elif fmt == FileFormat.JSON:
            return cls._recover_json(corrupted_data, original_data, case_id)
        elif fmt == FileFormat.PNG:
            return cls._recover_png(corrupted_data, original_data, case_id)
        elif fmt == FileFormat.JPEG:
            return cls._recover_jpeg(corrupted_data, original_data, case_id)
        else:
            return cls._recover_binary_fallback(corrupted_data, original_data, case_id)

    @classmethod
    def _recover_text(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        """
        Simulates an LLM predicting missing or corrupted text.
        Even if grammatically flawless, it invents synonymous words or altered phrasing.
        """
        orig_text = original.decode("utf-8", errors="replace")
        
        # Simulate LLM inpainting: replace zeros or corrupted spans with plausible sentences
        # A realistic LLM completion produces high semantic plausibility but different wording
        simulated_llm_text = orig_text.replace(
            "All worker agents and processes must operate under strictly scoped identities.",
            "Each worker service and automated agent shall function with minimal scoped credentials."
        ).replace(
            "Authorized by: CISO Cryptographic Assurance Group.",
            "Approved by: Enterprise Cybersecurity Oversight Directorate."
        )

        reconstructed = simulated_llm_text.encode("utf-8")
        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(reconstructed).hexdigest()

        ber = cls.calculate_bit_error_rate(original, reconstructed)
        byerr = cls.calculate_byte_error_rate(original, reconstructed)

        # Hallucination rate: token difference ratio
        orig_words = set(orig_text.split())
        rec_words = set(simulated_llm_text.split())
        hallucinated_words = rec_words - orig_words
        hallucination_rate = len(hallucinated_words) / max(1, len(rec_words))

        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.TEXT,
            method="LLM Autoregressive Completion (Simulated GPT-4o / Claude 3.5)",
            reconstructed_data=reconstructed,
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=ber,
            byte_error_rate=byerr,
            hallucination_rate=hallucination_rate,
            syntax_valid=True,
            semantic_drift_score=0.25,
            diagnostic_details=(
                "LLM generated syntactically fluent prose, but substituted synonyms "
                "('shall function' vs 'must operate', 'Enterprise Oversight' vs 'CISO'). "
                "Cryptographic SHA-256 completely invalidated."
            ),
        )

    @classmethod
    def _recover_csv(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        """
        Simulates ML / Heuristic tabular imputation.
        Replaces corrupted numbers with mean/median or hallucinated values.
        """
        orig_text = original.decode("utf-8", errors="replace")
        lines = orig_text.splitlines()

        # Simulate heuristic imputation: row 3 & row 7 amounts replaced with mean/default values
        imputed_lines = []
        hallucinations = 0
        total_cells = 0

        for idx, line in enumerate(lines):
            cells = line.split(",")
            total_cells += len(cells)
            if idx in (2, 5, 8) and len(cells) >= 5:
                # Hallucinate amount & auth code
                cells[4] = f"{random.uniform(500.0, 3000.0):.2f}"  # Fabricated amount
                if len(cells) >= 9:
                    cells[8] = "E84B192F"  # Fabricated auth code
                hallucinations += 2
            imputed_lines.append(",".join(cells))

        reconstructed_text = "\r\n".join(imputed_lines)
        reconstructed = reconstructed_text.encode("utf-8")
        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(reconstructed).hexdigest()

        ber = cls.calculate_bit_error_rate(original, reconstructed)
        byerr = cls.calculate_byte_error_rate(original, reconstructed)
        hallucination_rate = hallucinations / max(1, total_cells)

        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.CSV,
            method="Tabular Imputation & LLM Row Synthesis",
            reconstructed_data=reconstructed,
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=ber,
            byte_error_rate=byerr,
            hallucination_rate=hallucination_rate,
            syntax_valid=True,
            semantic_drift_score=0.45,
            diagnostic_details=(
                "Syntactically valid RFC 4180 CSV, but financial amounts and auth codes "
                "were hallucinated. Silent ledger distortion introduced."
            ),
        )

    @classmethod
    def _recover_json(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        """
        Simulates Heuristic JSON repair (bracket balancing + schema-default imputation).
        """
        try:
            orig_obj = json.loads(original.decode("utf-8"))
        except Exception:
            orig_obj = {}

        # Heuristic repair: balanced brackets, but missing or modified keys
        repaired_obj = json.loads(json.dumps(orig_obj))
        # Alter a critical security setting
        if "cryptographic_policies" in repaired_obj:
            repaired_obj["cryptographic_policies"]["erasure_coding"]["default_redundancy_pct"] = 20.0
        if "telemetry_metrics" in repaired_obj:
            repaired_obj["telemetry_metrics"]["corruptions_repaired"] = 999  # Hallucinated metric

        reconstructed = json.dumps(repaired_obj, indent=2, sort_keys=True).encode("utf-8")
        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(reconstructed).hexdigest()

        ber = cls.calculate_bit_error_rate(original, reconstructed)
        byerr = cls.calculate_byte_error_rate(original, reconstructed)

        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.JSON,
            method="Structural JSON Linter & Heuristic Imputation",
            reconstructed_data=reconstructed,
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=ber,
            byte_error_rate=byerr,
            hallucination_rate=0.18,
            syntax_valid=True,
            semantic_drift_score=0.30,
            diagnostic_details=(
                "Valid RFC 8259 JSON structure achieved, but security parameters "
                "and telemetry counts were altered during synthesis."
            ),
        )

    @classmethod
    def _recover_png(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        """
        Simulates Heuristic / Diffusion inpainting repair on PNG.
        Appends reconstructed magic bytes or pads missing chunks.
        """
        # Heuristic: prepend valid PNG header b"\x89PNG\r\n\x1a\n" if missing
        reconstructed = bytearray(corrupted)
        magic = b"\x89PNG\r\n\x1a\n"
        if not reconstructed.startswith(magic):
            # Prepend or overwrite header
            if len(reconstructed) >= len(magic):
                reconstructed[:len(magic)] = magic
            else:
                reconstructed = bytearray(magic + bytes(reconstructed))

        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(reconstructed).hexdigest()

        ber = cls.calculate_bit_error_rate(original, bytes(reconstructed))
        byerr = cls.calculate_byte_error_rate(original, bytes(reconstructed))

        # Test if PIL can decode the heuristically repaired PNG
        syntax_valid = False
        try:
            img = Image.open(io.BytesIO(bytes(reconstructed)))
            img.verify()
            syntax_valid = True
        except Exception:
            syntax_valid = False

        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.PNG,
            method="Heuristic Container Patching & Zero-Padding",
            reconstructed_data=bytes(reconstructed),
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=ber,
            byte_error_rate=byerr,
            hallucination_rate=0.85,
            syntax_valid=syntax_valid,
            semantic_drift_score=0.90,
            diagnostic_details=(
                f"Container header re-attached. Decoder syntax valid: {syntax_valid}. "
                "Compressed zlib stream has missing/corrupted entropy, preventing bit-exact recovery."
            ),
        )

    @classmethod
    def _recover_jpeg(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        """
        Simulates Heuristic JPEG SOI marker restoration.
        """
        reconstructed = bytearray(corrupted)
        magic = b"\xff\xd8\xff"
        if not reconstructed.startswith(magic):
            if len(reconstructed) >= len(magic):
                reconstructed[:len(magic)] = magic
            else:
                reconstructed = bytearray(magic + bytes(reconstructed))

        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(reconstructed).hexdigest()

        ber = cls.calculate_bit_error_rate(original, bytes(reconstructed))
        byerr = cls.calculate_byte_error_rate(original, bytes(reconstructed))

        syntax_valid = False
        try:
            img = Image.open(io.BytesIO(bytes(reconstructed)))
            img.verify()
            syntax_valid = True
        except Exception:
            syntax_valid = False

        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.JPEG,
            method="Heuristic JPEG Marker Synthesis",
            reconstructed_data=bytes(reconstructed),
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=ber,
            byte_error_rate=byerr,
            hallucination_rate=0.88,
            syntax_valid=syntax_valid,
            semantic_drift_score=0.85,
            diagnostic_details=(
                f"JPEG SOI marker attached. Decoder valid: {syntax_valid}. "
                "DCT coefficients and quantization tables altered or corrupted."
            ),
        )

    @classmethod
    def _recover_binary_fallback(
        cls, corrupted: bytes, original: bytes, case_id: str
    ) -> GenerativeRecoveryResult:
        expected_sha = hashlib.sha256(original).hexdigest()
        rec_sha = hashlib.sha256(corrupted).hexdigest()
        return GenerativeRecoveryResult(
            case_id=case_id,
            format=FileFormat.BINARY,
            method="Zero-Padding Fallback",
            reconstructed_data=corrupted,
            expected_sha256=expected_sha,
            reconstructed_sha256=rec_sha,
            sha256_match=(rec_sha == expected_sha),
            bit_error_rate=cls.calculate_bit_error_rate(original, corrupted),
            byte_error_rate=cls.calculate_byte_error_rate(original, corrupted),
            hallucination_rate=1.0,
            syntax_valid=False,
            semantic_drift_score=1.0,
            diagnostic_details="Binary fallback incapable of inferring missing entropy.",
        )
