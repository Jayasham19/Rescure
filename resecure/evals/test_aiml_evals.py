"""
Unit and Integration Tests for ReSecure AI/ML & Evaluation Benchmark Suite.
Tests:
  1. Reed-Solomon GF(2^8) exact recovery and hash invariance (P(error) = 0).
  2. Safe Failure Protocol when E > M (no corrupt bytes written).
  3. Generative AI hash failure rate (P(exact match) = 0) and hallucination detection.
  4. Corruption Pattern Classifier precision and diagnostic categorization.
  5. Format Identification on header-wiped assets without magic bytes.
"""

import hashlib
import json
import pytest

from resecure.ai.classifier import (
    CorruptionFeatureExtractor,
    CorruptionPatternClassifier,
    CorruptionType,
)
from resecure.ai.format_detector import FileFormat, FormatDetector
from resecure.evals.benchmark_cases import (
    BenchmarkCaseFactory,
    generate_pristine_csv,
    generate_pristine_jpeg,
    generate_pristine_json,
    generate_pristine_png,
    generate_pristine_text,
)
from resecure.evals.codec import CodecVerdict, ReedSolomonEngine
from resecure.evals.generative_simulator import GenerativeSimulator


class TestReedSolomonDeterministicRecovery:
    """Verifies that Reed-Solomon guarantees exact bit-for-bit reconstruction."""

    @pytest.mark.parametrize(
        "generator,fmt",
        [
            (generate_pristine_text, FileFormat.TEXT),
            (generate_pristine_csv, FileFormat.CSV),
            (generate_pristine_json, FileFormat.JSON),
            (generate_pristine_png, FileFormat.PNG),
            (generate_pristine_jpeg, FileFormat.JPEG),
        ],
    )
    def test_rs_exact_recovery_within_budget(self, generator, fmt):
        data = generator()
        chunk_size = 128
        orig_chunks, pkg = ReedSolomonEngine.protect(data, chunk_size=chunk_size, redundancy_percentage=25.0)

        # Corrupt 1 chunk (chunk 0)
        corrupted_chunks = [bytearray(c) for c in orig_chunks]
        corrupted_chunks[0] = bytearray(b"\x00" * chunk_size)

        res = ReedSolomonEngine.recover(
            live_chunks=corrupted_chunks,
            parity_chunks=pkg.parity_chunks,
            damaged_indices=[0],
            original_size=len(data),
            expected_root_sha256=pkg.root_sha256,
            chunk_size=chunk_size,
        )

        assert res.verdict == CodecVerdict.VERIFIED_EXACT
        assert res.hash_verified_exact is True
        assert res.bit_error_rate == 0.0
        assert res.byte_error_rate == 0.0
        assert res.recovered_data == data
        assert hashlib.sha256(res.recovered_data).hexdigest() == pkg.root_sha256

    def test_rs_safe_failure_when_damage_exceeds_parity(self):
        data = generate_pristine_text()
        chunk_size = 128
        orig_chunks, pkg = ReedSolomonEngine.protect(data, chunk_size=chunk_size, redundancy_percentage=20.0)

        # Force damage count > M
        m = pkg.parity_chunks_m
        damaged_indices = list(range(m + 1))
        corrupted_chunks = [bytearray(c) for c in orig_chunks]
        for idx in damaged_indices:
            corrupted_chunks[idx] = bytearray(b"\x00" * chunk_size)

        res = ReedSolomonEngine.recover(
            live_chunks=corrupted_chunks,
            parity_chunks=pkg.parity_chunks,
            damaged_indices=damaged_indices,
            original_size=len(data),
            expected_root_sha256=pkg.root_sha256,
            chunk_size=chunk_size,
        )

        assert res.verdict == CodecVerdict.UNRECOVERABLE_EXACT
        assert res.safe_failure_triggered is True
        assert res.recovered_data is None
        assert res.hash_verified_exact is False


class TestGenerativeHallucinationEvaluation:
    """Verifies that generative/heuristic approaches fail SHA-256 and hallucinate values."""

    def test_generative_hash_failure_on_text(self):
        orig = generate_pristine_text()
        corr = orig.replace(b"CONFIDENTIAL", b"000000000000")
        res = GenerativeSimulator.recover(corr, orig, FileFormat.TEXT, "TEST_TEXT")

        assert res.sha256_match is False
        assert res.reconstructed_sha256 != res.expected_sha256
        assert res.hallucination_rate > 0.0
        assert res.syntax_valid is True

    def test_generative_hash_failure_on_csv(self):
        orig = generate_pristine_csv()
        corr = orig[: len(orig) // 2]
        res = GenerativeSimulator.recover(corr, orig, FileFormat.CSV, "TEST_CSV")

        assert res.sha256_match is False
        assert res.hallucination_rate > 0.0
        assert res.syntax_valid is True

    def test_generative_hash_failure_on_json(self):
        orig = generate_pristine_json()
        corr = orig.replace(b"RS-GATEWAY-NODE-077", b"0000000000000000000")
        res = GenerativeSimulator.recover(corr, orig, FileFormat.JSON, "TEST_JSON")

        assert res.sha256_match is False
        assert res.hallucination_rate > 0.0
        assert res.syntax_valid is True


class TestCorruptionClassifier:
    """Verifies classification accuracy of corruption patterns."""

    def test_all_benchmark_cases_classified_accurately(self):
        cases = BenchmarkCaseFactory.create_suite()
        classifier = CorruptionPatternClassifier()

        for case in cases:
            res = classifier.classify(
                corrupted_data=case.corrupted_data,
                original_data=case.original_data,
                expected_size=len(case.original_data),
                chunk_size=case.chunk_size,
            )
            assert res.predicted_type.value == case.corruption_type.value, (
                f"Failed for case {case.case_id}: expected {case.corruption_type.value}, "
                f"got {res.predicted_type.value}. Details: {res.diagnostic_details}"
            )


class TestFormatDetectorHeaderWiped:
    """Verifies format identification when magic bytes are wiped."""

    @pytest.mark.parametrize(
        "generator,expected_fmt",
        [
            (generate_pristine_text, FileFormat.TEXT),
            (generate_pristine_csv, FileFormat.CSV),
            (generate_pristine_json, FileFormat.JSON),
            (generate_pristine_png, FileFormat.PNG),
            (generate_pristine_jpeg, FileFormat.JPEG),
        ],
    )
    def test_format_detected_with_wiped_magic_bytes(self, generator, expected_fmt):
        data = bytearray(generator())
        # Overwrite first 64 bytes with zeros (obliterating magic bytes)
        wipe_len = min(64, len(data) // 4)
        data[:wipe_len] = b"\x00" * wipe_len

        detector = FormatDetector()
        res = detector.detect(bytes(data))

        assert res.magic_bytes_intact is False
        assert res.format == expected_fmt
        assert res.confidence >= 0.50


class TestFeatureExtractor:
    """Verifies information-theoretic metrics."""

    def test_shannon_entropy_bounds(self):
        zeros = b"\x00" * 1024
        assert CorruptionFeatureExtractor.calculate_shannon_entropy(zeros) == 0.0

        # Uniform byte spread
        all_bytes = bytes(range(256)) * 4
        entropy = CorruptionFeatureExtractor.calculate_shannon_entropy(all_bytes)
        assert abs(entropy - 8.0) < 0.001
