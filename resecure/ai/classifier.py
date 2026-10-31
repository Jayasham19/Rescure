"""
ReSecure AI/ML Module: Corruption Pattern Classifier
Analyzes damaged byte streams and extracts information-theoretic,
statistical, and structural features to classify corruption patterns.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class CorruptionType(str, Enum):
    BIT_FLIP = "BIT_FLIP"
    ZERO_FILL = "ZERO_FILL"
    HEADER_WIPE = "HEADER_WIPE"
    TRUNCATION = "TRUNCATION"
    RANSOMWARE_ENCRYPTION = "RANSOMWARE_ENCRYPTION"
    LINE_ENDING_CORRUPTION = "LINE_ENDING_CORRUPTION"
    MULTI_CHUNK_WIPE = "MULTI_CHUNK_WIPE"
    UNKNOWN = "UNKNOWN"


@dataclass
class CorruptionFeatures:
    """Statistical and information-theoretic features extracted from byte stream."""
    total_bytes: int
    shannon_entropy: float
    null_byte_ratio: float
    printable_ascii_ratio: float
    uniformity_p_value: float
    header_zero_ratio: float
    header_entropy: float
    trailing_zero_ratio: float
    window_entropies: List[float] = field(default_factory=list)
    is_truncated: bool = False
    size_deficit_bytes: int = 0
    cr_count: int = 0
    lf_count: int = 0
    crlf_count: int = 0
    isolated_cr_count: int = 0


@dataclass
class ClassificationResult:
    """Result of corruption pattern classification."""
    predicted_type: CorruptionType
    confidence: float
    diagnostic_details: str
    features: CorruptionFeatures
    recommended_recovery_action: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class CorruptionFeatureExtractor:
    """Extracts information-theoretic and byte-distribution metrics."""

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculates Shannon entropy in bits per byte: H(X) = -sum(p_i * log2(p_i)).
        Bounds: 0.0 (uniform single byte / all zeros) to 8.0 (pure random / AES encrypted).
        """
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def calculate_chi_square_uniformity(data: bytes) -> float:
        """
        Performs Chi-Square Goodness-of-Fit test against uniform distribution (256 bins).
        Returns a pseudo-uniformity score in [0.0, 1.0] where 1.0 indicates
        cryptographically uniform byte distribution (e.g. AES/ChaCha ransomware).
        """
        if len(data) < 128:
            return 0.0
        expected = len(data) / 256.0
        counts = Counter(data)
        chi2 = 0.0
        for b in range(256):
            observed = counts.get(b, 0)
            chi2 += ((observed - expected) ** 2) / expected
        
        # Degrees of freedom = 255. Critical value for p=0.05 is ~293.
        # High uniformity => chi2 is close to 255.
        if chi2 < 400.0:
            return max(0.0, 1.0 - (chi2 / 600.0))
        return 0.0

    @classmethod
    def extract_features(
        cls,
        data: bytes,
        expected_size: Optional[int] = None,
        chunk_size: int = 65536,
    ) -> CorruptionFeatures:
        """Extracts comprehensive feature vector from data bytes."""
        total = len(data)
        if total == 0:
            return CorruptionFeatures(
                total_bytes=0,
                shannon_entropy=0.0,
                null_byte_ratio=1.0,
                printable_ascii_ratio=0.0,
                uniformity_p_value=0.0,
                header_zero_ratio=1.0,
                header_entropy=0.0,
                trailing_zero_ratio=1.0,
                is_truncated=expected_size is not None and expected_size > 0,
                size_deficit_bytes=expected_size or 0,
            )

        entropy = cls.calculate_shannon_entropy(data)
        null_count = data.count(b"\x00")
        null_ratio = null_count / total

        # Printable ASCII: 0x20..0x7E, plus \t, \r, \n
        printable_count = sum(
            1 for b in data if (32 <= b <= 126) or b in (9, 10, 13)
        )
        printable_ratio = printable_count / total

        uniformity = cls.calculate_chi_square_uniformity(data)

        # Header metrics (first min(chunk_size, 4096) bytes)
        header_len = min(total, 4096)
        header_slice = data[:header_len]
        header_zero_ratio = header_slice.count(b"\x00") / header_len
        header_entropy = cls.calculate_shannon_entropy(header_slice)

        # Trailing metrics (last min(chunk_size, 4096) bytes)
        tail_len = min(total, 4096)
        tail_slice = data[-tail_len:]
        tail_zero_ratio = tail_slice.count(b"\x00") / tail_len

        # Window entropies (e.g. per chunk or 4KB window)
        window_size = min(chunk_size, 16384)
        window_entropies = []
        for i in range(0, total, max(1, window_size)):
            win = data[i : i + window_size]
            window_entropies.append(cls.calculate_shannon_entropy(win))

        # Truncation check
        is_truncated = False
        deficit = 0
        if expected_size is not None and total < expected_size:
            is_truncated = True
            deficit = expected_size - total

        # Line ending metrics
        cr_count = data.count(b"\r")
        lf_count = data.count(b"\n")
        crlf_count = data.count(b"\r\n")
        isolated_cr = cr_count - crlf_count

        return CorruptionFeatures(
            total_bytes=total,
            shannon_entropy=entropy,
            null_byte_ratio=null_ratio,
            printable_ascii_ratio=printable_ratio,
            uniformity_p_value=uniformity,
            header_zero_ratio=header_zero_ratio,
            header_entropy=header_entropy,
            trailing_zero_ratio=tail_zero_ratio,
            window_entropies=window_entropies,
            is_truncated=is_truncated,
            size_deficit_bytes=deficit,
            cr_count=cr_count,
            lf_count=lf_count,
            crlf_count=crlf_count,
            isolated_cr_count=isolated_cr,
        )


class CorruptionPatternClassifier:
    """
    Classifies damage patterns into distinct cyber threat and physical failure modes.
    Combines rule-informed information theory thresholds with statistical pattern matching.
    """

    def __init__(self, chunk_size: int = 65536):
        self.chunk_size = chunk_size
        self.extractor = CorruptionFeatureExtractor()

    def classify(
        self,
        corrupted_data: bytes,
        original_data: Optional[bytes] = None,
        expected_size: Optional[int] = None,
        chunk_size: Optional[int] = None,
    ) -> ClassificationResult:
        """
        Classifies the corruption pattern in `corrupted_data`.
        If `original_data` is supplied (e.g. during test benchmarks or forensic baseline),
        exact differential diagnostics are computed.
        """
        eff_chunk_size = chunk_size or self.chunk_size
        features = self.extractor.extract_features(
            corrupted_data, expected_size=expected_size, chunk_size=eff_chunk_size
        )

        # 1. Comparative Analysis (when original bytes or manifest baseline available)
        if original_data is not None:
            return self._classify_with_ground_truth(
                corrupted_data, original_data, features, eff_chunk_size
            )

        # 2. Standalone Truncation Diagnosis
        if features.is_truncated and features.size_deficit_bytes > 0:
            return ClassificationResult(
                predicted_type=CorruptionType.TRUNCATION,
                confidence=0.98,
                diagnostic_details=(
                    f"File stream truncated. Missing {features.size_deficit_bytes} bytes "
                    f"({(features.size_deficit_bytes / (features.total_bytes + features.size_deficit_bytes)) * 100:.1f}% deficit)."
                ),
                features=features,
                recommended_recovery_action="Apply Reed-Solomon erasure decoding with trailing missing chunks marked as erasures.",
            )

        # 3. Standalone Heuristic & Entropy-based Analysis
        return self._classify_standalone(corrupted_data, features, eff_chunk_size)

    def _classify_with_ground_truth(
        self,
        corrupted: bytes,
        original: bytes,
        features: CorruptionFeatures,
        chunk_size: int,
    ) -> ClassificationResult:
        """Fine-grained classification when ground truth or manifest comparison is available."""
        len_c = len(corrupted)
        len_o = len(original)

        # A. Check for Line Ending Corruption (CRLF vs LF) BEFORE size truncation
        if features.printable_ascii_ratio > 0.75:
            orig_norm = original.replace(b"\r\n", b"\n")
            corr_norm = corrupted.replace(b"\r\n", b"\n")
            if orig_norm == corr_norm:
                return ClassificationResult(
                    predicted_type=CorruptionType.LINE_ENDING_CORRUPTION,
                    confidence=0.99,
                    diagnostic_details="Inadvertent CRLF/LF line ending translation detected.",
                    features=features,
                    recommended_recovery_action="Apply deterministic line ending normalization or Reed-Solomon parity repair.",
                )

        # B. Pure Truncation (missing trailing bytes, prefix identical)
        if len_c < len_o:
            if original.startswith(corrupted):
                return ClassificationResult(
                    predicted_type=CorruptionType.TRUNCATION,
                    confidence=1.0,
                    diagnostic_details=f"File stream truncated at byte {len_c} (missing {len_o - len_c} bytes). Prefix matches perfectly.",
                    features=features,
                    recommended_recovery_action="Reconstruct missing suffix via Reed-Solomon parity.",
                )

        # Byte-by-byte differential
        common_len = min(len_c, len_o)
        diff_indices = [i for i in range(common_len) if corrupted[i] != original[i]]
        # If lengths differ, add trailing offsets to diffs
        if len_c > len_o:
            diff_indices.extend(range(len_o, len_c))
        elif len_c < len_o:
            diff_indices.extend(range(len_c, len_o))

        total_diffs = len(diff_indices)

        if total_diffs == 0:
            return ClassificationResult(
                predicted_type=CorruptionType.UNKNOWN,
                confidence=1.0,
                diagnostic_details="No byte discrepancies detected. Asset is PRISTINE.",
                features=features,
                recommended_recovery_action="No recovery needed.",
            )

        # Group differences by chunk index
        affected_chunks = sorted(list(set(i // max(1, chunk_size) for i in diff_indices)))

        # C. Single/Sparse Bit Flips
        if total_diffs <= 8:
            total_bit_flips = 0
            for i in diff_indices:
                if i < common_len:
                    xor_val = corrupted[i] ^ original[i]
                    total_bit_flips += bin(xor_val).count("1")
                else:
                    total_bit_flips += 8
            
            if total_bit_flips <= 16:
                return ClassificationResult(
                    predicted_type=CorruptionType.BIT_FLIP,
                    confidence=0.98,
                    diagnostic_details=f"Silent bit rot: {total_bit_flips} bit flip(s) isolated across {total_diffs} byte(s).",
                    features=features,
                    recommended_recovery_action="Single-chunk Reed-Solomon error correction restores exact bit state.",
                )

        # D. Header Wipe: chunk 0 is damaged while subsequent chunks are intact
        if affected_chunks == [0]:
            chunk0_slice = corrupted[:min(chunk_size, len_c)]
            # Check if chunk 0 is zeroed or encrypted
            if chunk0_slice.count(b"\x00") / max(1, len(chunk0_slice)) > 0.8:
                return ClassificationResult(
                    predicted_type=CorruptionType.HEADER_WIPE,
                    confidence=0.98,
                    diagnostic_details="Zero-fill header destruction (intermittent ransomware pattern or zero-fill wipe).",
                    features=features,
                    recommended_recovery_action="Restore header chunk 0 via Reed-Solomon parity or format template repair.",
                )
            # High entropy in chunk 0
            if self.extractor.calculate_shannon_entropy(chunk0_slice) > 7.5:
                # If original chunk 0 was NOT high entropy, or ransomware encrypted
                orig_c0_entropy = self.extractor.calculate_shannon_entropy(original[:min(chunk_size, len_o)])
                if orig_c0_entropy < 7.2:
                    return ClassificationResult(
                        predicted_type=CorruptionType.RANSOMWARE_ENCRYPTION,
                        confidence=0.96,
                        diagnostic_details="Ransomware encrypted header block detected. Remainder of file unencrypted.",
                        features=features,
                        recommended_recovery_action="High entropy encrypted block cannot be decrypted; Reed-Solomon parity must reconstruct original entropy.",
                    )
            return ClassificationResult(
                predicted_type=CorruptionType.HEADER_WIPE,
                confidence=0.95,
                diagnostic_details="Header chunk 0 corrupted while payload remainder is intact.",
                features=features,
                recommended_recovery_action="Reconstruct header chunk 0 via Reed-Solomon parity.",
            )

        # E. Multi-Chunk Wipe: more than 1 chunk affected
        if len(affected_chunks) > 1:
            # Check if all affected chunks are zeroed
            zero_diffs = sum(1 for i in diff_indices if i < len_c and corrupted[i] == 0)
            return ClassificationResult(
                predicted_type=CorruptionType.MULTI_CHUNK_WIPE,
                confidence=0.95,
                diagnostic_details=f"Multi-chunk corruption detected across {len(affected_chunks)} chunks: {affected_chunks}.",
                features=features,
                recommended_recovery_action="Verify damaged chunk count <= M before committing parity recovery.",
            )

        # F. Single non-header chunk affected: affected_chunks == [k] where k > 0
        target_chunk_idx = affected_chunks[0]
        c_start = target_chunk_idx * chunk_size
        c_end = min(len_c, (target_chunk_idx + 1) * chunk_size)
        target_slice = corrupted[c_start:c_end]

        # Check for Zero-Fill
        if target_slice.count(b"\x00") / max(1, len(target_slice)) > 0.85:
            return ClassificationResult(
                predicted_type=CorruptionType.ZERO_FILL,
                confidence=0.97,
                diagnostic_details=f"Zero-fill pattern detected in chunk {target_chunk_idx} ({len(target_slice)} bytes zeroed).",
                features=features,
                recommended_recovery_action="Erasure decoding over zeroed chunk offsets.",
            )

        # Check for Ransomware encryption
        slice_entropy = self.extractor.calculate_shannon_entropy(target_slice)
        slice_uniformity = self.extractor.calculate_chi_square_uniformity(target_slice)
        max_possible_entropy = min(8.0, math.log2(max(2, len(target_slice))))
        entropy_ratio = slice_entropy / max_possible_entropy

        if total_diffs >= 32 and (slice_entropy > 6.5 or entropy_ratio > 0.85):
            return ClassificationResult(
                predicted_type=CorruptionType.RANSOMWARE_ENCRYPTION,
                confidence=0.96,
                diagnostic_details=(
                    f"Cryptographic pseudorandom payload detected in chunk {target_chunk_idx}. "
                    f"Entropy: {slice_entropy:.3f} bits/byte ({entropy_ratio * 100:.1f}% max)."
                ),
                features=features,
                recommended_recovery_action="High entropy block cannot be decrypted; Reed-Solomon parity must reconstruct original entropy.",
            )

        return ClassificationResult(
            predicted_type=CorruptionType.BIT_FLIP,
            confidence=0.85,
            diagnostic_details=f"Localized chunk corruption in chunk {target_chunk_idx} ({total_diffs} altered bytes).",
            features=features,
            recommended_recovery_action="Execute Reed-Solomon chunk repair.",
        )

    def _classify_standalone(
        self,
        corrupted: bytes,
        features: CorruptionFeatures,
        chunk_size: int,
    ) -> ClassificationResult:
        """Heuristic classification without access to pristine original bytes."""
        # 1. Header Wipe (Zero magic bytes, non-zero payload)
        if features.header_zero_ratio > 0.8 and features.null_byte_ratio < 0.5:
            return ClassificationResult(
                predicted_type=CorruptionType.HEADER_WIPE,
                confidence=0.93,
                diagnostic_details="Zeroed header detected with structured trailing payload.",
                features=features,
                recommended_recovery_action="Reconstruct header from parity manifest or format template.",
            )

        # 2. Ransomware encryption
        if features.shannon_entropy > 7.92 and features.uniformity_p_value > 0.5:
            return ClassificationResult(
                predicted_type=CorruptionType.RANSOMWARE_ENCRYPTION,
                confidence=0.96,
                diagnostic_details=f"High-entropy pseudorandom block ({features.shannon_entropy:.3f} bits/byte). Characteristic of AES/ransomware payload.",
                features=features,
                recommended_recovery_action="Irreversible without parity or encryption key.",
            )

        # 3. Zero-fill
        if features.null_byte_ratio > 0.90:
            return ClassificationResult(
                predicted_type=CorruptionType.ZERO_FILL,
                confidence=0.95,
                diagnostic_details=f"Massive null byte saturation ({features.null_byte_ratio * 100:.1f}% zeros).",
                features=features,
                recommended_recovery_action="Replace null blocks with Reed-Solomon parity recovery.",
            )

        # 4. Inconsistent entropy across windows
        if features.window_entropies:
            min_e = min(features.window_entropies)
            max_e = max(features.window_entropies)
            if features.window_entropies[0] < 1.0 and max_e > 5.0:
                return ClassificationResult(
                    predicted_type=CorruptionType.HEADER_WIPE,
                    confidence=0.88,
                    diagnostic_details=f"Window entropy anomaly: Chunk 0 entropy {features.window_entropies[0]:.2f} vs peak {max_e:.2f}.",
                    features=features,
                    recommended_recovery_action="Restore chunk 0.",
                )

        return ClassificationResult(
            predicted_type=CorruptionType.BIT_FLIP,
            confidence=0.70,
            diagnostic_details="Diffuse localized corruption detected.",
            features=features,
            recommended_recovery_action="Audit chunk SHA-256 hashes against authenticated manifest.",
        )
