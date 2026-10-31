"""
ReSecure AI/ML Module: Format Identification Without Magic Bytes
Identifies file formats when file headers, signatures, or magic numbers
have been wiped, corrupted by ransomware, or stripped during transmission.
Uses statistical byte distribution, structural token frequencies, and
internal binary container markers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class FileFormat(str, Enum):
    TEXT = "TEXT"
    CSV = "CSV"
    JSON = "JSON"
    PNG = "PNG"
    JPEG = "JPEG"
    BINARY = "BINARY"


# Standard Magic Byte Signatures
STANDARD_MAGIC = {
    FileFormat.PNG: b"\x89PNG\r\n\x1a\n",
    FileFormat.JPEG: b"\xff\xd8\xff",
}


@dataclass
class FormatPrediction:
    """Predicted format and supporting diagnostic evidence."""
    format: FileFormat
    confidence: float
    magic_bytes_intact: bool
    evidence: List[str]
    features: Dict[str, Any] = field(default_factory=dict)


class FormatDetector:
    """
    ML/Heuristic format identification engine capable of classifying files
    even when standard magic bytes (file signature) are destroyed or missing.
    """

    # Internal binary marker patterns for PNG & JPEG
    PNG_INTERNAL_CHUNKS = [b"IHDR", b"IDAT", b"IEND", b"PLTE", b"pHYs", b"tIME", b"sRGB", b"gAMA"]
    JPEG_INTERNAL_MARKERS = [
        b"\xff\xdb",  # DQT (Define Quantization Table)
        b"\xff\xc0",  # SOF0 (Start of Frame - Baseline DCT)
        b"\xff\xc2",  # SOF2 (Progressive DCT)
        b"\xff\xc4",  # DHT (Define Huffman Table)
        b"\xff\xda",  # SOS (Start of Scan)
        b"\xff\xd9",  # EOI (End of Image)
        b"\xff\xe0",  # APP0 (JFIF)
        b"\xff\xe1",  # APP1 (Exif)
    ]

    def detect(self, data: bytes, filename: Optional[str] = None) -> FormatPrediction:
        """
        Analyzes byte stream and identifies file format with confidence score.
        """
        if not data:
            return FormatPrediction(
                format=FileFormat.BINARY,
                confidence=0.0,
                magic_bytes_intact=False,
                evidence=["Empty byte stream."],
            )

        # 1. Check Magic Bytes
        if data.startswith(STANDARD_MAGIC[FileFormat.PNG]):
            return FormatPrediction(
                format=FileFormat.PNG,
                confidence=1.0,
                magic_bytes_intact=True,
                evidence=["Standard 8-byte PNG header present: \\x89PNG\\r\\n\\x1a\\n."],
            )

        if data.startswith(STANDARD_MAGIC[FileFormat.JPEG]):
            return FormatPrediction(
                format=FileFormat.JPEG,
                confidence=1.0,
                magic_bytes_intact=True,
                evidence=["Standard 3-byte JPEG SOI marker present: \\xff\\xd8\\xff."],
            )

        # 2. Magic bytes missing or corrupted. Perform deep structural & statistical analysis.
        evidence: List[str] = ["Standard magic bytes missing or corrupted."]
        features: Dict[str, Any] = {}

        total = len(data)

        # Check for binary image internal markers FIRST
        png_score, png_evidence = self._evaluate_png_structure(data)
        jpeg_score, jpeg_evidence = self._evaluate_jpeg_structure(data)

        features["png_score"] = png_score
        features["jpeg_score"] = jpeg_score

        if png_score >= 0.50 and png_score > jpeg_score:
            evidence.extend(png_evidence)
            return FormatPrediction(
                format=FileFormat.PNG,
                confidence=min(0.99, png_score),
                magic_bytes_intact=False,
                evidence=evidence,
                features=features,
            )

        if jpeg_score >= 0.50:
            evidence.extend(jpeg_evidence)
            return FormatPrediction(
                format=FileFormat.JPEG,
                confidence=min(0.99, jpeg_score),
                magic_bytes_intact=False,
                evidence=evidence,
                features=features,
            )

        # Strip leading null bytes (from zero-fill header wipe) to inspect payload body
        non_null_slice = data.lstrip(b"\x00")
        if not non_null_slice:
            return FormatPrediction(
                format=FileFormat.BINARY,
                confidence=0.90,
                magic_bytes_intact=False,
                evidence=["File contains exclusively null bytes."],
                features={"all_zeros": True},
            )

        # Printable ASCII analysis on non-null body
        printable_count = sum(
            1 for b in non_null_slice if (32 <= b <= 126) or b in (9, 10, 13)
        )
        printable_ratio = printable_count / len(non_null_slice)
        features["body_printable_ratio"] = printable_ratio

        # Text-family analysis (JSON vs CSV vs TEXT)
        if printable_ratio >= 0.70:
            text_pred = self._evaluate_text_formats(non_null_slice)
            evidence.extend(text_pred.evidence)
            text_pred.features.update(features)
            return text_pred

        # Fallback binary
        evidence.append(
            f"High binary density (body printable ratio {printable_ratio:.2f})."
        )
        return FormatPrediction(
            format=FileFormat.BINARY,
            confidence=0.80,
            magic_bytes_intact=False,
            evidence=evidence,
            features=features,
        )

    def _evaluate_png_structure(self, data: bytes) -> Tuple[float, List[str]]:
        """Evaluates whether data contains PNG chunk structures (even if header is wiped)."""
        score = 0.0
        evidence = []

        found_chunks = []
        for chunk_tag in self.PNG_INTERNAL_CHUNKS:
            if chunk_tag in data:
                found_chunks.append(chunk_tag.decode("ascii", errors="replace"))

        if found_chunks:
            evidence.append(f"Found PNG chunk signatures: {', '.join(found_chunks)}.")
            score += min(0.60, len(found_chunks) * 0.25)

        # IDAT and IEND are hallmark PNG chunks
        if b"IDAT" in data:
            score += 0.30
            evidence.append("Found critical PNG IDAT (image data) chunk.")

        if b"IEND" in data:
            score += 0.30
            evidence.append("Found PNG IEND (trailer) marker.")

        # PNG IEND chunk structure: \x00\x00\x00\x00IEND\xaeB`\x82 (12 bytes)
        if b"\x00\x00\x00\x00IEND\xaeB\x60\x82" in data:
            score += 0.35
            evidence.append("Found canonical 12-byte PNG IEND chunk with valid CRC32 (0xAE426082).")

        return min(1.0, score), evidence

    def _evaluate_jpeg_structure(self, data: bytes) -> Tuple[float, List[str]]:
        """Evaluates whether data contains JPEG segment markers (even if SOI is wiped)."""
        score = 0.0
        evidence = []

        found_markers = []
        for marker in self.JPEG_INTERNAL_MARKERS:
            if marker in data:
                found_markers.append(f"0x{marker.hex().upper()}")

        if found_markers:
            evidence.append(f"Found JPEG segment markers: {', '.join(found_markers)}.")
            score += min(0.50, len(found_markers) * 0.20)

        # Critical JPEG markers: DQT, DHT, SOS, EOI
        if b"\xff\xdb" in data:  # DQT
            score += 0.30
            evidence.append("Found JPEG DQT (Define Quantization Table) marker 0xFFDB.")

        if b"\xff\xc0" in data or b"\xff\xc2" in data:  # SOF0 / SOF2
            score += 0.25
            evidence.append("Found JPEG SOF (Start of Frame) marker.")

        if b"\xff\xda" in data:  # SOS
            score += 0.20
            evidence.append("Found JPEG SOS (Start of Scan) marker.")

        if data.endswith(b"\xff\xd9") or b"\xff\xd9" in data[-32:]:  # EOI
            score += 0.20
            evidence.append("Found JPEG EOI (End of Image) marker 0xFFD9 near end of file.")

        return min(1.0, score), evidence

    def _evaluate_text_formats(self, data: bytes) -> FormatPrediction:
        """Distinguishes JSON, CSV, and Plain Text from printable content."""
        evidence = []
        features: Dict[str, Any] = {}

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")

        # 1. JSON Evaluation
        json_score = 0.0
        open_braces = text.count("{")
        close_braces = text.count("}")
        open_brackets = text.count("[")
        close_brackets = text.count("]")
        colons = text.count(":")
        quotes = text.count('"')

        features["json_delimiters"] = {
            "braces": (open_braces, close_braces),
            "brackets": (open_brackets, close_brackets),
            "colons": colons,
            "quotes": quotes,
        }

        # Key-Value pattern: "key": value
        kv_patterns = re.findall(r'"[a-zA-Z0-9_\-\.]+":\s*', text)
        if len(kv_patterns) >= 2:
            json_score += 0.50
            evidence.append(f'Detected {len(kv_patterns)} JSON key-value pattern(s) like "key": value.')

        if (open_braces > 0 and close_braces > 0) or (open_brackets > 0 and close_brackets > 0):
            json_score += 0.30

        if text.strip().endswith(("}", "]")):
            json_score += 0.20

        # 2. CSV Evaluation
        csv_score = 0.0
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) >= 2:
            for delimiter, name in [(",", "comma"), ("\t", "tab"), (";", "semicolon")]:
                counts = [line.count(delimiter) for line in lines[:20]]
                if counts and any(c >= 2 for c in counts):
                    # Check mode / frequency of delimiter count (handles leading partial lines from header wipes)
                    from collections import Counter
                    count_freq = Counter(c for c in counts if c > 0)
                    if count_freq:
                        mode_count, mode_occurrences = count_freq.most_common(1)[0]
                        consistency_ratio = mode_occurrences / len(counts)
                        if mode_count >= 2 and consistency_ratio >= 0.60:
                            csv_score += 0.80
                            evidence.append(
                                f"Consistent {name} delimiter: {mode_count} columns across "
                                f"{consistency_ratio * 100:.0f}% of sample rows."
                            )
                            features["csv_delimiter"] = delimiter
                            break

        # Decision
        if json_score >= 0.50 and json_score > csv_score:
            evidence.append(f"Strong JSON structural match (confidence {min(0.99, json_score):.2f}).")
            return FormatPrediction(
                format=FileFormat.JSON,
                confidence=min(0.98, json_score),
                magic_bytes_intact=False,
                evidence=evidence,
                features=features,
            )

        if csv_score >= 0.60:
            evidence.append(f"Strong CSV tabular consistency (confidence {min(0.98, csv_score):.2f}).")
            return FormatPrediction(
                format=FileFormat.CSV,
                confidence=min(0.98, csv_score),
                magic_bytes_intact=False,
                evidence=evidence,
                features=features,
            )

        evidence.append("High printable text ratio without dominant JSON or CSV structural tokens.")
        return FormatPrediction(
            format=FileFormat.TEXT,
            confidence=0.90,
            magic_bytes_intact=False,
            evidence=evidence,
            features=features,
        )
