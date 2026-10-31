"""
CalmStacks ReSecure Test Suite - Format Validation Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_format_validators
"""

from __future__ import annotations

import io
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from PIL import Image

from resecure.backend.src.core.format_validators import (
    JPEG_EOI,
    JPEG_SOI,
    PNG_MAGIC,
    detect_file_format,
    validate_csv,
    validate_format,
    validate_jpeg,
    validate_json,
    validate_png,
    validate_text,
)


class TestFormatValidators(unittest.TestCase):
    """Verifies syntactic and structural compliance validation across all supported formats."""

    def test_text_validation_valid_and_invalid(self) -> None:
        """Verifies text validator on clean UTF-8, BOM, and null byte corruption."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_valid, \
             tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_bom, \
             tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_null, \
             tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_bad_utf8:
            p_valid = f_valid.name
            p_bom = f_bom.name
            p_null = f_null.name
            p_bad_utf8 = f_bad_utf8.name

        try:
            # 1. Clean valid text
            Path(p_valid).write_text("Hello ReSecure World\nSecond Line\n", encoding="utf-8")
            res_valid = validate_text(p_valid)
            self.assertTrue(res_valid["is_valid"])
            self.assertEqual(res_valid["verdict"], "FORMAT_VALID")

            # 2. Text with BOM
            Path(p_bom).write_bytes(b"\xef\xbb\xbfBOM Header Text\n")
            res_bom = validate_text(p_bom)
            self.assertTrue(res_bom["is_valid"])
            self.assertTrue(res_bom["metrics"]["has_bom"])

            # 3. Text with forbidden null bytes
            Path(p_null).write_bytes(b"Text with \x00 null bytes in middle\n")
            res_null = validate_text(p_null)
            self.assertFalse(res_null["is_valid"])
            self.assertEqual(res_null["verdict"], "FORMAT_INVALID")
            self.assertGreater(res_null["metrics"]["null_byte_count"], 0)

            # 4. Text with invalid UTF-8 byte
            Path(p_bad_utf8).write_bytes(b"Bad \xff\xfe non utf8 bytes\n")
            res_bad = validate_text(p_bad_utf8)
            self.assertFalse(res_bad["is_valid"])
        finally:
            for p in (p_valid, p_bom, p_null, p_bad_utf8):
                Path(p).unlink(missing_ok=True)

    def test_csv_validation_valid_and_ragged(self) -> None:
        """Verifies CSV validator on clean RFC 4180 and ragged rows."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_valid, \
             tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_ragged, \
             tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_unclosed:
            p_valid = f_valid.name
            p_ragged = f_ragged.name
            p_unclosed = f_unclosed.name

        try:
            # 1. Valid CSV
            Path(p_valid).write_text("id,name,role\n1,Alice,Admin\n2,Bob,User\n", encoding="utf-8")
            res_valid = validate_csv(p_valid)
            self.assertTrue(res_valid["is_valid"])
            self.assertEqual(res_valid["metrics"]["expected_columns"], 3)
            self.assertEqual(res_valid["metrics"]["ragged_rows_count"], 0)

            # 2. Ragged CSV (row 2 has only 2 columns instead of 3)
            Path(p_ragged).write_text("id,name,role\n1,Alice\n2,Bob,User\n", encoding="utf-8")
            res_ragged = validate_csv(p_ragged)
            self.assertFalse(res_ragged["is_valid"])
            self.assertEqual(res_ragged["metrics"]["ragged_rows_count"], 1)

            # 3. Unclosed quote CSV
            Path(p_unclosed).write_text('id,name,role\n1,"Alice,Admin\n', encoding="utf-8")
            res_unclosed = validate_csv(p_unclosed)
            self.assertFalse(res_unclosed["is_valid"])
        finally:
            for p in (p_valid, p_ragged, p_unclosed):
                Path(p).unlink(missing_ok=True)

    def test_json_validation_valid_and_malformed(self) -> None:
        """Verifies JSON validator on clean RFC 8259, trailing commas, and syntax errors."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_valid, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_trailing, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_bad:
            p_valid = f_valid.name
            p_trailing = f_trailing.name
            p_bad = f_bad.name

        try:
            # 1. Clean JSON
            Path(p_valid).write_text('{"key": "value", "items": [1, 2, 3]}', encoding="utf-8")
            res_valid = validate_json(p_valid)
            self.assertTrue(res_valid["is_valid"])
            self.assertEqual(res_valid["metrics"]["root_type"], "dict")

            # 2. Trailing comma JSON
            Path(p_trailing).write_text('{"key": "value", "items": [1, 2, 3, ]}', encoding="utf-8")
            res_trailing = validate_json(p_trailing)
            self.assertFalse(res_trailing["is_valid"])

            # 3. Truncated malformed JSON
            Path(p_bad).write_text('{"key": "value", "items": [1, 2', encoding="utf-8")
            res_bad = validate_json(p_bad)
            self.assertFalse(res_bad["is_valid"])
        finally:
            for p in (p_valid, p_trailing, p_bad):
                Path(p).unlink(missing_ok=True)

    def test_png_validation_valid_and_corrupt(self) -> None:
        """Verifies PNG validator on genuine PNG and modified CRC / truncated PNG."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_valid, \
             tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_bad_magic, \
             tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_bad_crc:
            p_valid = f_valid.name
            p_bad_magic = f_bad_magic.name
            p_bad_crc = f_bad_crc.name

        try:
            # 1. Generate genuine 16x16 PNG using Pillow
            img = Image.new("RGB", (16, 16), color="red")
            img.save(p_valid, format="PNG")

            res_valid = validate_png(p_valid)
            self.assertTrue(res_valid["is_valid"])
            self.assertEqual(res_valid["metrics"]["width"], 16)
            self.assertEqual(res_valid["metrics"]["height"], 16)

            # 2. Corrupt magic bytes
            valid_bytes = Path(p_valid).read_bytes()
            bad_magic_bytes = b"BADMAGIC" + valid_bytes[8:]
            Path(p_bad_magic).write_bytes(bad_magic_bytes)
            res_magic = validate_png(p_bad_magic)
            self.assertFalse(res_magic["is_valid"])

            # 3. Corrupt IHDR CRC
            # In PNG, IHDR is 13 bytes data. Length: offset 8-11. Type: 12-15. Data: 16-28. CRC: 29-32.
            bad_crc_bytes = bytearray(valid_bytes)
            bad_crc_bytes[29] = (bad_crc_bytes[29] + 1) % 256
            Path(p_bad_crc).write_bytes(bad_crc_bytes)
            res_crc = validate_png(p_bad_crc)
            self.assertFalse(res_crc["is_valid"])
            self.assertGreater(res_crc["metrics"]["crc_errors"], 0)
        finally:
            for p in (p_valid, p_bad_magic, p_bad_crc):
                Path(p).unlink(missing_ok=True)

    def test_jpeg_validation_valid_and_truncated(self) -> None:
        """Verifies JPEG validator on genuine JPEG and truncated EOI."""
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f_valid, \
             tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f_bad_eoi:
            p_valid = f_valid.name
            p_bad_eoi = f_bad_eoi.name

        try:
            # 1. Genuine JPEG
            img = Image.new("RGB", (32, 32), color="blue")
            img.save(p_valid, format="JPEG")

            res_valid = validate_jpeg(p_valid)
            self.assertTrue(res_valid["is_valid"])
            self.assertEqual(res_valid["metrics"]["width"], 32)
            self.assertEqual(res_valid["metrics"]["height"], 32)

            # 2. Truncate EOI (\xFF\xD9)
            valid_bytes = Path(p_valid).read_bytes()
            truncated_bytes = valid_bytes[:-2]
            Path(p_bad_eoi).write_bytes(truncated_bytes)
            res_bad = validate_jpeg(p_bad_eoi)
            self.assertFalse(res_bad["is_valid"])
        finally:
            for p in (p_valid, p_bad_eoi):
                Path(p).unlink(missing_ok=True)

    def test_detect_file_format(self) -> None:
        """Verifies auto-detection of formats."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_png, \
             tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_csv, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_json:
            p_png = f_png.name
            p_csv = f_csv.name
            p_json = f_json.name

        try:
            img = Image.new("RGB", (8, 8), color="green")
            img.save(p_png, format="PNG")
            Path(p_csv).write_text("a,b,c\n1,2,3\n", encoding="utf-8")
            Path(p_json).write_text('{"foo": "bar"}', encoding="utf-8")

            self.assertEqual(detect_file_format(p_png), "PNG")
            self.assertEqual(detect_file_format(p_csv), "CSV")
            self.assertEqual(detect_file_format(p_json), "JSON")
        finally:
            for p in (p_png, p_csv, p_json):
                Path(p).unlink(missing_ok=True)
