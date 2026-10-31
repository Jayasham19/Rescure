"""
CalmStacks ReSecure Test Suite - Heuristic Structural Repair Engine Tests
System: ReSecure (MVP v1.0)
Module: resecure.backend.tests.test_repair_engine
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from resecure.backend.src.core.format_validators import (
    JPEG_EOI,
    JPEG_SOI,
    PNG_MAGIC,
    validate_csv,
    validate_json,
    validate_png,
)
from resecure.backend.src.core.repair_engine import (
    DISCLOSURE_WARNING,
    repair_file_format,
)


class TestRepairEngine(unittest.TestCase):
    """Verifies heuristic fallback repair and explicit disclosure logging across all formats."""

    def test_repair_text(self) -> None:
        """Verifies stripping orphan nulls and replacing non-UTF-8 bytes."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f_src, \
             tempfile.NamedTemporaryFile(suffix=".repaired.txt", delete=False) as f_out:
            p_src = f_src.name
            p_out = f_out.name

        try:
            # Source with orphan null bytes
            Path(p_src).write_bytes(b"Clean Header\nLine with\x00 null byte\n")
            res = repair_file_format(source_path=p_src, output_path=p_out, format_name="TEXT")

            self.assertEqual(res["verdict"], "STRUCTURALLY_SALVAGED")
            self.assertEqual(res["disclosure_warning"], DISCLOSURE_WARNING)
            self.assertGreater(res["mutations_count"], 0)

            # Assert output file has null bytes removed
            repaired_bytes = Path(p_out).read_bytes()
            self.assertNotIn(b"\x00", repaired_bytes)

            # Assert disclosure log exists on disk
            log_path = Path(res["log_path"])
            self.assertTrue(log_path.is_file())
            log_data = json.loads(log_path.read_text(encoding="utf-8"))
            self.assertEqual(log_data["mutations_count"], res["mutations_count"])
            log_path.unlink(missing_ok=True)
        finally:
            Path(p_src).unlink(missing_ok=True)
            Path(p_out).unlink(missing_ok=True)

    def test_repair_csv_ragged_rows(self) -> None:
        """Verifies padding ragged rows with missing commas and balancing quotes."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_src, \
             tempfile.NamedTemporaryFile(suffix=".repaired.csv", delete=False) as f_out:
            p_src = f_src.name
            p_out = f_out.name

        try:
            # Header has 4 columns; row 2 has only 2 columns; row 3 has unclosed quote
            bad_csv = 'col1,col2,col3,col4\nval1,val2\n"valA,valB,valC,valD\n'
            Path(p_src).write_text(bad_csv, encoding="utf-8")

            res = repair_file_format(source_path=p_src, output_path=p_out, format_name="CSV")
            self.assertEqual(res["verdict"], "STRUCTURALLY_SALVAGED")
            self.assertGreater(res["mutations_count"], 0)

            # Check that the repaired CSV passes validation
            val_result = validate_csv(p_out)
            self.assertTrue(val_result["is_valid"])
            self.assertEqual(val_result["metrics"]["ragged_rows_count"], 0)

            log_path = Path(res["log_path"])
            log_path.unlink(missing_ok=True)
        finally:
            Path(p_src).unlink(missing_ok=True)
            Path(p_out).unlink(missing_ok=True)

    def test_repair_json_truncated_and_trailing_comma(self) -> None:
        """Verifies stripping trailing commas and closing truncated bracket stacks."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_src, \
             tempfile.NamedTemporaryFile(suffix=".repaired.json", delete=False) as f_out:
            p_src = f_src.name
            p_out = f_out.name

        try:
            # Truncated JSON with open array and object, plus trailing comma
            truncated_json = '{"system": "resecure", "events": [{"id": 1, "status": "ok"}, {"id": 2, '
            Path(p_src).write_text(truncated_json, encoding="utf-8")

            res = repair_file_format(source_path=p_src, output_path=p_out, format_name="JSON")
            self.assertEqual(res["verdict"], "STRUCTURALLY_SALVAGED")

            # Validate repaired JSON
            val_result = validate_json(p_out)
            self.assertTrue(val_result["is_valid"])

            # Verify it parses cleanly with json.loads
            repaired_text = Path(p_out).read_text(encoding="utf-8")
            obj = json.loads(repaired_text)
            self.assertEqual(obj["system"], "resecure")

            log_path = Path(res["log_path"])
            log_path.unlink(missing_ok=True)
        finally:
            Path(p_src).unlink(missing_ok=True)
            Path(p_out).unlink(missing_ok=True)

    def test_repair_png_missing_magic_and_iend(self) -> None:
        """Verifies re-injecting PNG magic and appending missing IEND."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f_orig, \
             tempfile.NamedTemporaryFile(suffix=".bad.png", delete=False) as f_src, \
             tempfile.NamedTemporaryFile(suffix=".repaired.png", delete=False) as f_out:
            p_orig = f_orig.name
            p_src = f_src.name
            p_out = f_out.name

        try:
            img = Image.new("RGB", (16, 16), color="yellow")
            img.save(p_orig, format="PNG")
            orig_bytes = Path(p_orig).read_bytes()

            # Corrupt magic and strip terminal IEND (last 12 bytes)
            bad_bytes = b"WIPED_MG" + orig_bytes[8:-12]
            Path(p_src).write_bytes(bad_bytes)

            res = repair_file_format(source_path=p_src, output_path=p_out, format_name="PNG")
            self.assertEqual(res["verdict"], "STRUCTURALLY_SALVAGED")

            # Check that magic header and IEND are restored
            repaired_bytes = Path(p_out).read_bytes()
            self.assertTrue(repaired_bytes.startswith(PNG_MAGIC))
            self.assertTrue(repaired_bytes.endswith(b"IEND\xaeB\x60\x82"))

            log_path = Path(res["log_path"])
            log_path.unlink(missing_ok=True)
        finally:
            for p in (p_orig, p_src, p_out):
                Path(p).unlink(missing_ok=True)

    def test_non_destructive_guard(self) -> None:
        """Verifies that source_path == output_path is rejected."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            path = tf.name

        try:
            with self.assertRaises(ValueError):
                repair_file_format(source_path=path, output_path=path, format_name="TEXT")
        finally:
            Path(path).unlink(missing_ok=True)
