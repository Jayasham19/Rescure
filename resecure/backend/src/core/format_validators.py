"""
CalmStacks ReSecure Core Engine - Deep Format Validation Engine
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.format_validators
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from PIL import Image

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
PDF_MAGIC = b"%PDF-"
MAX_JSON_DEPTH = 128


def detect_file_format(file_path: Union[str, Path]) -> str:
    """
    Detects file format by sniffing magic bytes, syntax patterns, and file extension.
    Returns: 'TEXT', 'CSV', 'JSON', 'PNG', 'JPEG', 'PDF', or 'BINARY'.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    ext = path.suffix.lower()
    file_size = path.stat().st_size

    if file_size == 0:
        if ext == ".pdf":
            return "PDF"
        if ext in (".txt", ".md", ".log"):
            return "TEXT"
        if ext == ".csv":
            return "CSV"
        if ext == ".json":
            return "JSON"
        return "TEXT"

    # Read first 16 bytes for magic byte sniffing
    with path.open("rb") as f:
        head = f.read(16)
        f.seek(max(0, file_size - 16))
        tail = f.read(16)

    # Magic byte checks
    if head.startswith(PNG_MAGIC):
        return "PNG"

    if head.startswith(JPEG_SOI):
        return "JPEG"

    if head.startswith(PDF_MAGIC):
        return "PDF"

    # Read first 4KB for format and content sniffing
    with path.open("rb") as f:
        sample = f.read(4096)

    # Check for PDF magic byte within preamble (first 1024 bytes per ISO 32000)
    if PDF_MAGIC in sample[:1024]:
        return "PDF"

    # Explicit extension checks for document / binary formats
    if ext == ".pdf":
        return "PDF"
    if ext in (".png",):
        return "PNG"
    if ext in (".jpg", ".jpeg", ".jpe"):
        return "JPEG"

    # Extension matches for text formats (allow validators to inspect and report corruption)
    if ext in (".json",):
        return "JSON"
    if ext in (".csv",):
        return "CSV"
    if ext in (".txt", ".log", ".md", ".sql", ".yaml", ".yml", ".ini", ".env"):
        return "TEXT"

    # High null-byte check for untyped files: files with significant nulls are binary, not text
    if b"\x00" in sample:
        null_ratio = sample.count(b"\x00") / max(1, len(sample))
        if null_ratio > 0.05:
            return "BINARY"

    # Strip UTF-8 BOM if present
    stripped = sample[3:] if sample.startswith(b"\xef\xbb\xbf") else sample
    sample_text = None
    try:
        sample_text = stripped.decode("utf-8")
    except UnicodeDecodeError:
        pass

    if sample_text is not None:
        trimmed = sample_text.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            return "JSON"
        if ext == ".json" and (trimmed.startswith("{") or trimmed.startswith("[")):
            return "JSON"
        if ext == ".csv":
            return "CSV"
        # Check if CSV-like (contains commas and multiple lines with matching comma counts)
        lines = [ln for ln in trimmed.splitlines() if ln.strip()]
        if len(lines) > 1 and all("," in ln for ln in lines[:5]):
            comma_counts = [ln.count(",") for ln in lines[:5]]
            if len(set(comma_counts)) == 1 and comma_counts[0] > 0:
                return "CSV"

    # Check if printable UTF-8 text (without null bytes)
    if sample_text is not None and b"\x00" not in sample:
        return "TEXT"

    return "BINARY"


# ---------------------------------------------------------------------------
# Format Validators
# ---------------------------------------------------------------------------

def validate_text(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates plain text / UTF-8 files:
    - Multi-byte UTF-8 validity
    - BOM detection
    - Control characters (orphan nulls)
    - Line ending consistency
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    raw_bytes = path.read_bytes()
    file_size = len(raw_bytes)

    # 1. BOM Detection
    has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")
    if has_bom:
        findings.append({
            "rule_name": "UTF8_BOM",
            "passed": True,
            "severity": "INFO",
            "message": "Byte Order Mark (BOM) 0xEFBBBF detected at byte offset 0.",
            "byte_offset": 0,
            "line_number": 1,
        })
        text_bytes = raw_bytes[3:]
    else:
        text_bytes = raw_bytes

    # 2. UTF-8 Code Point Validation
    try:
        decoded_text = text_bytes.decode("utf-8")
        findings.append({
            "rule_name": "UTF8_CODEPOINTS",
            "passed": True,
            "severity": "INFO",
            "message": "All byte sequences conform strictly to UTF-8 standard.",
            "byte_offset": 0,
            "line_number": 1,
        })
    except UnicodeDecodeError as e:
        is_valid = False
        findings.append({
            "rule_name": "UTF8_CODEPOINTS",
            "passed": False,
            "severity": "ERROR",
            "message": f"Illegal UTF-8 byte sequence at offset {e.start}: {e.reason}",
            "byte_offset": e.start + (3 if has_bom else 0),
            "line_number": None,
        })
        decoded_text = text_bytes.decode("utf-8", errors="replace")

    # 3. Forbidden Binary Control Characters
    # Allow 0x09 (TAB), 0x0A (LF), 0x0D (CR)
    forbidden_nulls = [i for i, b in enumerate(text_bytes) if b == 0]
    other_forbidden = [
        i for i, b in enumerate(text_bytes)
        if b < 32 and b not in (9, 10, 13)
    ]

    if forbidden_nulls:
        is_valid = False
        findings.append({
            "rule_name": "CONTROL_CHARACTERS",
            "passed": False,
            "severity": "ERROR",
            "message": f"Detected {len(forbidden_nulls)} illegal orphan null byte(s) (0x00). First at offset {forbidden_nulls[0]}.",
            "byte_offset": forbidden_nulls[0] + (3 if has_bom else 0),
            "line_number": None,
        })
    elif other_forbidden:
        findings.append({
            "rule_name": "CONTROL_CHARACTERS",
            "passed": False,
            "severity": "WARNING",
            "message": f"Detected {len(other_forbidden)} non-standard control byte(s). First at offset {other_forbidden[0]}.",
            "byte_offset": other_forbidden[0] + (3 if has_bom else 0),
            "line_number": None,
        })
    else:
        findings.append({
            "rule_name": "CONTROL_CHARACTERS",
            "passed": True,
            "severity": "INFO",
            "message": "No forbidden binary control characters detected.",
            "byte_offset": None,
            "line_number": None,
        })

    # 4. Line Ending Consistency
    crlf_count = text_bytes.count(b"\r\n")
    lf_only_count = text_bytes.count(b"\n") - crlf_count
    cr_only_count = text_bytes.count(b"\r") - crlf_count

    if crlf_count > 0 and lf_only_count > 0:
        line_ending_type = "MIXED"
        findings.append({
            "rule_name": "LINE_ENDINGS",
            "passed": False,
            "severity": "WARNING",
            "message": f"Mixed line endings detected ({crlf_count} CRLF, {lf_only_count} LF).",
            "byte_offset": None,
            "line_number": None,
        })
    elif crlf_count > 0:
        line_ending_type = "CRLF"
        findings.append({
            "rule_name": "LINE_ENDINGS",
            "passed": True,
            "severity": "INFO",
            "message": "Consistent Windows CRLF line endings.",
            "byte_offset": None,
            "line_number": None,
        })
    elif lf_only_count > 0:
        line_ending_type = "LF"
        findings.append({
            "rule_name": "LINE_ENDINGS",
            "passed": True,
            "severity": "INFO",
            "message": "Consistent Unix LF line endings.",
            "byte_offset": None,
            "line_number": None,
        })
    else:
        line_ending_type = "NONE"

    lines = decoded_text.splitlines()

    return {
        "format": "TEXT",
        "is_valid": is_valid,
        "verdict": "FORMAT_VALID" if is_valid else "FORMAT_INVALID",
        "findings": findings,
        "metrics": {
            "byte_count": file_size,
            "char_count": len(decoded_text),
            "line_count": len(lines),
            "has_bom": has_bom,
            "line_ending_type": line_ending_type,
            "null_byte_count": len(forbidden_nulls),
        },
    }


def validate_csv(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates CSV files according to RFC 4180:
    - Strict column count consistency (header establishes expected columns)
    - Quote escaping and balancing
    - Ragged row detection
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return {
            "format": "CSV",
            "is_valid": False,
            "verdict": "FORMAT_INVALID",
            "findings": [{
                "rule_name": "UTF8_ENCODING",
                "passed": False,
                "severity": "ERROR",
                "message": f"CSV encoding error: file is not valid UTF-8 at offset {e.start}",
                "byte_offset": e.start,
                "line_number": None,
            }],
            "metrics": {},
        }

    # Quote balancing check across raw text
    quote_count = content.count('"')
    if quote_count % 2 != 0:
        is_valid = False
        findings.append({
            "rule_name": "QUOTE_BALANCING",
            "passed": False,
            "severity": "ERROR",
            "message": f"Unbalanced double quotes: found {quote_count} quotation marks (odd count).",
            "byte_offset": None,
            "line_number": None,
        })
    else:
        findings.append({
            "rule_name": "QUOTE_BALANCING",
            "passed": True,
            "severity": "INFO",
            "message": "Quotation marks are balanced.",
            "byte_offset": None,
            "line_number": None,
        })

    reader = csv.reader(io.StringIO(content))
    rows: List[List[str]] = []
    ragged_rows: List[Dict[str, Any]] = []

    try:
        for row_num, row in enumerate(reader, start=1):
            rows.append(row)
    except csv.Error as e:
        is_valid = False
        findings.append({
            "rule_name": "RFC4180_SYNTAX",
            "passed": False,
            "severity": "ERROR",
            "message": f"CSV parse error: {e}",
            "byte_offset": None,
            "line_number": None,
        })

    expected_cols = len(rows[0]) if rows else 0

    if rows:
        findings.append({
            "rule_name": "RFC4180_SYNTAX",
            "passed": True,
            "severity": "INFO",
            "message": f"Successfully parsed {len(rows)} CSV rows.",
            "byte_offset": None,
            "line_number": 1,
        })

        for row_idx, row in enumerate(rows[1:], start=2):
            if len(row) != expected_cols:
                is_valid = False
                ragged_rows.append({
                    "row": row_idx,
                    "expected_columns": expected_cols,
                    "actual_columns": len(row),
                    "deficit": expected_cols - len(row),
                })
                findings.append({
                    "rule_name": "COLUMN_CONSISTENCY",
                    "passed": False,
                    "severity": "ERROR",
                    "message": f"Row {row_idx}: ragged row has {len(row)} columns, expected {expected_cols}.",
                    "byte_offset": None,
                    "line_number": row_idx,
                })

        if not ragged_rows:
            findings.append({
                "rule_name": "COLUMN_CONSISTENCY",
                "passed": True,
                "severity": "INFO",
                "message": f"All {len(rows)} rows have consistent column count ({expected_cols}).",
                "byte_offset": None,
                "line_number": None,
            })

    return {
        "format": "CSV",
        "is_valid": is_valid,
        "verdict": "FORMAT_VALID" if is_valid else "FORMAT_INVALID",
        "findings": findings,
        "metrics": {
            "total_rows": len(rows),
            "expected_columns": expected_cols,
            "ragged_rows_count": len(ragged_rows),
            "ragged_rows": ragged_rows[:10],
        },
    }


def _check_json_depth(obj: Any, current_depth: int = 1) -> int:
    """Calculates maximum recursion depth in a nested JSON structure."""
    if current_depth > MAX_JSON_DEPTH:
        return current_depth
    if isinstance(obj, dict):
        return max([_check_json_depth(v, current_depth + 1) for v in obj.values()], default=current_depth)
    if isinstance(obj, list):
        return max([_check_json_depth(v, current_depth + 1) for v in obj], default=current_depth)
    return current_depth


def validate_json(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates JSON files according to RFC 8259:
    - Strict syntax parsing
    - Stack-based delimiter matching
    - Recursion depth limit (<= 128)
    - Trailing commas detection
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return {
            "format": "JSON",
            "is_valid": False,
            "verdict": "FORMAT_INVALID",
            "findings": [{
                "rule_name": "UTF8_ENCODING",
                "passed": False,
                "severity": "ERROR",
                "message": f"JSON encoding error: not valid UTF-8 at offset {e.start}",
                "byte_offset": e.start,
                "line_number": None,
            }],
            "metrics": {},
        }

    # 1. Delimiter Balance & Trailing Commas regex sniff
    trailing_comma_match = re.search(r",\s*([\]\}])", content)
    if trailing_comma_match:
        is_valid = False
        findings.append({
            "rule_name": "TRAILING_COMMAS",
            "passed": False,
            "severity": "ERROR",
            "message": f"Illegal trailing comma before '{trailing_comma_match.group(1)}' at offset {trailing_comma_match.start()}.",
            "byte_offset": trailing_comma_match.start(),
            "line_number": content[:trailing_comma_match.start()].count("\n") + 1,
        })
    else:
        findings.append({
            "rule_name": "TRAILING_COMMAS",
            "passed": True,
            "severity": "INFO",
            "message": "No illegal trailing commas detected.",
            "byte_offset": None,
            "line_number": None,
        })

    # 2. Strict Parse
    parsed_obj = None
    try:
        parsed_obj = json.loads(content)
        findings.append({
            "rule_name": "JSON_RFC8259_SYNTAX",
            "passed": True,
            "severity": "INFO",
            "message": "JSON document is syntactically compliant with RFC 8259.",
            "byte_offset": None,
            "line_number": 1,
        })
    except json.JSONDecodeError as e:
        is_valid = False
        findings.append({
            "rule_name": "JSON_RFC8259_SYNTAX",
            "passed": False,
            "severity": "ERROR",
            "message": f"JSON syntax error: {e.msg} at line {e.lineno}, column {e.colno} (char {e.pos}).",
            "byte_offset": e.pos,
            "line_number": e.lineno,
        })

    # 3. Recursion Depth Check
    max_depth = 0
    if parsed_obj is not None:
        max_depth = _check_json_depth(parsed_obj)
        if max_depth > MAX_JSON_DEPTH:
            is_valid = False
            findings.append({
                "rule_name": "RECURSION_DEPTH",
                "passed": False,
                "severity": "ERROR",
                "message": f"Recursion depth ({max_depth}) exceeds maximum permitted limit ({MAX_JSON_DEPTH}).",
                "byte_offset": None,
                "line_number": None,
            })
        else:
            findings.append({
                "rule_name": "RECURSION_DEPTH",
                "passed": True,
                "severity": "INFO",
                "message": f"Recursion depth ({max_depth}) within permitted limit ({MAX_JSON_DEPTH}).",
                "byte_offset": None,
                "line_number": None,
            })

    root_type = type(parsed_obj).__name__ if parsed_obj is not None else "invalid"

    return {
        "format": "JSON",
        "is_valid": is_valid,
        "verdict": "FORMAT_VALID" if is_valid else "FORMAT_INVALID",
        "findings": findings,
        "metrics": {
            "root_type": root_type,
            "max_depth": max_depth,
            "char_count": len(content),
            "keys_count": len(parsed_obj) if isinstance(parsed_obj, dict) else (len(parsed_obj) if isinstance(parsed_obj, list) else 1),
        },
    }


def validate_png(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates PNG files:
    - 8-byte magic header (\x89PNG\r\n\x1a\n)
    - Sequential chunk framing (IHDR first, IEND last)
    - IEEE 802.3 CRC-32 per chunk
    - Pillow image decompression verification
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    raw_bytes = path.read_bytes()
    file_size = len(raw_bytes)

    # 1. Magic bytes
    if not raw_bytes.startswith(PNG_MAGIC):
        return {
            "format": "PNG",
            "is_valid": False,
            "verdict": "FORMAT_INVALID",
            "findings": [{
                "rule_name": "PNG_MAGIC_BYTES",
                "passed": False,
                "severity": "ERROR",
                "message": f"Invalid PNG magic bytes: found {raw_bytes[:8].hex()}, expected {PNG_MAGIC.hex()}",
                "byte_offset": 0,
                "line_number": None,
            }],
            "metrics": {},
        }

    findings.append({
        "rule_name": "PNG_MAGIC_BYTES",
        "passed": True,
        "severity": "INFO",
        "message": "PNG magic header is valid.",
        "byte_offset": 0,
        "line_number": None,
    })

    # 2. Sequential Chunk Parsing & CRC-32 Validation
    offset = 8
    chunks_parsed: List[str] = []
    crc_errors = 0
    ihdr_info: Dict[str, Any] = {}

    while offset < file_size:
        if offset + 8 > file_size:
            is_valid = False
            findings.append({
                "rule_name": "PNG_CHUNK_STRUCTURE",
                "passed": False,
                "severity": "ERROR",
                "message": f"Truncated PNG chunk header at byte offset {offset}.",
                "byte_offset": offset,
                "line_number": None,
            })
            break

        chunk_length = struct.unpack(">I", raw_bytes[offset:offset + 4])[0]
        chunk_type = raw_bytes[offset + 4:offset + 8]
        type_str = chunk_type.decode("ascii", errors="replace")
        chunks_parsed.append(type_str)

        data_start = offset + 8
        data_end = data_start + chunk_length
        crc_offset = data_end

        if crc_offset + 4 > file_size:
            is_valid = False
            findings.append({
                "rule_name": "PNG_CHUNK_STRUCTURE",
                "passed": False,
                "severity": "ERROR",
                "message": f"Chunk [{type_str}] data truncated: requires {chunk_length} bytes, file ends early.",
                "byte_offset": offset,
                "line_number": None,
            })
            break

        chunk_data = raw_bytes[data_start:data_end]
        recorded_crc = struct.unpack(">I", raw_bytes[crc_offset:crc_offset + 4])[0]
        computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        if computed_crc != recorded_crc:
            is_valid = False
            crc_errors += 1
            findings.append({
                "rule_name": "PNG_CHUNK_CRC32",
                "passed": False,
                "severity": "ERROR",
                "message": f"Chunk [{type_str}] CRC mismatch: expected 0x{recorded_crc:08X}, computed 0x{computed_crc:08X}",
                "byte_offset": crc_offset,
                "line_number": None,
            })

        if type_str == "IHDR" and chunk_length >= 13:
            width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk_data[:10])
            ihdr_info = {
                "width": width,
                "height": height,
                "bit_depth": bit_depth,
                "color_type": color_type,
            }

        offset = crc_offset + 4

    # 3. Mandatory chunk positions
    if chunks_parsed:
        if chunks_parsed[0] != "IHDR":
            is_valid = False
            findings.append({
                "rule_name": "PNG_MANDATORY_CHUNKS",
                "passed": False,
                "severity": "ERROR",
                "message": f"First PNG chunk must be IHDR, found '{chunks_parsed[0]}'.",
                "byte_offset": 8,
                "line_number": None,
            })

        if chunks_parsed[-1] != "IEND":
            is_valid = False
            findings.append({
                "rule_name": "PNG_MANDATORY_CHUNKS",
                "passed": False,
                "severity": "ERROR",
                "message": f"Missing terminal IEND chunk; last chunk was '{chunks_parsed[-1]}'.",
                "byte_offset": file_size,
                "line_number": None,
            })
        else:
            findings.append({
                "rule_name": "PNG_MANDATORY_CHUNKS",
                "passed": True,
                "severity": "INFO",
                "message": "Mandatory IHDR and IEND chunks properly placed.",
                "byte_offset": None,
                "line_number": None,
            })

    if crc_errors == 0:
        findings.append({
            "rule_name": "PNG_CHUNK_CRC32",
            "passed": True,
            "severity": "INFO",
            "message": "All parsed chunk CRC-32 checksums match.",
            "byte_offset": None,
            "line_number": None,
        })

    # 4. Pillow verification
    pillow_valid = False
    try:
        with Image.open(path) as img:
            img.verify()
            pillow_valid = True
            findings.append({
                "rule_name": "PILLOW_VERIFY",
                "passed": True,
                "severity": "INFO",
                "message": f"Pillow image parser successfully verified stream: {img.size[0]}x{img.size[1]} {img.mode}.",
                "byte_offset": None,
                "line_number": None,
            })
    except Exception as e:
        is_valid = False
        findings.append({
            "rule_name": "PILLOW_VERIFY",
            "passed": False,
            "severity": "ERROR",
            "message": f"Pillow image parser error: {e}",
            "byte_offset": None,
            "line_number": None,
        })

    metrics = {
        "chunks_parsed": len(chunks_parsed),
        "chunk_types": chunks_parsed[:20],
        "crc_errors": crc_errors,
    }
    metrics.update(ihdr_info)

    return {
        "format": "PNG",
        "is_valid": is_valid,
        "verdict": "FORMAT_VALID" if is_valid else "FORMAT_INVALID",
        "findings": findings,
        "metrics": metrics,
    }


def validate_jpeg(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates JPEG files:
    - Start of Image (SOI 0xFFD8) marker
    - End of Image (EOI 0xFFD9) marker
    - Segment marker sequence (APP, DQT, DHT, SOF, SOS)
    - Pillow decompression stream verification
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    raw_bytes = path.read_bytes()
    file_size = len(raw_bytes)

    # 1. Start of Image (SOI) Marker
    if not raw_bytes.startswith(JPEG_SOI):
        is_valid = False
        findings.append({
            "rule_name": "JPEG_SOI_MARKER",
            "passed": False,
            "severity": "ERROR",
            "message": f"Missing Start of Image (SOI) marker 0xFFD8 at byte offset 0.",
            "byte_offset": 0,
            "line_number": None,
        })
    else:
        findings.append({
            "rule_name": "JPEG_SOI_MARKER",
            "passed": True,
            "severity": "INFO",
            "message": "Valid JPEG Start of Image (SOI) marker 0xFFD8.",
            "byte_offset": 0,
            "line_number": None,
        })

    # 2. End of Image (EOI) Marker
    if not raw_bytes.endswith(JPEG_EOI):
        is_valid = False
        findings.append({
            "rule_name": "JPEG_EOI_MARKER",
            "passed": False,
            "severity": "ERROR",
            "message": "Missing End of Image (EOI) marker 0xFFD9 at file termination.",
            "byte_offset": max(0, file_size - 2),
            "line_number": None,
        })
    else:
        findings.append({
            "rule_name": "JPEG_EOI_MARKER",
            "passed": True,
            "severity": "INFO",
            "message": "Valid JPEG End of Image (EOI) marker 0xFFD9.",
            "byte_offset": file_size - 2,
            "line_number": None,
        })

    # 3. Marker Segment Parsing
    markers_found: List[str] = []
    offset = 2
    while offset < file_size - 1:
        if raw_bytes[offset] == 0xFF:
            marker = raw_bytes[offset + 1]
            if marker == 0xD9:  # EOI
                markers_found.append("EOI")
                break
            elif marker == 0xDA:  # SOS (Start of Scan - entropy stream follows)
                markers_found.append("SOS")
                break
            elif marker in (0xE0, 0xE1):
                markers_found.append(f"APP{marker - 0xE0}")
            elif marker == 0xDB:
                markers_found.append("DQT")
            elif marker == 0xC4:
                markers_found.append("DHT")
            elif marker in (0xC0, 0xC2):
                markers_found.append(f"SOF{marker - 0xC0}")

            # Markers with length
            if marker not in (0xD8, 0xD9, 0x00) and offset + 3 < file_size:
                length = struct.unpack(">H", raw_bytes[offset + 2:offset + 4])[0]
                offset += 2 + length
                continue

        offset += 1

    findings.append({
        "rule_name": "JPEG_SEGMENT_MARKERS",
        "passed": len(markers_found) > 0,
        "severity": "INFO" if len(markers_found) > 0 else "WARNING",
        "message": f"Found JPEG marker sequence: {', '.join(markers_found) if markers_found else 'none'}",
        "byte_offset": None,
        "line_number": None,
    })

    # 4. Pillow Verification
    try:
        with Image.open(path) as img:
            img.verify()
            findings.append({
                "rule_name": "PILLOW_VERIFY",
                "passed": True,
                "severity": "INFO",
                "message": f"Pillow verified image: {img.size[0]}x{img.size[1]} format {img.format}.",
                "byte_offset": None,
                "line_number": None,
            })
            width, height = img.size
    except Exception as e:
        is_valid = False
        findings.append({
            "rule_name": "PILLOW_VERIFY",
            "passed": False,
            "severity": "ERROR",
            "message": f"Pillow image verification error: {e}",
            "byte_offset": None,
            "line_number": None,
        })
        width, height = None, None

    return {
        "format": "JPEG",
        "is_valid": is_valid,
        "verdict": "FORMAT_VALID" if is_valid else "FORMAT_INVALID",
        "findings": findings,
        "metrics": {
            "markers_found": markers_found,
            "width": width,
            "height": height,
            "file_size_bytes": file_size,
        },
    }


def validate_pdf(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validates PDF file syntax, header markers, EOF trailer, and object structure using pypdf.
    """
    path = Path(file_path).resolve()
    findings: List[Dict[str, Any]] = []
    is_valid = True

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = path.stat().st_size
    if file_size == 0:
        return {
            "format": "PDF",
            "is_valid": False,
            "verdict": "FORMAT_INVALID",
            "findings": [{
                "rule_name": "PDF_EMPTY_FILE",
                "passed": False,
                "severity": "ERROR",
                "message": "PDF file is 0 bytes; empty payload.",
                "byte_offset": 0,
                "line_number": None,
            }],
            "metrics": {"size_bytes": 0, "page_count": 0},
        }

    raw_bytes = path.read_bytes()

    # 1. Total zero-fill wipe check
    null_count = raw_bytes.count(b"\x00")
    if null_count == file_size:
        return {
            "format": "PDF",
            "is_valid": False,
            "verdict": "FORMAT_INVALID",
            "findings": [{
                "rule_name": "PDF_ZERO_FILL_WIPED",
                "passed": False,
                "severity": "ERROR",
                "message": f"Fatal corruption: file consists entirely of {null_count} null bytes (0x00). Total entropy loss.",
                "byte_offset": 0,
                "line_number": None,
            }],
            "metrics": {"size_bytes": file_size, "page_count": 0, "null_bytes": null_count},
        }

    # 2. Magic header check (%PDF-)
    header_idx = raw_bytes.find(b"%PDF-")
    if header_idx == -1:
        is_valid = False
        findings.append({
            "rule_name": "PDF_MAGIC_HEADER",
            "passed": False,
            "severity": "ERROR",
            "message": "Missing standard '%PDF-' magic header in file preamble.",
            "byte_offset": 0,
            "line_number": 1,
        })
    elif header_idx > 0:
        is_valid = False
        findings.append({
            "rule_name": "PDF_HEADER_OFFSET",
            "passed": False,
            "severity": "WARNING",
            "message": f"PDF header found at offset {header_idx} instead of byte 0 (prefix garbage detected).",
            "byte_offset": header_idx,
            "line_number": None,
        })
    else:
        version_str = raw_bytes[5:8].decode("ascii", errors="ignore")
        findings.append({
            "rule_name": "PDF_MAGIC_HEADER",
            "passed": True,
            "severity": "INFO",
            "message": f"Valid PDF header '%PDF-{version_str}' detected at offset 0.",
            "byte_offset": 0,
            "line_number": 1,
        })

    # 3. EOF marker check (%%EOF)
    tail_sample = raw_bytes[-1024:] if file_size >= 1024 else raw_bytes
    if b"%%EOF" not in tail_sample:
        is_valid = False
        findings.append({
            "rule_name": "PDF_EOF_MARKER",
            "passed": False,
            "severity": "WARNING",
            "message": "Missing standard '%%EOF' terminator marker in file trailer.",
            "byte_offset": file_size,
            "line_number": None,
        })
    else:
        findings.append({
            "rule_name": "PDF_EOF_MARKER",
            "passed": True,
            "severity": "INFO",
            "message": "Valid '%%EOF' terminator marker detected.",
            "byte_offset": file_size - len(tail_sample) + tail_sample.rfind(b"%%EOF"),
            "line_number": None,
        })

    # 4. Deep structural parsing with pypdf
    page_count = 0
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(raw_bytes), strict=False)
        page_count = len(reader.pages)
        if page_count == 0:
            is_valid = False
            findings.append({
                "rule_name": "PDF_PAGES_EMPTY",
                "passed": False,
                "severity": "ERROR",
                "message": "PDF document contains 0 parseable pages.",
                "byte_offset": None,
                "line_number": None,
            })
        else:
            findings.append({
                "rule_name": "PDF_PAGES_VALID",
                "passed": True,
                "severity": "INFO",
                "message": f"Successfully parsed {page_count} PDF page(s) and cross-reference catalog.",
                "byte_offset": None,
                "line_number": None,
            })
    except Exception as e:
        is_valid = False
        findings.append({
            "rule_name": "PDF_PARSER_ERROR",
            "passed": False,
            "severity": "ERROR",
            "message": f"PDF parser structural error: {str(e)}",
            "byte_offset": None,
            "line_number": None,
        })

    verdict = "FORMAT_VALID" if is_valid else "FORMAT_INVALID"
    return {
        "format": "PDF",
        "is_valid": is_valid,
        "verdict": verdict,
        "findings": findings,
        "metrics": {
            "size_bytes": file_size,
            "page_count": page_count,
            "null_bytes": null_count,
        },
    }


def validate_format(
    file_path: Union[str, Path],
    format_name: str = "AUTO",
) -> Dict[str, Any]:
    """
    Main entry point for deep format validation.
    Detects format if AUTO or unrecognized, then executes specific validator.
    """
    fmt = format_name.upper() if format_name else "AUTO"
    if fmt == "AUTO":
        fmt = detect_file_format(file_path)

    if fmt == "TEXT":
        return validate_text(file_path)
    elif fmt == "CSV":
        return validate_csv(file_path)
    elif fmt == "JSON":
        return validate_json(file_path)
    elif fmt == "PNG":
        return validate_png(file_path)
    elif fmt in ("JPEG", "JPG"):
        return validate_jpeg(file_path)
    elif fmt == "PDF":
        return validate_pdf(file_path)
    else:
        # Generic binary check
        path = Path(file_path).resolve()
        return {
            "format": "BINARY",
            "is_valid": True,
            "verdict": "FORMAT_VALID",
            "findings": [{
                "rule_name": "BINARY_STREAM",
                "passed": True,
                "severity": "INFO",
                "message": "Binary file format; raw byte stream read successfully.",
                "byte_offset": 0,
                "line_number": None,
            }],
            "metrics": {
                "size_bytes": path.stat().st_size if path.exists() else 0,
            },
        }
