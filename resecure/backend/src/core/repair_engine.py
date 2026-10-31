"""
CalmStacks ReSecure Core Engine - Heuristic Structural Repair Engine
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.core.repair_engine
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

from .format_validators import JPEG_EOI, JPEG_SOI, PNG_MAGIC, detect_file_format

DISCLOSURE_WARNING = (
    "Heuristic repair executed. Content was mutated to achieve structural compliance; "
    "data loss or truncation has occurred."
)
IEND_CHUNK = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"


def repair_text(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged text/UTF-8:
    - Strips orphan null characters
    - Replaces invalid UTF-8 sequences with U+FFFD
    """
    repair_log: List[Dict[str, Any]] = []

    # 1. Strip orphan null bytes (guarding against 100% zero-fill wipe)
    if b"\x00" in content_bytes:
        count = content_bytes.count(b"\x00")
        if count == len(content_bytes):
            # Entire file consists of null bytes: fatal entropy loss, cannot be repaired as text
            return b"", []
        first_offset = content_bytes.find(b"\x00")
        content_bytes = content_bytes.replace(b"\x00", b"")
        repair_log.append({
            "action": "strip_control_char",
            "byte_offset": first_offset,
            "description": f"Stripped {count} orphan null byte(s) (0x00)",
            "row": None,
            "tokens_appended": None,
        })

    # 2. Decode with replace
    try:
        decoded = content_bytes.decode("utf-8")
        out_bytes = decoded.encode("utf-8")
    except UnicodeDecodeError:
        decoded = content_bytes.decode("utf-8", errors="replace")
        out_bytes = decoded.encode("utf-8")
        repair_log.append({
            "action": "replace_bytes",
            "byte_offset": 0,
            "description": "Replaced corrupted non-UTF-8 byte sequence(s) with Unicode replacement character U+FFFD",
            "row": None,
            "tokens_appended": "\uFFFD",
        })

    return out_bytes, repair_log


def repair_csv(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged CSV files:
    - Balances unclosed double quotes before newlines
    - Pads ragged rows with empty fields to match header column count
    """
    repair_log: List[Dict[str, Any]] = []

    # Decode text
    text = content_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=False)

    if not lines:
        return content_bytes, repair_log

    # 1. Balance unclosed double quotes per line
    fixed_lines: List[str] = []
    for line_idx, line in enumerate(lines, start=1):
        q_count = line.count('"')
        if q_count % 2 != 0:
            line = line + '"'
            repair_log.append({
                "action": "balance_quote",
                "row": line_idx,
                "byte_offset": None,
                "description": f"Row {line_idx}: Appended missing closing quotation mark",
                "tokens_appended": '"',
            })
        fixed_lines.append(line)

    reconstructed_text = "\n".join(fixed_lines)

    # 2. Parse rows and pad columns
    reader = csv.reader(io.StringIO(reconstructed_text))
    rows: List[List[str]] = []
    try:
        for r in reader:
            rows.append(r)
    except csv.Error:
        # Fallback split
        rows = [ln.split(",") for ln in fixed_lines]

    if not rows:
        return reconstructed_text.encode("utf-8"), repair_log

    expected_cols = len(rows[0])
    padded_rows: List[List[str]] = [rows[0]]

    for r_idx, r in enumerate(rows[1:], start=2):
        if len(r) < expected_cols:
            deficit = expected_cols - len(r)
            r = r + [""] * deficit
            repair_log.append({
                "action": "pad_columns",
                "row": r_idx,
                "byte_offset": None,
                "description": f"Row {r_idx}: Padded {deficit} missing column(s) with empty fields",
                "tokens_appended": "," * deficit,
            })
        elif len(r) > expected_cols:
            r = r[:expected_cols]
            repair_log.append({
                "action": "truncate_columns",
                "row": r_idx,
                "byte_offset": None,
                "description": f"Row {r_idx}: Truncated extraneous columns beyond header width ({expected_cols})",
                "tokens_appended": None,
            })
        padded_rows.append(r)

    out_io = io.StringIO()
    writer = csv.writer(out_io, lineterminator="\n")
    writer.writerows(padded_rows)
    return out_io.getvalue().encode("utf-8"), repair_log


def repair_json(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged JSON files:
    - Strips illegal trailing commas before closing braces/brackets
    - Terminates unclosed string literals
    - Appends closing brackets and braces according to delimiter stack
    """
    repair_log: List[Dict[str, Any]] = []
    text = content_bytes.decode("utf-8", errors="replace").strip()

    # 1. Strip trailing commas: `, ]` -> ` ]`, `, }` -> ` }`
    trailing_comma_pattern = re.compile(r",\s*([\]\}])")
    if trailing_comma_pattern.search(text):
        count = len(trailing_comma_pattern.findall(text))
        text = trailing_comma_pattern.sub(r"\1", text)
        repair_log.append({
            "action": "strip_trailing_comma",
            "row": None,
            "byte_offset": None,
            "description": f"Stripped {count} illegal trailing comma(s) before closing delimiters",
            "tokens_appended": None,
        })

    # 2. Check if already valid JSON
    try:
        json.loads(text)
        return text.encode("utf-8"), repair_log
    except json.JSONDecodeError:
        pass

    # 3. Stack-based delimiter tracking to auto-close open structures
    # Scan characters while keeping track of string state and bracket stack
    in_string = False
    escape = False
    stack: List[str] = []

    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char in ("{", "["):
                stack.append(char)
            elif char == "}":
                if stack and stack[-1] == "{":
                    stack.pop()
            elif char == "]":
                if stack and stack[-1] == "[":
                    stack.pop()

    repaired_suffix = ""
    if in_string:
        repaired_suffix += '"'
        repair_log.append({
            "action": "close_string_literal",
            "row": None,
            "byte_offset": len(text),
            "description": "Appended closing quotation mark to terminate open string literal",
            "tokens_appended": '"',
        })

    # Close remaining open brackets in reverse order
    closing_tokens = []
    while stack:
        opener = stack.pop()
        closer = "}" if opener == "{" else "]"
        closing_tokens.append(closer)

    if closing_tokens:
        tokens_str = "".join(closing_tokens)
        repaired_suffix += tokens_str
        repair_log.append({
            "action": "close_bracket_stack",
            "row": None,
            "byte_offset": len(text),
            "description": f"Appended closing delimiter tokens '{tokens_str}' to close unterminated structures",
            "tokens_appended": tokens_str,
        })

    text = text + repaired_suffix

    # Strip any trailing commas again if closing delimiters exposed them
    text = trailing_comma_pattern.sub(r"\1", text)

    return text.encode("utf-8"), repair_log


def repair_png(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged PNG files:
    - Re-injects 8-byte PNG magic header if missing
    - Recalculates invalid chunk CRC-32 checksums
    - Appends standard 12-byte IEND chunk if missing
    """
    repair_log: List[Dict[str, Any]] = []
    data = bytearray(content_bytes)

    # 1. Restore PNG magic header
    if not data.startswith(PNG_MAGIC):
        if b"IHDR" in data:
            ihdr_pos = data.find(b"IHDR")
            if ihdr_pos >= 4:
                prefix = PNG_MAGIC
                data = bytearray(prefix + data[ihdr_pos - 4:])
            else:
                data = bytearray(PNG_MAGIC + data)
        else:
            data = bytearray(PNG_MAGIC + data)

        repair_log.append({
            "action": "restore_png_magic",
            "row": None,
            "byte_offset": 0,
            "description": "Re-injected standard 8-byte PNG magic header \\x89PNG\\r\\n\\x1a\\n",
            "tokens_appended": None,
        })

    # 2. Walk chunks, recalculate invalid CRCs
    offset = 8
    file_len = len(data)
    has_iend = False

    while offset + 8 <= file_len:
        chunk_len = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        type_str = chunk_type.decode("ascii", errors="replace")

        data_start = offset + 8
        data_end = data_start + chunk_len
        crc_offset = data_end

        if crc_offset + 4 > file_len:
            # Chunk truncated; truncate file or close here
            break

        chunk_data = data[data_start:data_end]
        rec_crc = struct.unpack(">I", data[crc_offset:crc_offset + 4])[0]
        calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        if calc_crc != rec_crc:
            data[crc_offset:crc_offset + 4] = struct.pack(">I", calc_crc)
            repair_log.append({
                "action": "recalculate_crc32",
                "row": None,
                "byte_offset": crc_offset,
                "description": f"Recalculated CRC-32 for chunk [{type_str}]: 0x{rec_crc:08X} -> 0x{calc_crc:08X}",
                "tokens_appended": None,
            })

        if type_str == "IEND":
            has_iend = True
            data = data[:crc_offset + 4]  # strip any trailing garbage
            break

        offset = crc_offset + 4

    # 3. Append missing terminal IEND chunk
    if not has_iend:
        data.extend(IEND_CHUNK)
        repair_log.append({
            "action": "append_iend_chunk",
            "row": None,
            "byte_offset": len(data) - len(IEND_CHUNK),
            "description": "Appended standard 12-byte IEND terminal chunk to complete PNG stream",
            "tokens_appended": "IEND",
        })

    return bytes(data), repair_log


def repair_jpeg(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged JPEG files:
    - Injects missing Start of Image (SOI 0xFFD8) marker
    - Appends missing End of Image (EOI 0xFFD9) marker
    """
    repair_log: List[Dict[str, Any]] = []
    data = bytearray(content_bytes)

    # 1. Missing SOI marker
    if not data.startswith(JPEG_SOI):
        data = bytearray(JPEG_SOI + data)
        repair_log.append({
            "action": "inject_soi_marker",
            "row": None,
            "byte_offset": 0,
            "description": "Injected missing Start of Image (SOI) marker 0xFFD8 at offset 0",
            "tokens_appended": "\\xFF\\xD8",
        })

    # 2. Missing EOI marker
    if not data.endswith(JPEG_EOI):
        data.extend(JPEG_EOI)
        repair_log.append({
            "action": "append_eoi_marker",
            "row": None,
            "byte_offset": len(data) - 2,
            "description": "Appended missing End of Image (EOI) marker 0xFFD9 at file termination",
            "tokens_appended": "\\xFF\\xD9",
        })

    return bytes(data), repair_log


def repair_pdf(content_bytes: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Applies heuristic repairs for damaged PDF documents:
    - Checks for zero-fill entropy loss (returns empty bytes if fatal)
    - Strips prepended prefix garbage before %PDF-
    - Synthesizes missing %PDF- header if objects exist
    - Synthesizes missing %%EOF terminator
    - Rebuilds cross-reference and object stream catalog using pypdf
    - Validates output using real PDF parser; returns empty bytes if unrecoverable
    """
    repair_log: List[Dict[str, Any]] = []

    if not content_bytes or content_bytes.count(b"\x00") == len(content_bytes):
        return b"", []

    working = content_bytes

    # 1. Strip prepended prefix garbage before %PDF-
    header_idx = working.find(b"%PDF-")
    if header_idx > 0:
        working = working[header_idx:]
        repair_log.append({
            "action": "strip_prefix_garbage",
            "byte_offset": 0,
            "description": f"Stripped {header_idx} byte(s) of prepended header garbage before %PDF- marker",
            "row": None,
            "tokens_appended": None,
        })
    elif header_idx == -1 and (b"obj" in working or b"/Pages" in working):
        working = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + working
        repair_log.append({
            "action": "synthesize_header",
            "byte_offset": 0,
            "description": "Synthesized standard %PDF-1.4 magic header and binary comment",
            "row": None,
            "tokens_appended": "%PDF-1.4\n",
        })

    # 2. Synthesize missing %%EOF terminator
    if b"%%EOF" not in working[-1024:]:
        working = working + b"\n%%EOF\n"
        repair_log.append({
            "action": "synthesize_eof",
            "byte_offset": len(working),
            "description": "Synthesized missing %%EOF terminator marker",
            "row": None,
            "tokens_appended": "\n%%EOF\n",
        })

    # 3. Rebuild object tree and catalog using pypdf
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(working), strict=False)
        if len(reader.pages) > 0:
            writer = pypdf.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            buf = io.BytesIO()
            writer.write(buf)
            rebuilt = buf.getvalue()
            if len(rebuilt) > 0:
                working = rebuilt
                repair_log.append({
                    "action": "rebuild_pdf_catalog",
                    "byte_offset": None,
                    "description": f"Rebuilt PDF object tree and cross-reference table ({len(reader.pages)} page(s) salvaged)",
                    "row": None,
                    "tokens_appended": None,
                })
    except Exception:
        pass

    # 4. Strict parser verification of repaired bytes
    try:
        import pypdf
        final_reader = pypdf.PdfReader(io.BytesIO(working), strict=False)
        if len(final_reader.pages) > 0:
            return working, repair_log
    except Exception:
        pass

    return b"", []


def repair_file_format(
    source_path: Union[str, Path],
    output_path: Union[str, Path],
    format_name: str = "AUTO",
    log_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Executes best-effort heuristic structural repair:
    - Never modifies source_path (read-only)
    - Writes repaired content to separate output_path
    - Writes forensic disclosure log to log_path
    - Sets verdict to STRUCTURALLY_SALVAGED
    """
    src = Path(source_path).resolve()
    out = Path(output_path).resolve()

    if src == out:
        raise ValueError(f"Non-Destructive Invariant: output_path cannot equal source_path ({src})")

    if not src.is_file():
        raise FileNotFoundError(f"Source file not found: {source_path}")

    fmt = format_name.upper() if format_name else "AUTO"
    if fmt == "AUTO":
        fmt = detect_file_format(src)

    content_bytes = src.read_bytes()

    if fmt == "TEXT":
        repaired_bytes, repair_log = repair_text(content_bytes)
    elif fmt == "CSV":
        repaired_bytes, repair_log = repair_csv(content_bytes)
    elif fmt == "JSON":
        repaired_bytes, repair_log = repair_json(content_bytes)
    elif fmt == "PNG":
        repaired_bytes, repair_log = repair_png(content_bytes)
    elif fmt in ("JPEG", "JPG"):
        repaired_bytes, repair_log = repair_jpeg(content_bytes)
    elif fmt == "PDF":
        repaired_bytes, repair_log = repair_pdf(content_bytes)
    else:
        repaired_bytes = content_bytes
        repair_log = []

    # INVARIANT: Never treat an empty output as successful recovery!
    if len(repaired_bytes) == 0:
        if out.is_file():
            out.unlink(missing_ok=True)
        return {
            "source_path": str(src),
            "output_path": str(out),
            "log_path": None,
            "format": fmt,
            "verdict": "UNRECOVERABLE",
            "disclosure_warning": "Recovery produced 0 bytes. Heuristic recovery is impossible for this corruption pattern (fatal entropy loss).",
            "mutations_count": 0,
            "repair_log": [],
        }

    # Write repaired file with guaranteed byte flushing
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        f.write(repaired_bytes)
        f.flush()
        os.fsync(f.fileno())

    # Write disclosure log
    resolved_log_path = Path(log_path).resolve() if log_path else Path(f"{out}.repaired.log.json")
    resolved_log_path.parent.mkdir(parents=True, exist_ok=True)

    log_data = {
        "source_path": str(src),
        "output_path": str(out),
        "format": fmt,
        "verdict": "STRUCTURALLY_SALVAGED",
        "disclosure_warning": DISCLOSURE_WARNING,
        "mutations_count": len(repair_log),
        "repair_log": repair_log,
    }
    resolved_log_path.write_text(json.dumps(log_data, indent=2), encoding="utf-8")

    return {
        "source_path": str(src),
        "output_path": str(out),
        "log_path": str(resolved_log_path),
        "format": fmt,
        "verdict": "STRUCTURALLY_SALVAGED",
        "disclosure_warning": DISCLOSURE_WARNING,
        "mutations_count": len(repair_log),
        "repair_log": repair_log,
    }
