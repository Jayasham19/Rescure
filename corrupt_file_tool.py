"""
ReSecure Corruptor & Resilience Test Tool
----------------------------------------
Allows controlled file corruption for testing Reed-Solomon GF(2^8) Erasure Coding.

Why did files previously show "DAMAGE EXCEEDS REDUNDANCY (E > M)"?
1. Default Parity Redundancy is 20%. For a file with K=12 chunks (64 KB each), M = 3 parity chunks.
2. In Reed-Solomon, M parity chunks can recover AT MOST M corrupted chunks (E <= M).
3. If you truncate 55% of a file, 7 out of 12 chunks are missing (E = 7). 7 > 3, so mathematical recovery is impossible!
4. If you insert bytes (fragmentation), chunk offsets shift, corrupting all subsequent chunks (E = 12).
5. If you zero out 40% of the file, 5 chunks are corrupted (E = 5 > 3).

Why did some files not "look" corrupted?
- PDF viewers (Chrome, Acrobat) are very lenient: if you corrupt internal metadata, the reader ignores errors and still renders the pages.
- To make a file VISIBLY BROKEN (Acrobat/Chrome says "Failed to load PDF"), we corrupt the magic header (%PDF-).
  Because the header is only in Chunk 0, E = 1 <= M, making it 100% broken to viewers yet 100% mathematically recoverable!
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional


def get_manifest_info(file_path: Path) -> tuple[int, int, int]:
    """
    Attempts to locate .rsmanifest.json for the file to determine K, M, and chunk_size.
    Returns: (data_chunks_k, parity_chunks_m, chunk_size_bytes)
    """
    manifest_candidates = [
        file_path.with_name(f"{file_path.name}.rsmanifest.json"),
        file_path.parent / f"{file_path.name}.rsmanifest.json",
        Path("data/staging") / f"{file_path.name}.rsmanifest.json",
        Path("demo_samples") / f"{file_path.name}.rsmanifest.json",
        Path.home() / "Downloads" / f"{file_path.name}.rsmanifest.json",
    ]
    for m in manifest_candidates:
        if m.is_file():
            try:
                data = json.loads(m.read_text(encoding="utf-8"))
                ec = data.get("erasure_coding", {})
                k = ec.get("data_chunks_k", 12)
                m_count = ec.get("parity_chunks_m", 3)
                c_size = ec.get("chunk_size_bytes", 65536)
                return k, m_count, c_size
            except Exception:
                pass

    # Default estimation for 64KB chunks and 20% redundancy
    file_size = file_path.stat().st_size if file_path.exists() else 1
    chunk_size = 65536
    k = max(1, (file_size + chunk_size - 1) // chunk_size)
    m_count = max(1, (k * 20 + 99) // 100)
    return k, m_count, chunk_size


def corrupt_file_smart(
    input_path: str,
    output_path: str,
    mode: str = "visible_broken_recoverable",
    chunks_to_corrupt: int = 1,
    fill_byte: int = 0x58,  # 'X'
) -> dict:
    """
    Corrupts a file with mathematical awareness of Reed-Solomon parity boundaries.

    Modes:
    1. 'visible_broken_recoverable':
       - Wrecks the magic header (%PDF- or image signature) in Chunk 0.
       - Result: File CANNOT be opened by PDF reader or Image viewer (Visibly 100% broken).
       - Solvability: Exactly 1 chunk damaged (E = 1 <= M). Bit-for-bit 100% recoverable!

    2. 'safe_chunk_corruption':
       - Corrupts exactly `chunks_to_corrupt` distinct chunks (e.g. 1 or 2 chunks).
       - Solvability: E <= M. 100% bit-for-bit recoverable!

    3. 'safe_truncation':
       - Truncates only from the tail within the parity budget (e.g. truncates 1 chunk).
       - Solvability: E <= M. 100% bit-for-bit recoverable!

    4. 'exceeds_parity_test':
       - Corrupts M + 2 chunks deliberately.
       - Result: Triggers ReSecure's SAFE FAILURE PROTOCOL (E > M).
    """
    src = Path(input_path).resolve()
    dst = Path(output_path).resolve()

    if not src.is_file():
        raise FileNotFoundError(f"Input file not found: {src}")

    data = bytearray(src.read_bytes())
    k, m_parity, chunk_size = get_manifest_info(src)
    total_len = len(data)

    print(f"\n=======================================================")
    print(f"  RESECURE CORRUPTION ENGINE: {src.name}")
    print(f"=======================================================")
    print(f"File Size        : {total_len:,} bytes")
    print(f"Data Chunks (K)  : {k} chunks (chunk_size: {chunk_size:,} bytes)")
    print(f"Parity Available : {m_parity} chunks (can recover up to E <= {m_parity})")
    print(f"Selected Mode    : {mode}")

    corrupted_indices = []

    if mode == "visible_broken_recoverable":
        # Wreck first 512 bytes (file header & structure) in Chunk 0
        corrupt_len = min(512, total_len)
        for i in range(corrupt_len):
            data[i] = fill_byte
        corrupted_indices = [0]
        print(f"Action: Overwrote first {corrupt_len} bytes (header) with 0x{fill_byte:02X}")
        print("Effect: PDF/Image viewers CANNOT open this file. It is visibly broken.")

    elif mode == "safe_chunk_corruption":
        # Corrupt specified number of chunks (capped at M for safety)
        count = min(chunks_to_corrupt, m_parity)
        for c in range(count):
            start = c * chunk_size
            end = min(start + chunk_size, total_len)
            # Corrupt 1000 bytes inside each chunk
            for i in range(start, min(start + 1024, end)):
                data[i] ^= 0xFF
            corrupted_indices.append(c)
        print(f"Action: Corrupted {count} chunks (indices: {corrupted_indices})")

    elif mode == "safe_truncation":
        # Truncate at most M chunks from the tail
        chunks_to_cut = min(chunks_to_corrupt, m_parity)
        new_len = max(1, total_len - (chunks_to_cut * chunk_size))
        data = data[:new_len]
        corrupted_indices = list(range(k - chunks_to_cut, k))
        print(f"Action: Truncated tail by {total_len - new_len:,} bytes ({chunks_to_cut} chunks)")

    elif mode == "exceeds_parity_test":
        # Deliberately corrupt M + 2 chunks
        chunks_to_wreck = min(k, m_parity + 2)
        for c in range(chunks_to_wreck):
            offset = c * chunk_size + 100
            if offset < total_len:
                data[offset:min(offset + 256, total_len)] = b"\x00" * min(256, total_len - offset)
                corrupted_indices.append(c)
        print(f"Action: Deliberately damaged {len(corrupted_indices)} chunks (exceeds parity M={m_parity})")

    else:
        raise ValueError(f"Unknown mode: {mode}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(data))

    e = len(corrupted_indices)
    is_solvable = e <= m_parity

    print(f"Output Written To: {dst}")
    print(f"Damaged Chunks (E): {e} {corrupted_indices}")
    print(f"Solvability Status: {'[OK] EXACT SOLVABLE (E <= M)' if is_solvable else '[FAIL] DAMAGE EXCEEDS REDUNDANCY (E > M)'}")
    print(f"=======================================================\n")

    return {
        "source": str(src),
        "output": str(dst),
        "k": k,
        "m": m_parity,
        "e": e,
        "damaged_indices": corrupted_indices,
        "is_solvable": is_solvable,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ReSecure Smart File Corruption Tool for Parity Recovery Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Corrupt any file so it's visibly broken but 100% recoverable (E=1 <= M):
  python corrupt_file_tool.py "my_document.pdf"

  # 2. Corrupt 2 chunks safely (E=2 <= M):
  python corrupt_file_tool.py "my_document.pdf" --mode safe_chunk_corruption --chunks 2

  # 3. Truncate tail safely within parity limit:
  python corrupt_file_tool.py "my_document.pdf" --mode safe_truncation

  # 4. Deliberately exceed parity to test Safe Failure (E > M):
  python corrupt_file_tool.py "my_document.pdf" --mode exceeds_parity_test
        """,
    )
    parser.add_argument("input_file", nargs="?", default=None, help="Path to the file to corrupt")
    parser.add_argument("-o", "--output", default=None, help="Output destination (default: <name>-corrupted.<ext>)")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["visible_broken_recoverable", "safe_chunk_corruption", "safe_truncation", "exceeds_parity_test"],
        default="visible_broken_recoverable",
        help="Corruption mode (default: visible_broken_recoverable)",
    )
    parser.add_argument(
        "-c",
        "--chunks",
        type=int,
        default=1,
        help="Number of chunks to corrupt for safe_chunk_corruption (default: 1)",
    )

    args = parser.parse_args()

    input_path = args.input_file
    if not input_path:
        # Check standard sample files or ask
        for candidate in [
            "C:/Users/ndsha/Downloads/Monitoring_interstate_river_2014-15.pdf",
            "C:/Users/ndsha/Downloads/AI for Scientific Research.pdf",
            "demo_samples/nscl_module_2.pdf",
            "demo_samples/test_document.pdf",
        ]:
            if Path(candidate).is_file():
                input_path = candidate
                break

    if not input_path or not Path(input_path).is_file():
        print("Usage: python corrupt_file_tool.py <path_to_file> [--mode <mode>]")
        print("\nAvailable files you can corrupt:")
        for candidate in [
            "C:/Users/ndsha/Downloads/Monitoring_interstate_river_2014-15.pdf",
            "C:/Users/ndsha/Downloads/AI for Scientific Research.pdf",
            "demo_samples/nscl_module_2.pdf",
        ]:
            if Path(candidate).is_file():
                print(f" - {candidate}")
        sys.exit(1)

    target_file = Path(input_path).resolve()
    if args.output:
        out_file = Path(args.output).resolve()
    else:
        out_file = target_file.parent / f"{target_file.stem}-corrupted{target_file.suffix}"

    corrupt_file_smart(
        input_path=str(target_file),
        output_path=str(out_file),
        mode=args.mode,
        chunks_to_corrupt=args.chunks,
    )
