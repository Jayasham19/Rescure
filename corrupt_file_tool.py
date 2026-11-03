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
import re
from pathlib import Path
from typing import Optional, List, Tuple


def get_available_sample_files() -> List[Path]:
    """Finds all available sample files across demo_samples and Downloads."""
    candidates = []
    
    # 1. demo_samples
    demo_dir = Path("demo_samples")
    if not demo_dir.is_dir():
        demo_dir = Path(__file__).resolve().parent / "demo_samples"
    
    if demo_dir.is_dir():
        for f in sorted(demo_dir.glob("*.pdf")) + sorted(demo_dir.glob("*.dat")):
            if not f.name.startswith("corrupted_") and not f.name.startswith("Corrupted_") and not f.name.startswith("recovered_"):
                candidates.append(f)

    # 2. Downloads directory
    dl = Path.home() / "Downloads"
    for name in [
        "JNDCV.pdf",
        "AI for Scientific Research.pdf",
        "Monitoring_interstate_river_2014-15.pdf",
        "nscl_module_2.pdf",
    ]:
        p = dl / name
        if p.is_file() and p not in candidates:
            candidates.append(p)

    return candidates


def resolve_file(query_str: Optional[str]) -> Optional[Path]:
    """Smartly resolves a file path from a path, filename, partial name, or number."""
    samples = get_available_sample_files()
    if not query_str:
        return samples[0] if samples else None

    # Check if number passed (e.g. "1")
    if query_str.isdigit():
        idx = int(query_str) - 1
        if 0 <= idx < len(samples):
            return samples[idx].resolve()

    p = Path(query_str)
    if p.is_file():
        return p.resolve()

    # Search in common locations
    search_dirs = [
        Path.cwd(),
        Path("demo_samples"),
        Path(__file__).resolve().parent / "demo_samples",
        Path("data/staging"),
        Path.home() / "Downloads",
    ]

    for d in search_dirs:
        cand = d / p.name
        if cand.is_file():
            return cand.resolve()

    # Case-insensitive substring match
    q_lower = query_str.lower().strip()
    for s in samples:
        if q_lower in s.name.lower():
            return s.resolve()

    return None


def get_manifest_info(file_path: Path) -> Tuple[int, int, int]:
    """
    Attempts to locate .rsmanifest.json for the file to determine K, M, and chunk_size.
    Returns: (data_chunks_k, parity_chunks_m, chunk_size_bytes)
    """
    manifest_candidates = [
        file_path.with_name(f"{file_path.name}.rsmanifest.json"),
        file_path.parent / f"{file_path.name}.rsmanifest.json",
        Path("demo_samples") / f"{file_path.name}.rsmanifest.json",
        Path(__file__).resolve().parent / "demo_samples" / f"{file_path.name}.rsmanifest.json",
        Path("data/staging") / f"{file_path.name}.rsmanifest.json",
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

    if mode in ("visible_broken_recoverable", "1", "visible"):
        mode = "visible_broken_recoverable"
        # Wreck first 512 bytes (file header & structure) in Chunk 0
        corrupt_len = min(512, total_len)
        for i in range(corrupt_len):
            data[i] = fill_byte
        corrupted_indices = [0]
        print(f"Action: Overwrote first {corrupt_len} bytes (magic header) with 0x{fill_byte:02X} ('{chr(fill_byte)}')")
        print("Effect: PDF/Image viewers CANNOT open this file. It is visibly 100% broken.")

    elif mode in ("safe_chunk_corruption", "2", "chunks"):
        mode = "safe_chunk_corruption"
        count = min(chunks_to_corrupt, m_parity)
        for c in range(count):
            start = c * chunk_size
            end = min(start + chunk_size, total_len)
            for i in range(start, min(start + 1024, end)):
                data[i] ^= 0xFF
            corrupted_indices.append(c)
        print(f"Action: Corrupted {count} chunks (indices: {corrupted_indices})")

    elif mode in ("safe_truncation", "3", "truncation"):
        mode = "safe_truncation"
        chunks_to_cut = min(chunks_to_corrupt, m_parity)
        new_len = max(1, total_len - (chunks_to_cut * chunk_size))
        data = data[:new_len]
        corrupted_indices = list(range(k - chunks_to_cut, k))
        print(f"Action: Truncated tail by {total_len - new_len:,} bytes ({chunks_to_cut} chunks)")

    elif mode in ("exceeds_parity_test", "4", "exceeds"):
        mode = "exceeds_parity_test"
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

    # Also mirror into demo_samples if output is Corrupted_<name>
    demo_dir = Path("demo_samples")
    if not demo_dir.is_dir():
        demo_dir = Path(__file__).resolve().parent / "demo_samples"
    if demo_dir.is_dir() and dst.parent != demo_dir.resolve():
        try:
            demo_mirror = demo_dir / dst.name
            demo_mirror.write_bytes(bytes(data))
        except Exception:
            pass

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


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ReSecure Smart File Corruption Tool for Parity Recovery Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # nargs="*" allows unquoted file names with spaces: python corrupt_file_tool.py AI for Scientific Research.pdf
    parser.add_argument("input_file", nargs="*", default=None, help="File to corrupt (name, path, or number 1-5)")
    parser.add_argument("-o", "--output", default=None, help="Output path (default: Corrupted_<filename>)")
    parser.add_argument(
        "-m",
        "--mode",
        default="visible_broken_recoverable",
        help="Mode: 1=visible_broken_recoverable, 2=safe_chunk_corruption, 3=safe_truncation, 4=exceeds_parity_test",
    )
    parser.add_argument(
        "-c",
        "--chunks",
        type=int,
        default=1,
        help="Number of chunks to corrupt (default: 1)",
    )

    args = parser.parse_args()

    raw_query = " ".join(args.input_file) if args.input_file else None
    target_file = resolve_file(raw_query)

    samples = get_available_sample_files()

    if not target_file:
        print("\n=======================================================")
        print("  RESECURE FILE CORRUPTION TEST TOOL")
        print("=======================================================")
        print("Please choose a file to corrupt by typing its number:\n")
        for i, s in enumerate(samples, 1):
            print(f"  [{i}] {s.name}")
        print("\nOr pass a filename directly, for example:")
        print("  python corrupt_file_tool.py JNDCV.pdf")
        print("  python corrupt_file_tool.py 1")
        print("=======================================================\n")

        try:
            choice = input("Enter choice (1-4): ").strip()
            target_file = resolve_file(choice)
        except (EOFError, KeyboardInterrupt):
            pass

    if not target_file or not target_file.is_file():
        print(f"Error: Could not find or resolve file '{raw_query}'.")
        sys.exit(1)

    if args.output:
        out_file = Path(args.output).resolve()
    else:
        # Match RecoveryStudio naming convention: Corrupted_<filename>
        out_file = target_file.parent / f"Corrupted_{target_file.name}"

    corrupt_file_smart(
        input_path=str(target_file),
        output_path=str(out_file),
        mode=args.mode,
        chunks_to_corrupt=args.chunks,
    )


if __name__ == "__main__":
    main()
