import os
import sys
from pathlib import Path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
import json
from PIL import Image
from resecure.backend.src.services.protection_service import ProtectionService
from resecure.backend.src.core.hasher import hash_file

demo_dir = os.path.abspath("demo_samples")
os.makedirs(demo_dir, exist_ok=True)

# 1. Corrupted JSON (for One-Click Repair / Format Repair)
corrupted_json_content = """{
  "system": "ReSecure Cyber Gateway",
  "version": "1.0.0",
  "cluster_nodes": [
    {"id": "node-01", "status": "ACTIVE"},
    {"id": "node-02", "status": "STANDBY"},
  ],
  "security_policies": {
    "max_retries": 3,
    "air_gap_enforced": true
"""
with open(os.path.join(demo_dir, "corrupted_config.json"), "w", encoding="utf-8") as f:
    f.write(corrupted_json_content)

# 2. Corrupted CSV (ragged rows)
corrupted_csv_content = """tx_id,timestamp,sender,recipient,amount_usd,status
TX1001,2026-10-22T10:00:00Z,ACC-101,ACC-202,1500.00,SETTLED
TX1002,2026-10-22T10:01:00Z,ACC-103,ACC-204,240.50
TX1003,2026-10-22T10:02:00Z,ACC-105,ACC-206,9900.00,PENDING,EXTRA_FLAG,OVERFLOW
TX1004,2026-10-22T10:03:00Z,ACC-107,ACC-208,45.00,SETTLED
"""
with open(os.path.join(demo_dir, "corrupted_ledger.csv"), "w", encoding="utf-8") as f:
    f.write(corrupted_csv_content)

# 3. Healthy Text File (~192KB, 3 full 64KB chunks, perfect for Protect Studio)
base_line = "RESECURE_CONFIDENTIAL_CYBER_AUDIT_LOG_RECORD_INDEX_"
lines = [f"{base_line}{i:05d}: Timestamp=2026-10-22T12:00:00Z, Checksum=OK, Status=VALID" for i in range(2350)]
healthy_text = "\n".join(lines).encode("utf-8")
healthy_txt_path = os.path.join(demo_dir, "healthy_audit_log.txt")
with open(healthy_txt_path, "wb") as f:
    f.write(healthy_text)

# 4. Healthy PNG Image
img = Image.new("RGB", (128, 128), color=(16, 185, 129))
png_path = os.path.join(demo_dir, "healthy_badge.png")
img.save(png_path, format="PNG")

# 5. Pre-Protected Recovery Test Package (Damaged file + manifest + parity)
recov_source_path = os.path.join(demo_dir, "protected_database.dat")
with open(recov_source_path, "wb") as f:
    f.write(healthy_text)

# Protect it with 34% redundancy (K=3, M=2)
ps = ProtectionService()
prot_res = ps.protect_file(
    source_path=recov_source_path,
    redundancy_percentage=34,
    output_dir=demo_dir,
    secret_key="resecure-master-integrity-key-2026"
)

# Create a damaged copy (flip 1 byte in Chunk 0 at offset 500)
damaged_path = os.path.join(demo_dir, "damaged_database.dat")
damaged_bytes = bytearray(healthy_text)
damaged_bytes[500] ^= 0xFF
with open(damaged_path, "wb") as f:
    f.write(damaged_bytes)

print("Demo samples generated successfully in demo_samples/:")
for name in sorted(os.listdir(demo_dir)):
    size = os.path.getsize(os.path.join(demo_dir, name))
    print(f" - {name} ({size} bytes)")
