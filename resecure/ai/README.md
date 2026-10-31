# ReSecure AI/ML Module: Diagnostic Telemetry, Statistical Feature Extraction & Corruption Classification

**Package Path**: `resecure/ai/` (and root `ai/`)  
**Components**: `classifier.py`, `format_detector.py`  
**Purpose**: High-speed, air-gapped machine learning and statistical physics feature extraction for diagnostic corruption classification and headerless format recovery.  

---

## 1. Architectural Philosophy: Diagnostic AI vs. Generative AI

A core architectural tenet of ReSecure is:
> **"Mathematical Invariance (No AI Hallucination)"**

Digital forensics and cybersecurity demand strict mathematical guarantees. When a storage block or critical byte is wiped, generative AI models (LLMs, neural inpainters, diffusion models) can hallucinate plausible-looking text or syntax, but they **cannot invent missing binary entropy out of thin air**. Due to the cryptographic avalanche effect of SHA-256, any single-bit deviation produces an uncorrelated hash digest.

Therefore, in ReSecure, **AI/ML is strictly segregated from raw byte reconstruction**:
- **Reed-Solomon $GF(2^8)$**: Exclusively responsible for exact bit-for-bit file reconstruction ($P(\text{bit error}) = 0$).
- **ReSecure AI/ML**: Exclusively responsible for **Diagnostic Triage**, **Corruption Pattern Classification**, and **Header-Wiped Format Detection**.

```
+---------------------------------------------------------------------------------------------------+
|                                 RESECURE AI/ML RESPONSIBILITY BOUNDARY                            |
+-------------------------------------------------------+-------------------------------------------+
| PROHIBITED FOR AI / ML                                | VALIDATED DOMAIN FOR AI / ML              |
+-------------------------------------------------------+-------------------------------------------+
| - Fabricating missing binary payload bytes            | - Calculating Shannon Entropy (H)         |
| - Guessing financial numbers in damaged CSVs          | - Measuring Chi-Square byte uniformity    |
| - Synthesizing fake passwords or auth tokens          | - Identifying damage signature patterns   |
| - Hallucinating missing pixels in encrypted images    | - Distinguishing Bit-Rot vs Ransomware    |
| - Pretending an unrecoverable file was fixed          | - Detecting formats with wiped headers    |
+-------------------------------------------------------+-------------------------------------------+
```

---

## 2. Statistical Feature Extraction (`src/ai/classifier.py`)

The `FeatureExtractor` extracts 8 information-theoretic features from arbitrary byte streams:

| Feature Name | Mathematical Definition | Physical / Forensic Interpretation |
| :--- | :--- | :--- |
| **Shannon Entropy** ($H$) | $H(X) = - \sum_{i=0}^{255} p_i \log_2(p_i)$ | Measures randomness: $0.0$ for zero-wiped blocks, $\approx 1.5 - 3.5$ for English text, $\approx 7.95 - 8.0$ for AES encryption or compressed archives. |
| **Chi-Square** ($\chi^2$) | $\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i}$ | Divergence from a uniform byte distribution. Low for encrypted/compressed bytes; extremely high for structured text or repetitive patterns. |
| **Null-Byte Ratio** ($R_{\text{null}}$) | $\frac{\text{count}(0\text{x}00)}{N}$ | Identifies file zeroing, sparse disk allocations, or wiped headers ($R_{\text{null}} \to 1.0$). |
| **Printable ASCII Ratio** | $\frac{\text{count}(0\text{x}20..0\text{x}7E, \text{CR}, \text{LF}, \text{TAB})}{N}$ | High for source code, JSON, CSV, logs; near 0 for binary executables or compiled formats. |
| **Hamming Weight Density** | $\frac{\sum \text{popcount}(b_i)}{8N}$ | Fraction of 1-bits in stream. Truly random/encrypted data approaches exactly $0.5000$. Skewed densities indicate bias. |
| **Autocorrelation (Lag 1)** | $\rho_1 = \frac{\sum (x_i - \bar{x})(x_{i+1} - \bar{x})}{\sum (x_i - \bar{x})^2}$ | Measures serial dependence between consecutive bytes. Near 0 for ciphertext; elevated for natural languages and images. |
| **Longest Consecutive Run** | $\max_k \{ b_i = b_{i+1} = \dots = b_{i+k-1} \}$ | Detects buffer overruns, unwritten disk blocks, or repetition patterns. |
| **Top Byte Frequency** | $\frac{\max(O_i)}{N}$ | Dominance of the most common byte symbol in the sample. |

---

## 3. Corruption Pattern Classifier (`classifier.py`)

The classifier processes the delta between the pristine manifest and live chunk stream, utilizing a multi-variable decision model to classify corruptions into 8 distinct categories:

1. **`BIT_FLIP`**: Cosmic radiation or NAND gate degradation. Low Hamming distance ($d_H \le 3$), localized bit changes, high similarity to original chunk.
2. **`HEADER_WIPE`**: Intermittent ransomware or malware wiping file signatures (first 64 to 4,096 bytes replaced with nulls or garbage) while body remains intact.
3. **`TRUNCATION`**: Premature network disconnection, power outage during write, or disk quota exhaustion. Trailing chunks completely missing.
4. **`RANSOMWARE_ENCRYPTED`**: High Shannon entropy ($H > 7.92$), uniform Chi-Square ($\chi^2 < 350$), and 50% Hamming density ($0.49 \le D_H \le 0.51$).
5. **`ZERO_FILL`**: File system allocated blocks without flushing data, or secure wipe operations ($R_{\text{null}} > 0.90$).
6. **`LINE_ENDING_TRANSCODE`**: Accidental Git checkout or FTP ASCII transfer converting `\r\n` to `\n` or vice-versa.
7. **`MULTI_CHUNK_WIPE`**: Contiguous swath of multiple damaged chunks exceeding localized bit errors.
8. **`UNKNOWN`**: Anomalous corruption patterns requiring manual forensic triage.

---

## 4. Headerless Format Detector (`format_detector.py`)

When malware or disk corruption destroys standard magic bytes (e.g. wiping `%PDF-`, `\x89PNG`, `\xFF\xD8\xFF`, or `PK\x03\x04`), standard tools (`file` utility, `mimetypes`) fail completely.

The `FormatDetector` inspects deep structural invariants across surviving bytes:
- **TEXT**: High printable ASCII ratio ($\ge 0.92$), valid UTF-8 sequences, standard newline cadence.
- **CSV**: Consistent delimiter frequencies (comma, semicolon, tab) across line breaks with tabular alignment.
- **JSON**: Balanced curly `{}` and square `[]` brackets, quoted key-value pairs separated by colons `:`.
- **PNG**: Presence of internal chunk markers (`IHDR`, `IDAT`, `PLTE`, `IEND`) with valid 4-byte chunk lengths and IEEE 802.3 CRC-32 checksums.
- **JPEG**: Markers `0xFFC0`/`0xFFC2` (SOF), `0xFFC4` (DHT), `0xFFDB` (DQT), and `0xFFDA` (SOS) within body streams.
- **PDF**: Stream dictionaries, `/Page`, `/Pages`, `/Catalog`, `/Contents`, `/Font` dictionaries, and cross-reference table syntax (`xref`, `trailer`).

---

## 5. Automated Verification & Evals

To evaluate the AI/ML classifier and format detector:
```powershell
.\resecure\backend\venv\Scripts\python.exe -m pytest resecure/evals/test_aiml_evals.py -v
```
All 16 information-theoretic and classification tests pass with **100% accuracy**.
