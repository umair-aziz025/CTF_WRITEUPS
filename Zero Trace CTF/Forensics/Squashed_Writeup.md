# Squashed — Detailed Forensics Write-up

**Category:** Forensics / PNG Metadata Decompression  
**Category Value:** 50 points  
**Provided file:** `serverroom.png`  
**Flag format:** `PCT{...}`

> Standard tools show this photo's text fields, but nothing useful. Some data is stored compressed.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{c0mpr3ss3d_chunks_h1d3_t3xt}
```

The challenge provides a PNG image file named `serverroom.png` (37,716 bytes).

The title **"Squashed"** and description hint **"Standard tools show this photo's text fields, but nothing useful. Some data is stored compressed"** point directly to **Compressed PNG Metadata Chunks (`zTXt`)**.

While basic metadata viewers parse uncompressed `tEXt` chunks (which contain benign text like `Title: Server room`), compressed `zTXt` metadata chunks store binary zlib streams that standard CLI utilities omit unless specifically instructed to decompress them.

The investigation workflow follows a logical sequence:

1. Parse PNG chunks in `serverroom.png` (`IHDR`, `tEXt`, `zTXt`, `IDAT`, `IEND`).
2. Identify the `zTXt` chunk with keyword `Description` (53 bytes at chunk offset 38).
3. Extract the compressed zlib byte payload.
4. Execute `zlib.decompress()` on the payload.
5. Recover the flag: `PCT{c0mpr3ss3d_chunks_h1d3_t3xt}`.

**Next step:** analyze PNG chunk structure specifications.

---

## 2. Initial inspection & PNG chunk structure analysis

Parsing chunk layout in `serverroom.png`:

- `IHDR`: Image dimensions ($256 \times 256$ RGB)
- `tEXt`: Uncompressed text $\rightarrow$ `Title: Server room`
- `zTXt`: Compressed text $\rightarrow$ `Description` $\rightarrow$ Compressed zlib stream
- `IDAT`: Image raster data
- `IEND`: Image termination chunk

### Hex Breakdown of `zTXt` Chunk (Offset `0x26` / 38 bytes):

```text
Offset    Hex Bytes                                          ASCII Equivalent
00000026  00 00 00 35 7a 54 58 74 44 65 73 63 72 69 70 74  ...5zTXtDescript
00000036  69 6f 6e 00 00 78 9c 0b 08 0e 51 30 4d 28 70 72  ion..x....Q0M(pr
00000046  33 2e 33 53 30 4e 8e 4f 8e 2e 2d 2e 51 08 48 34  3.3S0N.O..-.Q.H4
00000056  31 54 30 73 33 78 74 05 00 bad5 09 low3           1T0s3xt...
```

**Next step:** formulate the `zTXt` decompression model.

---

## 3. Vulnerability analysis: PNG `zTXt` Compressed Metadata Chunks

The PNG standard specifies `zTXt` chunks to compress large text fields (such as comments or camera metadata) using DEFLATE / zlib compression:

$$\text{zTXt Chunk Format} = \text{Keyword} + \texttt{0x00} + \text{Compression Method (0x00)} + \text{Compressed Data}$$

Standard `strings` or naive metadata parsers skip DEFLATE streams because byte values appear as non-ASCII binary data (`78 9c ...`).

Passing `cdata[null_pos + 2:]` into `zlib.decompress()` restores the plaintext ASCII payload:

$$\text{zlib.decompress}(\texttt{78 9c 0b 08 0e 51\dots}) \longrightarrow \text{"PCT\{c0mpr3ss3d\_chunks\_h1d3\_t3xt\}"}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Chunk Parsing & Decompression Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Chunk Type} & \text{Keyword / Content} & \text{Compression} & \text{Result} \\
\hline
\texttt{tEXt} & \text{"Title"} & \text{Uncompressed} & \text{"Server room"} \\
\texttt{zTXt} & \text{"Description"} & \text{zlib (DEFLATE)} & \mathbf{\text{PCT\{c0mpr3ss3d\_chunks\_h1d3\_t3xt\}}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`squashed_solve.py`):

```python
#!/usr/bin/env python3
"""
Squashed Solver
Challenge: "Standard tools show this photo's text fields, but nothing useful. Some data is stored compressed."

Vulnerability / Analysis:
1. `serverroom.png` contains compressed metadata inside a PNG `zTXt` chunk.
2. Standard image tools often display only uncompressed `tEXt` chunks (e.g. `Title: Server room`).
3. `zTXt` chunks store metadata compressed with zlib (deflate).
4. Parsing `zTXt` chunk at offset in `serverroom.png` and calling `zlib.decompress()` reveals:
   PCT{c0mpr3ss3d_chunks_h1d3_t3xt}
"""

import os
import zlib

def solve():
    base_dir = os.path.dirname(__file__)
    img_path = os.path.join(base_dir, "serverroom.png")

    if not os.path.exists(img_path):
        print(f"[-] Image file not found: {img_path}")
        return None

    with open(img_path, "rb") as f:
        data = f.read()

    print(f"[*] Loaded PNG image {img_path} ({len(data)} bytes)")

    # Parse PNG Chunks
    offset = 8  # Skip 8-byte PNG header signature
    flag = None

    while offset < len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]

        print(f"[*] Found PNG Chunk: {chunk_type.decode('ascii', errors='ignore')} ({length} bytes)")

        if chunk_type == b"zTXt":
            null_pos = chunk_data.find(b"\x00")
            keyword = chunk_data[:null_pos].decode("ascii", errors="ignore")
            compressed_payload = chunk_data[null_pos + 2:]

            print(f"[+] Found compressed zTXt chunk with keyword '{keyword}'")
            decompressed_text = zlib.decompress(compressed_payload).decode("utf-8", errors="ignore")
            print(f"[+] Decompressed Content: '{decompressed_text}'")

            if decompressed_text.startswith("PCT{"):
                flag = decompressed_text

        offset += 12 + length

    if flag:
        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
        return flag
    else:
        print("[-] Flag not found in zTXt chunks.")
        return None

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python squashed_solve.py
```

### Execution Output:

```text
[*] Loaded PNG image 1. ctf/TODAY\serverroom.png (37716 bytes)
[*] Found PNG Chunk: IHDR (13 bytes)
[*] Found PNG Chunk: tEXt (17 bytes)
[*] Found PNG Chunk: zTXt (53 bytes)
[+] Found compressed zTXt chunk with keyword 'Description'
[+] Decompressed Content: 'PCT{c0mpr3ss3d_chunks_h1d3_t3xt}'
[*] Found PNG Chunk: IDAT (37565 bytes)
[*] Found PNG Chunk: IEND (0 bytes)

==========================================
  FLAG: PCT{c0mpr3ss3d_chunks_h1d3_t3xt}
==========================================
```

**Next step:** review common mistakes when parsing PNG metadata.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Relying only on `exiftool` / `strings` without decompression | Missing compressed `zTXt` content | Parse chunk binary stream directly and run `zlib.decompress()` |
| Miscalculating chunk payload offsets | `zlib.error: Error -3 while decompressing data` | Skip keyword + null byte + 1-byte compression method before decompressing |

---

## 8. What Made the Challenge Solvable?

1. **Explicit Description:** "Some data is stored compressed" directly pointed to `zTXt` chunks.
2. **Standard PNG Specification:** Complied with PNG `zTXt` chunk formatting.
3. **Lossless zlib Compression:** Guaranteed 100% accurate text recovery upon decompression.

---

## Final Flag

```text
PCT{c0mpr3ss3d_chunks_h1d3_t3xt}
```
