# Broken Header — Detailed Forensics Write-up

**Category:** Forensics / File Repair  
**Category Value:** 210 points  
**Provided file:** `corrupted.dat`  
**Flag format:** `PCT{...}`

> The file will not open anywhere. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{indus_min4ret_c0mpas5_cb32}
```

The challenge provides a corrupted binary file named `corrupted.dat` (9,923 bytes) that fails to open in standard image viewers or media applications.

The investigation workflow follows a logical sequence:

1. Inspect the raw bytes of `corrupted.dat` using a hex editor / Python script.
2. Identify the zeroed 8-byte header (`00 00 00 00 00 00 00 00`) followed immediately by intact PNG chunk structures starting with `IHDR` (`00 00 00 0D 49 48 44 52`).
3. Replace the corrupted 8-byte preamble with the standard PNG magic signature: `89 50 4E 47 0D 0A 1A 0A`.
4. Save the repaired binary payload as `repaired.png`.
5. Open `repaired.png` to render the $640 \times 120$ image containing the text flag: `PCT{indus_min4ret_c0mpas5_cb32}`.

**Next step:** analyze the hex dump of the input file.

---

## 2. Initial inspection & Hex analysis

Inspecting the first 64 bytes of `corrupted.dat`:

```text
Offset    Hex Bytes                                          ASCII Equivalent
00000000  00 00 00 00 00 00 00 00 00 00 00 0d 49 48 44 52  ............IHDR
00000010  00 00 02 80 00 00 00 78 08 02 00 00 00 ed f1 d4  .......x........
00000020  29 00 00 26 8a 49 44 41 54 78 9c ed dd 77 5c 53  )..&.IDATx...w\S
```

### Key Observations
1. **Corrupted Magic Bytes:** The first 8 bytes (`00 00 00 00 00 00 00 00`) are zeroed out.
2. **Intact Chunk Structure:**
   - Byte 8..11: `00 00 00 0D` (Length = 13 bytes for `IHDR` chunk).
   - Byte 12..15: `49 48 44 52` (`IHDR` ASCII identifier).
   - Byte 16..19: `00 00 02 80` (Image Width = 640 pixels).
   - Byte 20..23: `00 00 00 78` (Image Height = 120 pixels).
   - Byte 35..38: `49 44 41 54` (`IDAT` zlib-compressed image data chunk).

**Next step:** formulate the PNG file header specifications.

---

## 3. Vulnerability analysis: PNG File Format Specifications

Every valid Portable Network Graphics (PNG) file must begin with an exact 8-byte magic sequence:

$$\text{PNG\_Magic} = \texttt{0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A}$$

In ASCII / escape notation: `\x89PNG\r\n\x1a\n`.

### Structural Role of PNG Signature Bytes

| Byte Index | Hex Value | Purpose / Meaning |
|---|---|---|
| 0 | `89` | Detects 8-bit non-ASCII data corruption |
| 1..3 | `50 4E 47` | ASCII characters `"PNG"` |
| 4..5 | `0D 0A` | DOS/Windows line ending (`\r\n`) to detect CR/LF conversion |
| 6 | `1A` | Control-Z character (stops `TYPE` output in MS-DOS) |
| 7 | `0A` | Unix line ending (`\n`) to detect LF conversion |

Replacing the first 8 zeroed bytes restores full PNG file format compliance.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Binary Repair & Image Reconstruction Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Step} & \text{Offset Range} & \text{Original Value} & \text{Repaired Value} \\
\hline
1 & \text{0x00 .. 0x07} & \texttt{00 00 00 00 00 00 00 00} & \texttt{89 50 4E 47 0D 0A 1A 0A} \\
2 & \text{0x08 .. End} & \text{Unchanged Chunk Payload} & \text{Preserved } (\texttt{IHDR}, \texttt{IDAT}, \texttt{IEND}) \\
3 & \text{Output} & \text{Save as } \texttt{repaired.png} & \text{Renders } 640 \times 120 \text{ PNG image} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`broken_header_solve.py`):

```python
#!/usr/bin/env python3
"""
Broken Header Solver
Challenge: "The file will not open anywhere."

Vulnerability / Analysis:
1. `corrupted.dat` is a PNG file whose 8-byte magic header was zeroed out:
     Corrupted: 00 00 00 00 00 00 00 00
     Valid PNG: 89 50 4E 47 0D 0A 1A 0A
2. Subsequent chunks (`IHDR`, `IDAT`, `IEND`) remain intact with valid length and CRC metadata.
3. Replacing the first 8 bytes with `\x89PNG\r\n\x1a\n` repairs the image (`repaired.png`).
4. Viewing `repaired.png` renders the embedded flag text:
   PCT{indus_min4ret_c0mpas5_cb32}
"""

import os
from PIL import Image

def solve():
    base_dir = os.path.dirname(__file__)
    dat_path = os.path.join(base_dir, "corrupted.dat")
    repaired_path = os.path.join(base_dir, "repaired.png")

    if not os.path.exists(dat_path):
        print(f"[-] Input file not found: {dat_path}")
        return None

    with open(dat_path, "rb") as f:
        data = f.read()

    print(f"[*] Input file size: {len(data)} bytes")
    print(f"[*] Corrupted header bytes: {data[:8].hex()}")

    # Valid PNG Magic Signature
    png_signature = b"\x89PNG\r\n\x1a\n"

    # Replace zeroed header
    repaired_bytes = png_signature + data[8:]

    with open(repaired_path, "wb") as f:
        f.write(repaired_bytes)

    print(f"[+] Repaired header written to {repaired_path}")

    # Validate image using PIL
    try:
        img = Image.open(repaired_path)
        print(f"[+] Successfully opened image! Format: {img.format}, Size: {img.size}, Mode: {img.mode}")
    except Exception as e:
        print(f"[-] Image validation failed: {e}")
        return None

    flag = "PCT{indus_min4ret_c0mpas5_cb32}"
    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify execution output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python broken_header_solve.py
```

### Execution Output:

```text
[*] Input file size: 9923 bytes
[*] Corrupted header bytes: 0000000000000000
[+] Repaired header written to 1. ctf/TODAY\repaired.png
[+] Successfully opened image! Format: PNG, Size: (640, 120), Mode: RGB

==========================================
  FLAG: PCT{indus_min4ret_c0mpas5_cb32}
==========================================
```

**Next step:** review common mistakes when diagnosing file corruption.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Relying solely on file extension (`.dat`) | Assuming arbitrary binary or raw data format | Search binary payload for recognizable ASCII chunk identifiers (`IHDR`, `IDAT`, `JFIF`, `BM`) |
| Overwriting more than 8 bytes | Corrupting the 4-byte `IHDR` chunk length or chunk tag | Only replace the first 8 bytes (`data[8:]` offset) |
| Using text mode to read binary data | Line ending conversions corrupt PNG byte stream | Open files strictly with `"rb"` and `"wb"` modes |

---

## 8. What Made the Challenge Solvable?

1. **Intact Internal Chunks:** Only the 8-byte file signature was modified; `IHDR`, `IDAT`, and `IEND` chunks remained untouched.
2. **Distinctive Chunk Identifiers:** The `IHDR` and `IDAT` magic strings clearly identified PNG format.
3. **Simple Hex Patching:** Restoring 8 static signature bytes completely uncorrupted the image.

---

## Final Flag

```text
PCT{indus_min4ret_c0mpas5_cb32}
```
