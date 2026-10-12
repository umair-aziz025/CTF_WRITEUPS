# Onion — Detailed Cryptography Write-up

**Category:** Cryptography / Multi-Layer Encoding  
**Category Value:** 400 points  
**Provided file:** `onion.txt`  
**Flag format:** `PCT{...}`

> This file is like an onion. Beneath every layer there's another one. Keep peeling until you reach the core.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{layers_upon_layers_upon_layers}
```

The challenge presents a 96-byte text file named `onion.txt`. The description hints **"This file is like an onion. Beneath every layer there's another one"** point directly to a multi-stage nested encoding pipeline.

The investigation workflow follows a logical sequence:

1. Inspect `onion.txt` and identify Base32 encoding (alphabet `A-Z`, `2-7`, ending with `===`).
2. Decode Base32 to reveal binary data matching zlib header magic bytes (`78 9c`).
3. Decompress zlib payload to expose a Base64 encoded string (`NTA0Mz...`).
4. Decode Base64 string to obtain an obfuscated hex string (`5043547o6p...`).
5. Recognize that non-hex letters (`o`, `p`, `q`, `r`, `s`) are ROT-13 shifted versions of valid hex digits (`b`, `c`, `d`, `e`, `f`).
6. Apply ROT-13 decryption to obtain clean hex bytes (`5043547b6c61...`).
7. Convert hex bytes to ASCII to reveal the flag: `PCT{layers_upon_layers_upon_layers}`.

**Next step:** analyze each layer's transformation mechanics.

---

## 2. Initial inspection & Multi-layer encoding analysis

Opening `onion.txt` yields the string:

```text
PCOPGC3RGTYK2CRV6AZ3EMCKO2E2Z4FLZI3PEC2JV32KX4RVJSXEUNXUVNZDISVORKVPJC7QEVK54OBZ2DLBMAAN7QQF6===
```

### Key Observations
1. **Layer 0 Alphabet:** Upper-case letters `A-Z`, numbers `2-7`, and `===` padding (RFC 4648 Base32).
2. **Layer 1 Magic Bytes:** Decoded Base32 bytes start with `0x78 0x9C`, indicating standard zlib compression (deflate algorithm).
3. **Layer 2 String:** Zlib decompression produces Base64 payload starting with `NTA0Mz...`.
4. **Layer 3 Hex Obfuscation:** Base64 decoding produces a hex-like string where letters `o-s` replace standard hex digits `b-f`.

**Next step:** formulate the mathematical transformation for each layer.

---

## 3. Vulnerability analysis: Layer-by-Layer Transformation Model

$$\begin{array}{|c|l|l|l|}
\hline
\text{Layer} & \text{Input Format} & \text{Transformation Applied} & \text{Resulting Output} \\
\hline
0 & \text{Base32 String} & \text{base64.b32decode}() & \text{Zlib binary payload } (\texttt{78 9c \dots}) \\
1 & \text{Zlib Bytes} & \text{zlib.decompress}() & \text{Base64 String } (\texttt{NTA0Mz\dots}) \\
2 & \text{Base64 String} & \text{base64.b64decode}() & \text{ROT-13 Obfuscated Hex } (\texttt{5043547o\dots}) \\
3 & \text{Obfuscated Hex} & \text{codecs.decode}(\cdot, \text{"rot\_13"}) & \text{Clean Hex String } (\texttt{5043547b6c\dots}) \\
4 & \text{Clean Hex} & \text{bytes.fromhex}() & \text{ASCII Flag: } \text{PCT\{layers\_upon\dots\}} \\
\hline
\end{array}$$

### ROT-13 Hex Character Mapping
In Layer 3, ROT-13 shifts the letters by 13 positions:

$$\text{ROT-13}(\text{'o'}) = \text{'b'}, \quad \text{ROT-13}(\text{'p'}) = \text{'c'}, \quad \text{ROT-13}(\text{'q'}) = \text{'d'}, \quad \text{ROT-13}(\text{'r'}) = \text{'e'}, \quad \text{ROT-13}(\text{'s'}) = \text{'f'}$$

Transforming `5043547o6p61...` via ROT-13 produces `5043547b6c61...`.

Converting `50 43 54 7b 6c 61 79 65 72 73 5f 75 70 6f 6e 5f 6c 61 79 65 72 73 5f 75 70 6f 6e 5f 6c 61 79 65 72 73 7d` to ASCII recovers `PCT{layers_upon_layers_upon_layers}`.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Layer Unwrapping Breakdown

```text
[Layer 0] PCOPGC3RGTYK2CRV6AZ3EMCKO2E2Z4FLZI3PEC2JV32KX4RVJSXEUNXUVNZDISVORKVPJC7QEVK54OBZ2DLBMAAN7QQF6===
    │
    ▼ (Base32 Decode)
[Layer 1] \x78\x9c\xf3\x0bq4\xf0\xad\x0a5\xf03\xb20Jv... (zlib compressed)
    │
    ▼ (Zlib Decompress)
[Layer 2] NTA0MzU0N282cDYxNzk2NTcyNzM1czc1NzA2czZyNXM2cDYxNzk2NTcyNzM1czc1NzA2czZyNXM2cDYx...
    │
    ▼ (Base64 Decode)
[Layer 3] 5043547o6p61796572735s75706s6r5s6p61796572735s75706s6r5s6p61796572737q
    │
    ▼ (ROT-13 Decrypt)
[Layer 4] 5043547b6c61796572735f75706f6e5f6c61796572735f75706f6e5f6c61796572737d
    │
    ▼ (Hex to ASCII)
[Layer 5] PCT{layers_upon_layers_upon_layers}
```

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`onion_solve.py`):

```python
#!/usr/bin/env python3
"""
Onion Solver
Challenge: "This file is like an onion. Beneath every layer there's another one."

Vulnerability / Analysis:
1. Layer 0 (`onion.txt`): Base32-encoded payload starting with `PCOPGC3...`.
2. Layer 1 (Base32 decoded): Zlib-compressed binary payload starting with header `78 9c`.
3. Layer 2 (Zlib decompressed): Base64-encoded string starting with `NTA0Mz...`.
4. Layer 3 (Base64 decoded): Hex string with ROT-13 obfuscated hex digits (`o, p, q, r, s`).
5. Layer 4 (ROT-13 applied): Clean hex string `5043547b6c61796572735f75706f6e5f6c61796572735f75706f6e5f6c61796572737d`.
6. Layer 5 (Hex decoded): Plaintext ASCII flag:
   PCT{layers_upon_layers_upon_layers}
"""

import os
import base64
import zlib
import codecs

def solve():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "onion.txt")

    if not os.path.exists(file_path):
        print(f"[-] Input file not found: {file_path}")
        return None

    with open(file_path, "rb") as f:
        curr = f.read().strip()

    print(f"[*] Step 0: Loaded onion.txt ({len(curr)} bytes)")
    print(f"    Payload: {curr.decode('utf-8')[:60]}...")

    # Layer 1: Base32 Decode
    curr = base64.b32decode(curr)
    print(f"[+] Layer 1 (Base32 Decoded): {len(curr)} bytes (Zlib magic: {curr[:2].hex()})")

    # Layer 2: Zlib Decompress
    curr = zlib.decompress(curr)
    print(f"[+] Layer 2 (Zlib Decompressed): {len(curr)} bytes")
    print(f"    Payload: {curr.decode('utf-8')[:60]}...")

    # Layer 3: Base64 Decode
    curr = base64.b64decode(curr).decode("utf-8")
    print(f"[+] Layer 3 (Base64 Decoded): {len(curr)} characters")
    print(f"    Payload: {curr}")

    # Layer 4: ROT-13 Decryption on Hex String
    clean_hex = codecs.decode(curr, "rot_13")
    print(f"[+] Layer 4 (ROT-13 Applied): {clean_hex}")

    # Layer 5: Hex to ASCII
    flag_bytes = bytes.fromhex(clean_hex)
    flag = flag_bytes.decode("utf-8")

    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python onion_solve.py
```

### Execution Output:

```text
[*] Step 0: Loaded onion.txt (96 bytes)
    Payload: PCOPGC3RGTYK2CRV6AZ3EMCKO2E2Z4FLZI3PEC2JV32KX4RVJSXEUNXUVNZD...
[+] Layer 1 (Base32 Decoded): 58 bytes (Zlib magic: 789c)
[+] Layer 2 (Zlib Decompressed): 96 bytes
    Payload: NTA0MzU0N282cDYxNzk2NTcyNzM1czc1NzA2czZyNXM2cDYxNzk2NTcyNzM1...
[+] Layer 3 (Base64 Decoded): 70 characters
    Payload: 5043547o6p61796572735s75706s6r5s6p61796572735s75706s6r5s6p61796572737q
[+] Layer 4 (ROT-13 Applied): 5043547b6c61796572735f75706f6e5f6c61796572735f75706f6e5f6c61796572737d

==========================================
  FLAG: PCT{layers_upon_layers_upon_layers}
==========================================
```

**Next step:** review potential pitfalls when peeling multi-layer encodings.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Confusing Base32 (`A-Z`, `2-7`) with Base64 | Base64 decode errors on Layer 0 | Identify Base32 alphabet and padding rules |
| Treating zlib binary output as UTF-8 string | `UnicodeDecodeError` in Python | Process intermediate payloads strictly as `bytes` |
| Missing ROT-13 substitution on Layer 3 hex | `ValueError: non-hexadecimal digit found` | Apply ROT-13 transformation to map `o-s` back to `b-f` |

---

## 8. What Made the Challenge Solvable?

1. **Clear Metaphor:** Description "onion" hinted at recursive layered encoding.
2. **Distinctive Layer Signatures:** Base32 alphabet, zlib magic bytes `0x78 0x9C`, and Base64 padding.
3. **Structured Obfuscation:** ROT-13 shifted hex digits logically back into valid hexadecimal characters.

---

## Final Flag

```text
PCT{layers_upon_layers_upon_layers}
```
