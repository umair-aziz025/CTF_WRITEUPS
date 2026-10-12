# Double Trouble — Detailed Cryptography Write-up

**Category:** Cryptography / Multi-Stage Decoding  
**Category Value:** 230 points  
**Provided file:** `README_DECRYPT.txt`  
**Flag format:** `PCT{...}`

> A second ransom note, with more layers than the first.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{p33l_3v3ry_l4y3r}
```

The challenge provides a ransom text file named `README_DECRYPT.txt`.

The title **"Double Trouble"** and description hint **"with more layers than the first"** point directly to a multi-stage encoding chain.

The investigation workflow follows a logical sequence:

1. Inspect `README_DECRYPT.txt` and extract the 56-byte hexadecimal token `5131424865324d7a4d336c664d326b7a5a577866655452734d325639`.
2. Perform **Hex Decoding** to obtain the Base64 string `Q1BHe2MzM3lfM2kzZWxfeTRsM2V9`.
3. Perform **Base64 Decoding** to obtain the obfuscated flag string `CPG{c33y_3i3el_y4l3e}`.
4. Recognize that `CPG` is a ROT-13 shift of `PCT`.
5. Apply **ROT-13 Decryption** to unmask the leetspeak flag: `PCT{p33l_3v3ry_l4y3r}`.

**Next step:** analyze the token structure and stage transformations.

---

## 2. Initial inspection & Ransom note analysis

Opening `README_DECRYPT.txt` reveals:

```text
Your files are encrypted.
To prove we hold your data, here is a token:

5131424865324d7a4d336c664d326b7a5a577866655452734d325639

Pay within 48 hours.
```

### Key Observations
1. **Token Composition:** 56 hexadecimal characters (`[0-9a-fA-F]`).
2. **Length:** 56 hex characters $= 28$ bytes.

**Next step:** formulate the three-stage decoding pipeline.

---

## 3. Vulnerability analysis: Three-Stage Decoding Pipeline

$$\begin{array}{|c|l|l|l|}
\hline
\text{Stage} & \text{Input Payload} & \text{Decoder Function} & \text{Output Payload} \\
\hline
1 & \texttt{5131424865324d7a4d336c66\dots} & \text{Hex Decode } (\text{bytes.fromhex}) & \texttt{Q1BHe2MzM3lfM2kzZWxfeTRsM2V9} \\
2 & \texttt{Q1BHe2MzM3lfM2kzZWxfeTRsM2V9} & \text{Base64 Decode } (\text{base64.b64decode}) & \texttt{CPG\{c33y\_3i3el\_y4l3e\}} \\
3 & \texttt{CPG\{c33y\_3i3el\_y4l3e\}} & \text{ROT-13 Decrypt } (\text{codecs.decode}) & \mathbf{\text{PCT\{p33l\_3v3ry\_l4y3r\}}} \\
\hline
\end{array}$$

### ROT-13 Substitution Mapping

$$\text{ROT-13}(\text{'C'}) = \text{'P'}, \quad \text{ROT-13}(\text{'P'}) = \text{'C'}, \quad \text{ROT-13}(\text{'G'}) = \text{'T'}$$

$$\text{ROT-13}(\text{"c33y\_3i3el\_y4l3e"}) = \text{"p33l\_3v3ry\_l4y3r"} \ (\text{leetspeak for "peel_every_layer"})$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Layer Unwrapping Breakdown

```text
[Raw Token] 5131424865324d7a4d336c664d326b7a5a577866655452734d325639
    │
    ▼ (Hex Decode)
[Stage 1] Q1BHe2MzM3lfM2kzZWxfeTRsM2V9
    │
    ▼ (Base64 Decode)
[Stage 2] CPG{c33y_3i3el_y4l3e}
    │
    ▼ (ROT-13 Decrypt)
[Stage 3] PCT{p33l_3v3ry_l4y3r}
```

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`double_trouble_solve.py`):

```python
#!/usr/bin/env python3
"""
Double Trouble Solver
Challenge: "A second ransom note, with more layers than the first."

Vulnerability / Analysis:
1. `README_DECRYPT.txt` contains a ransom note with a 56-byte hex token:
   5131424865324d7a4d336c664d326b7a5a577866655452734d325639
2. Step 1: Hex Decoding yields a Base64 string:
   Q1BHe2MzM3lfM2kzZWxfeTRsM2V9
3. Step 2: Base64 Decoding yields an ROT-13 encrypted flag:
   CPG{c33y_3i3el_y4l3e}
4. Step 3: ROT-13 Decryption shifts CPG -> PCT and unmasks leetspeak flag:
   PCT{p33l_3v3ry_l4y3r}
"""

import os
import re
import base64
import codecs

def solve():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "README_DECRYPT.txt")

    if not os.path.exists(file_path):
        print(f"[-] Input file not found: {file_path}")
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract hex token using regex
    tokens = re.findall(r"[0-9a-fA-F]{16,}", content)
    if not tokens:
        print("[-] No valid hex token found in file.")
        return None

    hex_token = tokens[0]
    print(f"[*] Step 0: Extracted Hex Token: {hex_token}")

    # Step 1: Hex Decode
    b64_string = bytes.fromhex(hex_token).decode("ascii")
    print(f"[+] Step 1 (Hex Decoded): {b64_string}")

    # Step 2: Base64 Decode
    rot13_string = base64.b64decode(b64_string).decode("ascii")
    print(f"[+] Step 2 (Base64 Decoded): {rot13_string}")

    # Step 3: ROT-13 Decode
    flag = codecs.decode(rot13_string, "rot_13")

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
$ python double_trouble_solve.py
```

### Execution Output:

```text
[*] Step 0: Extracted Hex Token: 5131424865324d7a4d336c664d326b7a5a577866655452734d325639
[+] Step 1 (Hex Decoded): Q1BHe2MzM3lfM2kzZWxfeTRsM2V9
[+] Step 2 (Base64 Decoded): CPG{c33y_3i3el_y4l3e}

==========================================
  FLAG: PCT{p33l_3v3ry_l4y3r}
==========================================
```

**Next step:** review potential pitfalls when unwrapping multi-stage encodings.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Stopping at Stage 2 (`CPG{c33y...}`) | Submitting invalid flag format `CPG` | Notice `CPG` is ROT-13 shifted `PCT` and apply final ROT-13 decode |
| Including ransom note headers in hex decoder | `ValueError: non-hexadecimal number found` | Extract hex string using regex `[0-9a-fA-F]{16,}` |

---

## 8. What Made the Challenge Solvable?

1. **Clear Textual Hints:** Description "more layers than the first" signaled multi-stage decoding.
2. **Recognizable Formats:** Hex payload -> Base64 string -> `CPG{...}` ROT-13 header.
3. **Reversible Pipeline:** 1-to-1 deterministic decoders with zero loss.

---

## Final Flag

```text
PCT{p33l_3v3ry_l4y3r}
```
