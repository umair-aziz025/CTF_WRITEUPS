# Trailing Spaces — Detailed Steganography Write-up

**Category:** Steganography / Whitespace Encoding  
**Category Value:** 160 points  
**Provided file:** `memo.txt`  
**Flag format:** `PCT{...}`

> An internal memo full of boring sentences. Why does every line end differently?

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{t4bs_4nd_sp4c3s_4r3_b1ts}
```

The challenge provides a plain-text document named `memo.txt` containing 232 lines of text.

The title **"Trailing Spaces"** and description hint **"Why does every line end differently?"** point directly to **Whitespace Steganography**.

In whitespace steganography, non-printable characters (such as spaces ` ` and horizontal tabs `\t`) appended to the ends of lines hide binary data without altering the visible text displayed by standard text editors or word processors.

The investigation workflow follows a logical sequence:

1. Inspect `memo.txt` using binary mode to preserve line-ending whitespace (`\r\n` vs trailing ` ` / `\t`).
2. Extract the trailing character from each of the 232 lines.
3. Map Space (` `) to binary `0` and Tab (`\t`) to binary `1`.
4. Group the resulting 232-bit stream into 8-bit bytes (MSB-first).
5. Decode the byte array to ASCII to recover the flag: `PCT{t4bs_4nd_sp4c3s_4r3_b1ts}`.

**Next step:** analyze the line-ending properties.

---

## 2. Initial inspection & Line whitespace analysis

Inspecting `memo.txt` in raw binary mode reveals:

- **Total Lines:** 232
- **Line Endings:** Windows CRLF (`\r\n`) preceded by invisible trailing whitespace characters.
- **Character Distribution:** Exactly 1 trailing whitespace byte per line.

### Sample Line Endings Breakdown:

- Line 1 ends with `\x20` (Space) $\rightarrow 0$
- Line 2 ends with `\x09` (Tab) $\rightarrow 1$
- Line 3 ends with `\x20` (Space) $\rightarrow 0$
- Line 4 ends with `\x09` (Tab) $\rightarrow 1$
- Line 5 ends with `\x20` (Space) $\rightarrow 0$
- Line 6 ends with `\x20` (Space) $\rightarrow 0$
- Line 7 ends with `\x20` (Space) $\rightarrow 0$
- Line 8 ends with `\x20` (Space) $\rightarrow 0$

Binary stream for first byte: `01010000_2 = 0x50 = 'P'`.

**Next step:** formulate the whitespace steganography mathematical model.

---

## 3. Vulnerability analysis: Binary Whitespace Encoding

Let $L_i$ denote the $i$-th line of `memo.txt` for $i \in [0, 231]$.

The trailing whitespace character $W_i \in \{\text{` '}, \text{`\t'}\}$ maps to a single binary bit $b_i$:

$$b_i = \begin{cases} 0 & \text{if } W_i = \text{` '} \ (\texttt{0x20}) \\ 1 & \text{if } W_i = \text{`\t'} \ (\texttt{0x09}) \end{cases}$$

### Reconstructing Payload Bytes
To reconstruct the $k$-th byte of hidden message $M$:

$$M[k] = \sum_{j=0}^{7} b_{8k + j} \cdot 2^{7 - j}$$

Processing all 232 bits produces 29 ASCII characters ($232 / 8 = 29$):

$$M[0..28] = \text{"PCT\{t4bs\_4nd\_sp4c3s\_4r3\_b1ts\}"}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Bitstream Extraction Breakdown

$$\begin{array}{|c|c|c|c|l|}
\hline
\text{Line Range} & \text{Whitespace Sequence} & \text{Binary Bits} & \text{Hex Value} & \text{Decoded ASCII} \\
\hline
1 \dots 8 & \text{Space, Tab, Space, Tab, Space, Space, Space, Space} & \texttt{01010000} & \texttt{0x50} & \mathbf{P} \\
9 \dots 16 & \text{Space, Tab, Space, Space, Space, Space, Tab, Tab} & \texttt{01000011} & \texttt{0x43} & \mathbf{C} \\
17 \dots 24 & \text{Space, Tab, Space, Tab, Space, Tab, Space, Space} & \texttt{01010100} & \texttt{0x54} & \mathbf{T} \\
25 \dots 32 & \text{Space, Tab, Tab, Tab, Tab, Space, Tab, Tab} & \texttt{01111011} & \texttt{0x7B} & \mathbf{\{} \\
\dots & \dots & \dots & \dots & \dots \\
225 \dots 232 & \text{Space, Tab, Tab, Tab, Tab, Tab, Space, Tab} & \texttt{01111101} & \texttt{0x7D} & \mathbf{\}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`trailing_spaces_solve.py`):

```python
#!/usr/bin/env python3
"""
Trailing Spaces Solver
Challenge: "An internal memo full of boring sentences. Why does every line end differently?"

Vulnerability / Analysis:
1. `memo.txt` contains 232 lines of text.
2. The description hint ("Trailing Spaces") points directly to whitespace steganography.
3. Every line ends with a single trailing whitespace character:
     Space (' ') -> Bit 0
     Tab ('\t')   -> Bit 1
4. Collecting 232 bits across all lines and grouping into 8-bit bytes (MSB-first) reveals:
   PCT{t4bs_4nd_sp4c3s_4r3_b1ts}
"""

import os

def solve():
    base_dir = os.path.dirname(__file__)
    memo_path = os.path.join(base_dir, "memo.txt")

    if not os.path.exists(memo_path):
        print(f"[-] Input file not found: {memo_path}")
        return None

    with open(memo_path, "rb") as f:
        lines = f.readlines()

    print(f"[*] Loaded {len(lines)} lines from memo.txt")

    bits = []
    for line_no, line in enumerate(lines, 1):
        line_clean = line.rstrip(b"\r\n")
        if line_clean.endswith(b"\t"):
            bits.append(1)
        elif line_clean.endswith(b" "):
            bits.append(0)
        else:
            print(f"[!] Warning: Line {line_no} does not end with space or tab.")

    print(f"[*] Extracted {len(bits)} bits of whitespace steganography.")

    payload = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for bit in bits[i:i + 8]:
            byte_val = (byte_val << 1) | bit
        payload.append(byte_val)

    flag = payload.decode("ascii", errors="ignore")

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
$ python trailing_spaces_solve.py
```

### Execution Output:

```text
[*] Loaded 232 lines from memo.txt
[*] Extracted 232 bits of whitespace steganography.

==========================================
  FLAG: PCT{t4bs_4nd_sp4c3s_4r3_b1ts}
==========================================
```

**Next step:** review common mistakes when analyzing whitespace steganography.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Stripping trailing whitespace automatically with `.strip()` | Destroying the hidden bit payload | Use binary mode `rb` and strip strictly line-ending `\r\n` bytes (`.rstrip(b"\r\n")`) |
| Auto-converting tabs to spaces via IDE auto-formatting | Erasing all `1` bits in the document | Ensure text editor handles raw spaces and tabs without modification |

---

## 8. What Made the Challenge Solvable?

1. **Clear Textual Hint:** Title "Trailing Spaces" pointed directly to line-ending whitespace.
2. **Consistent Bit Count:** Exactly 232 lines = 29 8-bit ASCII characters.
3. **Standard Binary Mapping:** Space $= 0$, Tab $= 1$ with standard MSB-first bit order.

---

## Final Flag

```text
PCT{t4bs_4nd_sp4c3s_4r3_b1ts}
```
