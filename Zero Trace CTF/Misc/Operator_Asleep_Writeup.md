# Operator Asleep — Detailed Encoding Write-up

**Category:** Encoding / Base64  
**Category Value:** 40 points  
**Provided file:** `message.txt`  
**Flag format:** `PCT{...}`

> Mail from the Karakoram post, slightly mangled by the wire. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{radar_v4ult_h4rbor_0820c}
```

The challenge provides a single 40-byte text file named `message.txt` containing a Base64-encoded ASCII string.

The investigation workflow follows a logical sequence:

1. Inspect `message.txt` and note the trailing padding character `=` and the character alphabet (`[A-Za-z0-9+/=]`).
2. Identify the encoding format as standard **Base64**.
3. Pass the payload through a standard Base64 decoder.
4. Recover the flag: `PCT{radar_v4ult_h4rbor_0820c}`.

**Next step:** analyze the input payload properties.

---

## 2. Initial inspection & Encoding analysis

Opening `message.txt` yields:

```text
UENUe3JhZGFyX3Y0dWx0X2g0cmJvcl8wODIwY30=
```

### Key Observations
1. **Length:** 40 characters (a multiple of 4 bytes).
2. **Padding:** Ends with a single `=` padding character.
3. **Prefix:** Starts with `UENUe...`, which is the standard Base64 representation of the flag header `PCT{...}`:
   $$\text{Base64}(\text{"PCT\{"}) = \text{"UENUe"}$$

**Next step:** formulate the Base64 decoding mathematical model.

---

## 3. Vulnerability analysis: Base64 Encoding Scheme

Base64 maps sets of three 8-bit bytes (24 bits) into four 6-bit index values chosen from an 64-character alphabet ($\text{A-Z, a-z, 0-9, +, /}$).

### Decoding Bit Transformation

$$\begin{array}{|c|c|c|c|}
\hline
\text{Base64 Chunk} & \text{6-Bit Indices} & \text{Concatenated 24-Bit Binary} & \text{Decoded ASCII Bytes} \\
\hline
\texttt{UENU} & 20, 4, 53, 20 & \texttt{010100 000100 110101 010100} & \texttt{0x50 0x43 0x54} \ (\text{'P', 'C', 'T'}) \\
\texttt{e3Jh} & 30, 55, 36, 0 & \texttt{011110 110111 100100 000000} & \texttt{0x7B 0x72 0x61} \ (\text{'\{', 'r', 'a'}) \\
\dots & \dots & \dots & \dots \\
\hline
\end{array}$$

Applying standard Base64 decoding to the entire payload yields `PCT{radar_v4ult_h4rbor_0820c}`.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Base64 Decoding Procedure

To decode the payload:
1. Read the encoded string `UENUe3JhZGFyX3Y0dWx0X2g0cmJvcl8wODIwY30=` from `message.txt`.
2. Execute `base64.b64decode()` in Python.
3. Convert the resulting byte string to UTF-8 text.

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`operator_asleep_solve.py`):

```python
#!/usr/bin/env python3
"""
Operator Asleep Solver
Challenge: "Mail from the Karakoram post, slightly mangled by the wire."

Vulnerability / Analysis:
1. The file `message.txt` contains a Base64-encoded string: `UENUe3JhZGFyX3Y0dWx0X2g0cmJvcl8wODIwY30=`.
2. Standard Base64 decoding directly reveals the ASCII flag payload:
   PCT{radar_v4ult_h4rbor_0820c}
"""

import os
import base64

def solve():
    base_dir = os.path.dirname(__file__)
    msg_path = os.path.join(base_dir, "message.txt")

    if not os.path.exists(msg_path):
        print(f"[-] Input file not found: {msg_path}")
        return None

    with open(msg_path, "r", encoding="utf-8") as f:
        b64_input = f.read().strip()

    print(f"[*] Base64 Input String: {b64_input}")

    decoded_bytes = base64.b64decode(b64_input)
    flag = decoded_bytes.decode("utf-8")

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
$ python operator_asleep_solve.py
```

### Execution Output:

```text
[*] Base64 Input String: UENUe3JhZGFyX3Y0dWx0X2g0cmJvcl8wODIwY30=

==========================================
  FLAG: PCT{radar_v4ult_h4rbor_0820c}
==========================================
```

**Next step:** review common mistakes when decoding encoded payloads.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Confusing Base64 with custom encryption | Attempting complex frequency analysis or XOR bruteforce | Check for `=`/`==` padding and character set `[A-Za-z0-9+/]` |
| Truncating trailing `=` padding | Invalid length error in base64 decoders | Keep the full 40-character payload intact |

---

## 8. What Made the Challenge Solvable?

1. **Standard Base64 Signature:** Standard Base64 alphabet and `=` padding.
2. **Identifiable Prefix:** `UENU` maps directly to `PCT`.
3. **Reversible Encoding:** Base64 is a 1-to-1 deterministic encoding with zero loss.

---

## Final Flag

```text
PCT{radar_v4ult_h4rbor_0820c}
```
