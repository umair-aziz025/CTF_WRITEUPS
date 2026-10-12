# Dynamic Code — Detailed Reverse Engineering Write-up

**Category:** Reverse Engineering / Code Obfuscation  
**Challenge value:** 450 points  
**Provided file:** `loader.py`  
**Flag format:** `PCT{...}`

> The script builds code from numbers and runs it. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{glac1er_heap_b457ion_4d59}
```

The challenge provides a short Python script (`loader.py`) containing an integer array `data` and an XOR key constant `K = 32`. The script dynamically decodes the integer array into a byte string using single-byte XOR and executes the resulting string at runtime using Python's built-in `exec()` function.

Instead of running potentially untrusted code directly with `exec()`, we perform static reverse engineering by intercepting the XOR decoding operation. Decoding `data` with $K = 32$ produces the plaintext Python code:
```python
print('PCT{glac1er_heap_b457ion_4d59}')
```

The investigation workflow follows a logical sequence:

1. Inspect `loader.py` to identify the obfuscation pattern (`bytes(x ^ K for x in data)`).
2. Extract the integer array `data` and key $K = 32$.
3. Compute the single-byte XOR transformation $x_i \oplus K$ for every byte in `data`.
4. Convert the decoded byte sequence to a UTF-8 string.
5. Inspect the recovered Python source statement to extract the flag.

**Next step:** analyze the source code of `loader.py` and its runtime behavior.

---

## 2. Initial inspection: Analyzing `loader.py`

Opening `loader.py` reveals the following Python code:

```python
# totally harmless script
K = 32
data = [80, 82, 73, 78, 84, 8, 7, 112, 99, 116, 91, 71, 76, 65, 67, 17, 69, 82, 127, 72, 69, 65, 80, 127, 66, 20, 21, 23, 73, 79, 78, 127, 20, 68, 21, 25, 93, 7, 9]
exec(bytes(x ^ K for x in data).decode())
```

### Obfuscation Analysis
- `K = 32`: A single-byte XOR key (`0x20` in hexadecimal, which corresponds to the ASCII space character).
- `data`: A list of 39 integer byte values.
- `exec(...)`: Executes the dynamically reconstructed Python string in the current scope.

**Next step:** perform manual byte deobfuscation and trace the XOR operations.

---

## 3. Reverse Engineering: Single-Byte XOR Deobfuscation

Single-byte XOR obfuscation modifies each ASCII character $C$ into an obfuscated byte $C'$:
$$C' = C \oplus K$$

Since XOR is self-inverting ($(C \oplus K) \oplus K = C$), reversing the operation simply requires applying $\oplus 32$ to each integer in `data`:

| Index | Obfuscated Byte ($x_i$) | Key ($K$) | Deobfuscated Byte ($x_i \oplus 32$) | ASCII Character |
|---:|---:|---:|---:|:---:|
| 0 | 80 (`0x50`) | 32 | 112 (`0x70`) | `p` |
| 1 | 82 (`0x52`) | 32 | 114 (`0x72`) | `r` |
| 2 | 73 (`0x49`) | 32 | 105 (`0x69`) | `i` |
| 3 | 78 (`0x4E`) | 32 | 110 (`0x6E`) | `n` |
| 4 | 84 (`0x54`) | 32 | 116 (`0x74`) | `t` |
| 5 | 8 (`0x08`) | 32 | 40 (`0x28`) | `(` |
| 6 | 7 (`0x07`) | 32 | 39 (`0x27`) | `'` |
| 7 | 112 (`0x70`) | 32 | 80 (`0x50`) | `P` |
| 8 | 99 (`0x63`) | 32 | 67 (`0x43`) | `C` |
| 9 | 116 (`0x74`) | 32 | 84 (`0x54`) | `T` |
| 10 | 91 (`0x5B`) | 32 | 123 (`0x7B`) | `{` |
| $\dots$ | $\dots$ | $\dots$ | $\dots$ | $\dots$ |

Notice how XORing with `32` (`0x20`) toggles bit 5, effectively swapping ASCII case (e.g. `PRINT` $\rightarrow$ `print`, `pct{` $\rightarrow$ `PCT{`).

**Next step:** reconstruct the complete deobfuscated payload.

---

## 4. Deobfuscated Code Reconstruction & Execution

Reconstructing all 39 bytes yields the string:

```python
print('PCT{glac1er_heap_b457ion_4d59}')
```

Executing this statement prints the flag directly to standard output.

**Next step:** write an automated Python script to perform static extraction.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 solver script (`dynamic_code_solve.py`):

```python
#!/usr/bin/env python3
"""
Dynamic Code Solver
Challenge: "The script builds code from numbers and runs it."

Vulnerability / Analysis:
The Python script loader.py contains obfuscated byte data stored as an array of integers:
  K = 32
  data = [80, 82, 73, 78, 84, 8, 7, ...]

The execution flow applies XOR key K = 32 to each byte integer:
  bytes(x ^ K for x in data).decode()

By reconstructing and decoding the payload string without calling exec(),
we extract the underlying Python source code:
  print('PCT{glac1er_heap_b457ion_4d59}')

This immediately reveals the flag string.
"""

import sys

def solve():
    # Given parameters from loader.py
    K = 32
    data = [80, 82, 73, 78, 84, 8, 7, 112, 99, 116, 91, 71, 76, 65, 67, 17, 69, 82, 127, 72, 69, 65, 80, 127, 66, 20, 21, 23, 73, 79, 78, 127, 20, 68, 21, 25, 93, 7, 9]

    print("[*] Reconstructing obfuscated Python code payload...")

    # XOR each integer byte with key K = 32
    decoded_bytes = bytes(x ^ K for x in data)
    decoded_code = decoded_bytes.decode('utf-8')

    print(f"[+] Reconstructed Source Code:\n    {decoded_code}")

    # Extract flag from decoded code string
    if "PCT{" in decoded_code:
        start_idx = decoded_code.find("PCT{")
        end_idx = decoded_code.find("}", start_idx) + 1
        flag = decoded_code[start_idx:end_idx]
        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
    else:
        print("[-] Flag format not detected in decoded string.")

if __name__ == '__main__':
    solve()
```

**Next step:** verify solver script output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python dynamic_code_solve.py
```

### Execution Output:

```text
[*] Reconstructing obfuscated Python code payload...
[+] Reconstructed Source Code:
    print('PCT{glac1er_heap_b457ion_4d59}')

==========================================
  FLAG: PCT{glac1er_heap_b457ion_4d59}
==========================================
```

**Next step:** review common pitfalls in analyzing dynamic code execution.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Blindly running `exec()` on unknown files | Executing untrusted obfuscated code can run malicious system commands | Safely print/decode the payload (`print(bytes(...))`) instead of executing |
| Manual character-by-character decoding | Prone to transcription errors on long arrays | Use Python list comprehension `bytes(x ^ K for x in data)` |
| Misinterpreting `K = 32` as decimal vs hex | XORing with `0x32` (`50`) yields invalid ASCII garbage | Use integer `32` or hex `0x20` |

---

## 8. What Made the Challenge Solvable?

1. **Trivial XOR Key:** Single-byte XOR with constant $K=32$ provides basic obfuscation without cryptographic security.
2. **Reversible Execution Pipeline:** Replacing `exec()` with `print()` allowed safe static code extraction.
3. **Plaintext Embedding:** The secret flag string was hardcoded directly inside the payload's `print()` function.

---

## Final Flag

```text
PCT{glac1er_heap_b457ion_4d59}
```
