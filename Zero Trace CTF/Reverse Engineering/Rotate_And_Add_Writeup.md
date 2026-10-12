# Rotate & Add — Detailed Reverse Engineering Write-up

**Category:** Reverse Engineering / Custom Obfuscation  
**Category Value:** 400 points  
**Provided file:** `crackme`  
**Flag format:** `PCT{...}`

> A small binary asks for a flag. The check looks simple, but you can't brute-force your way through it. Find the flag.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{r3v3rs3_l1k3_4_pr0}
```

The challenge provides a stripped 64-bit x86 Linux ELF binary `crackme` (14,472 bytes). The program prompts the user for a flag string and compares it against an internal verification function.

The investigation workflow follows a logical sequence:

1. Disassemble `crackme` and locate the length comparison check (`strlen(input) == 23`).
2. Identify the byte-by-byte transformation routine at offset `0x127a`.
3. Locate the 5-byte repeating XOR key `b"pct26"` stored at `0x2057` in `.rodata`.
4. Extract the 23 target comparison bytes stored at `0x2040`.
5. Deconstruct the forward transformation algorithm:
   $$T_i = \text{ROL}_8(F_i \oplus K_{i \bmod 5}, 3) + i \pmod{256}$$
6. Formulate the exact mathematical inverse:
   $$F_i = \text{ROR}_8((T_i - i) \bmod 256, 3) \oplus K_{i \bmod 5}$$
7. Execute the inverse transformation to recover the flag.

**Next step:** analyze the disassembly and binary parameters.

---

## 2. Initial inspection & Binary disassembly

Inspecting the binary file properties:

- **Format:** ELF 64-bit LSB executable, x86-64, dynamically linked.
- **Stripped:** Symbol table removed.
- **Flag Length Check:** `0x17` ($23_{10}$) bytes.

### Assembly Disassembly (`0x127a` - `0x12a1`):

```asm
127a:  mov    rax,rcx
127d:  mul    rdi
1280:  mov    rax,rdx
1283:  shr    rax,0x2
1287:  and    rdx,0xfffffffffffffffc
128b:  add    rdx,rax
128e:  mov    rax,rcx
1291:  sub    rax,rdx
1294:  movzx  eax,BYTE PTR [r8+rax*1]   ; Fetch key byte K[i % 5] ("pct26")
1299:  xor    al,BYTE PTR [rcx+rsi*1]   ; XOR with input flag byte F[i]
129c:  rol    al,0x3                   ; Rotate left by 3 bits
129f:  add    eax,ecx                  ; Add character index i
12a1:  cmp    BYTE PTR [r9+rcx*1],al   ; Compare against target byte T[i]
```

### Extracted Data Tables

1. **Repeating Key ($K$):** `b"pct26"` (5 bytes at offset `0x2057`).
2. **Target Comparison Array ($T$):** 23 bytes at offset `0x2040`:
   ```text
   01 02 03 4d 26 1f ae 41 0a 33 24 ec cc 25 f8 29 f1 13 7d 45 24 af 5e
   ```

**Next step:** formulate the mathematical transformation model.

---

## 3. Vulnerability analysis: Reversible Byte-by-Byte Transformation

The checker applies three distinct operations per byte:

1. **XOR:** $x_1 = F_i \oplus K_{i \bmod 5}$
2. **Bitwise Left Rotation:** $x_2 = \text{ROL}_8(x_1, 3)$
3. **Index Addition:** $T_i = (x_2 + i) \bmod 256$

Because XOR, bitwise rotation, and modulo addition are all 1-to-1 bijective mappings over $\mathbb{Z}_{256}$, the entire pipeline is **100% reversible**. No one-way hashing or lossy compression occurred.

### Formulating the Inverse Operations

To recover $F_i$ from $T_i$:

1. **Invert Addition:**
   $$x_2 = (T_i - i) \bmod 256$$
2. **Invert Left Rotation:**
   $$x_1 = \text{ROR}_8(x_2, 3)$$
3. **Invert XOR:**
   $$F_i = x_1 \oplus K_{i \bmod 5}$$

Combining into a single closed-form equation:

$$F_i = \text{ROR}_8((T_i - i) \bmod 256, 3) \oplus K_{i \bmod 5}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Inverse Transformation Breakdown

$$\begin{array}{|c|c|c|c|c|c|c|}
\hline
i & T_i & (T_i - i) \bmod 256 & \text{ROR}_8(\cdot, 3) & K_{i \bmod 5} & F_i = \cdot \oplus K & \text{ASCII} \\
\hline
0 & \texttt{0x01} & \texttt{0x01} & \texttt{0x20} & \texttt{'p' (0x70)} & \texttt{0x20} \oplus \texttt{0x70} = \texttt{0x50} & \mathbf{P} \\
1 & \texttt{0x02} & \texttt{0x01} & \texttt{0x20} & \texttt{'c' (0x63)} & \texttt{0x20} \oplus \texttt{0x63} = \texttt{0x43} & \mathbf{C} \\
2 & \texttt{0x03} & \texttt{0x01} & \texttt{0x20} & \texttt{'t' (0x74)} & \texttt{0x20} \oplus \texttt{0x74} = \texttt{0x54} & \mathbf{T} \\
3 & \texttt{0x4D} & \texttt{0x4A} & \texttt{0x49} & \texttt{'2' (0x32)} & \texttt{0x49} \oplus \texttt{0x32} = \texttt{0x7B} & \mathbf{\{} \\
\dots & \dots & \dots & \dots & \dots & \dots & \dots \\
22 & \texttt{0x5E} & \texttt{0x48} & \texttt{0x09} & \texttt{'t' (0x74)} & \texttt{0x09} \oplus \texttt{0x74} = \texttt{0x7D} & \mathbf{\}} \\
\hline
\end{array}$$

Executing this sequence across all 23 indices yields `PCT{r3v3rs3_l1k3_4_pr0}`.

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`rotate_and_add_solve.py`):

```python
#!/usr/bin/env python3
"""
Rotate & Add Solver
Challenge: "A small binary asks for a flag. The check looks simple, but you can't brute-force your way through it."

Vulnerability / Analysis:
1. The binary `crackme` is a 64-bit ELF executable that expects a 23-character input flag.
2. The disassembly reveals a byte-by-byte check algorithm:
     Target[i] = ROL8(Flag[i] ^ Key[i % 5], 3) + i  (mod 256)
   where Key = "pct26" and Target = 0102034d261fae410a3324eccc25f829f1137d4524af5e.
3. Every operation in the transformation pipeline (+, ROL8, XOR) is 100% deterministic and reversible.
4. Inverting the sequence yields:
     Flag[i] = ROR8((Target[i] - i) mod 256, 3) ^ Key[i % 5]
5. Executing the inverse transformation reconstructs the flag:
   PCT{r3v3rs3_l1k3_4_pr0}
"""

import os

def ror8(x, n):
    """Rotate 8-bit unsigned integer right by n bits."""
    return ((x >> n) | (x << (8 - n))) & 0xFF

def rol8(x, n):
    """Rotate 8-bit unsigned integer left by n bits."""
    return ((x << n) | (x >> (8 - n))) & 0xFF

def solve():
    target = bytes.fromhex(
        "01 02 03 4d 26 1f ae 41 0a 33 24 ec cc 25 f8 "
        "29 f1 13 7d 45 24 af 5e"
    )
    key = b"pct26"

    print(f"[*] Target Byte Array Length: {len(target)} bytes")
    print(f"[*] Repeating Key: '{key.decode()}'")

    flag = bytearray()
    for i, t in enumerate(target):
        # Step 1: Undo index addition
        x = (t - i) & 0xFF
        # Step 2: Undo ROL 3 -> Apply ROR 3
        x = ror8(x, 3)
        # Step 3: Undo XOR with repeating key
        x ^= key[i % len(key)]
        flag.append(x)

    flag_str = flag.decode("ascii")

    # Forward verification assertion
    for i, ch in enumerate(flag):
        expected = (rol8(ch ^ key[i % len(key)], 3) + i) & 0xFF
        assert expected == target[i], f"Mismatch at index {i}"

    print(f"[+] Verification passed!")
    print(f"\n==========================================")
    print(f"  FLAG: {flag_str}")
    print(f"==========================================")
    return flag_str

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python rotate_and_add_solve.py
```

### Execution Output:

```text
[*] Target Byte Array Length: 23 bytes
[*] Repeating Key: 'pct26'
[+] Verification passed!

==========================================
  FLAG: PCT{r3v3rs3_l1k3_4_pr0}
==========================================
```

**Next step:** review common pitfalls when reversing custom assembly checking loops.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Confusing logical shift (`>>`) with bitwise rotation (`ROR`) | Corrupting bit positions during inversion | Implement 8-bit rotation: `((x >> n) \| (x << (8 - n))) & 0xFF` |
| Attempting brute-force search across $256^{23}$ state space | Exponential complexity $O(256^{23})$ computation hang | Invert operations deterministically per byte $O(23)$ |
| Missing index addition modulo 256 | Integer underflow or incorrect byte values | Wrap subtraction with `& 0xFF` |

---

## 8. What Made the Challenge Solvable?

1. **Bijective Operations:** All steps (+, ROL, XOR) preserved 100% of information per byte.
2. **Independent Byte Processing:** Each character $F_i$ depended only on index $i$ and target byte $T_i$.
3. **Hard-coded Constants:** The XOR key `"pct26"` and target byte array were statically embedded in `.rodata`.

---

## Final Flag

```text
PCT{r3v3rs3_l1k3_4_pr0}
```
