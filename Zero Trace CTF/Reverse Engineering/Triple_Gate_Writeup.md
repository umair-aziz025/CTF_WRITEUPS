# Triple Gate — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 260 points  
**File:** `triple-gate`  
**Flag format:** `PCT{...}`

> Triple gate. Pass all three. Download the ELF binary, reverse it, and find the password (the binary prints the flag).

## 1. Result and approach

**Password:**

```text
mYmy-oWAy-6Mh
```

**Flag:**

```text
PCT{5haheen_h3ap_1ndu5_ec1648e}
```

The password is an intermediate result, not the flag. The executable checks three password segments, then uses the complete password as a repeating XOR key to decode a 31-byte flag.

Our approach is to identify the input layout, solve each independent check, reconstruct the flag decoder, and verify both results against the original binary. The three checks require different techniques: XOR inversion, modular arithmetic, and a small search with an algebraically derived final byte.

## 2. Initial inspection

Run these commands with the binary in the current directory:

```bash
file triple-gate
sha256sum triple-gate
strings -a triple-gate
objdump -d -M intel triple-gate
```

The sample is a stripped, dynamically linked, little-endian x86-64 PIE ELF. Its interpreter is `/lib64/ld-linux-x86-64.so.2`.

SHA-256:

```text
fa5083d9ede2e7fe551750827772294dac5679f059091c8cd663020bff8716e7
```

Useful strings include:

```text
   [TRIPLE GATE]  v1.0
Nope. Access denied.
Correct! flag:
```

Imports include `strlen`, `snprintf`, `fgets`, `strcspn`, and `putc`. No readable full flag appears in the strings output. The success message and character-output function provide landmarks for following the validation and output paths.

Startup code passes static address `0x1160` to `__libc_start_main`, identifying the main routine despite the stripped symbols. Addresses in this write-up are static disassembly addresses; PIE allows the runtime load base to change.

**Next step:** follow input handling to identify the password constraints before considering any search.

## 3. Recover the password format

The input buffer begins at `rsp + 0x20`. The program copies `argv[1]` using `snprintf`, or reads standard input with `fgets` and removes its line ending using `strcspn`.

Both paths reach:

```asm
11bc: call strlen@plt
11c1: cmp  rax,0xd
11c5: je   11f9
```

The required length is `0x0d = 13` bytes. Then:

```asm
11f9: cmp BYTE PTR [rsp+0x24],0x2d
11fe: jne 11c7
1200: cmp BYTE PTR [rsp+0x29],0x2d
1205: jne 11c7
```

Subtracting the buffer offset `0x20` gives indices 4 and 9. Both must contain `0x2d`, the hyphen character.

```text
AAAA-BBBB-CCC
```

| Input indices, zero-based | Purpose |
|---|---|
| 0–3 | Gate 1: four bytes |
| 4 | Literal `-` |
| 5–8 | Gate 2: four bytes |
| 9 | Literal `-` |
| 10–12 | Gate 3: three bytes |

This immediately separates the recovery into small problems. Searching all 13 characters together would ignore information already available in the code.

**Next step:** translate the first four-byte check and reverse it directly.

## 4. Gate 1: bytewise XOR

The first loop loads two tables and compares four transformed input bytes:

```asm
1209: lea   rsi,[rip+0xe40]    ; table at 0x2050
1210: lea   rcx,[rip+0xe35]    ; target at 0x204c
1217: movzx edx,BYTE PTR [rbx+rax]
121b: xor   dl,BYTE PTR [rsi+rax]
121e: cmp   dl,BYTE PTR [rcx+rax]
1221: jne   11c7
1223: add   rax,0x1
1227: cmp   rax,0x4
122b: jne   1217
```

For each index `i`, the condition is:

```text
A[i] XOR key[i] = target[i]
```

XOR is self-inverse, so:

```text
A[i] = target[i] XOR key[i]
```

| Index | Target | Key | Recovered byte | Character |
|---:|---|---|---|---|
| 0 | `0x35` | `0x58` | `0x6d` | `m` |
| 1 | `0x77` | `0x2e` | `0x59` | `Y` |
| 2 | `0xc3` | `0xae` | `0x6d` | `m` |
| 3 | `0x7c` | `0x05` | `0x79` | `y` |

The first segment is **`mYmy`**. Both the key and target are known, so brute force is unnecessary.

**Next step:** trace the second loop. It uses arithmetic rather than XOR, so its byte-width semantics matter.

## 5. Gate 2: modular multiplication

```asm
122f: lea   rsi,[rsp+0x25]     ; password index 5
1234: lea   rcx,[rip+0xe0d]    ; target at 0x2048
123b: movzx edx,BYTE PTR [rsi+rax]
123f: lea   edx,[rdx+rdx*8]
1242: add   edx,eax
1244: cmp   BYTE PTR [rcx+rax],dl
1247: jne   11c7
```

The `lea` calculates `9*x`. The loop index is added, and the comparison uses `dl`, only the low eight bits. Therefore:

```text
(9 * B[i] + i) mod 256 = target2[i]
```

The target is `e7 10 4b 44`. Ordinary division by nine would be wrong because the result wraps modulo 256.

Since 9 and 256 are relatively prime, nine has a modular inverse:

```text
9 * 57 = 513 = 2*256 + 1
```

Thus:

```text
B[i] = ((target2[i] - i) * 57) mod 256
```

| Index | Target | Recovered ASCII | Character | Forward check |
|---:|---|---:|---|---|
| 0 | `0xe7` | 111 | `o` | `(9*111 + 0) % 256 = 231` |
| 1 | `0x10` | 87 | `W` | `(9*87 + 1) % 256 = 16` |
| 2 | `0x4b` | 65 | `A` | `(9*65 + 2) % 256 = 75` |
| 3 | `0x44` | 121 | `y` | `(9*121 + 3) % 256 = 68` |

The second segment is **`oWAy`**, giving:

```text
mYmy-oWAy-???
```

**Next step:** translate the final three-byte check exactly. A familiar multiplier does not guarantee a standard hash implementation.

## 6. Gate 3: a 32-bit hash-like check

```asm
1257: movzx edx,BYTE PTR [rsp+0x2a]
125c: movzx eax,BYTE PTR [rsp+0x2b]
1261: xor   edx,0x7578d2cd
1267: imul  edx,edx,0x1000193
126d: xor   eax,edx
126f: movzx edx,BYTE PTR [rsp+0x2c]
1274: imul  eax,eax,0x1000193
127a: xor   eax,edx
127c: cmp   eax,0xf6109d6c
1281: jne   11c7
```

Let the last three password bytes be `a`, `b`, and `c`:

```text
h1 = ((a XOR 0x7578d2cd) * 0x01000193) mod 2^32
h2 = ((h1 XOR b) * 0x01000193) mod 2^32
h2 XOR c = 0xf6109d6c
```

The multiplier is the FNV prime, but there is **no multiplication after the final XOR** in the machine code. Implementing three complete FNV-1a rounds would not reproduce this comparison.

Because the arithmetic uses 32-bit registers, Python must retain only the low 32 bits after each multiplication:

```python
h = expression & 0xFFFFFFFF
```

### Derive the third byte

A printable-ASCII search contains 95 possible bytes per position. Instead of checking `95^3 = 857,375` triples, search `95^2 = 9,025` pairs and calculate:

```text
c = h2 XOR 0xf6109d6c
```

Keep a candidate only if the complete value of `c` is in the printable range. Do not truncate it to eight bits: a value above 255 means the pair cannot satisfy the full 32-bit comparison with a single byte.

The search finds one printable match:

```text
6Mh
```

Printable ASCII is our search choice, not a restriction imposed by the executable. We establish one match within this alphabet and confirm acceptance by running the binary.

The password is now **`mYmy-oWAy-6Mh`**.

**Next step:** recover the flag-printing transformation. The password itself is not the challenge submission.

## 7. The flag decoder: overlapping stores and repeating XOR

After all gates pass, the program loads two 16-byte constants:

```asm
1287: movdqa xmm0,XMMWORD PTR [rip+0xdd1]  ; 0x2060
12a2: movaps XMMWORD PTR [rsp],xmm0
12a6: movdqa xmm0,XMMWORD PTR [rip+0xdc2]  ; 0x2070
12ae: movups XMMWORD PTR [rsp+0xf],xmm0
```

The second store starts at offset **15**, so it overlaps the final byte of the first store. Together they build a 31-byte buffer. Reproduce the actual writes:

```python
encrypted = bytearray(31)
encrypted[0:16] = data[0x2060:0x2070]
encrypted[15:31] = data[0x2070:0x2080]
```

Taking 31 contiguous bytes from `0x2060` would be wrong. An equivalent extraction is the first 15 bytes of the first block followed by all 16 bytes of the second block.

The output loop uses multiplication by `0x4ec4ec4f`, a right shift by 34, and subtraction of 13 times the quotient. For its indices, this calculates:

```text
key_index = i - 13 * floor(i / 13) = i % 13
```

This is a compiler optimization for division and remainder, not another encryption key. The loop then reads the original password and XORs it with the assembled buffer:

```asm
12e0: movzx edi,BYTE PTR [rsp+rax+0x20]
12e5: xor   dil,BYTE PTR [rbp+rbx]
12f2: call  putc@plt
12f7: cmp   rbx,0x1f
```

The full decryption equation is:

```python
flag[i] = encrypted[i] ^ password[i % 13]
```

It prints `0x1f = 31` bytes and a newline. Both hyphens are part of the repeating password key.

This explains why bypassing the checks with an arbitrary password would not reliably print the intended flag: the password bytes also control decryption.

## 8. Extracting the constants

```bash
readelf -SW triple-gate
objdump -s -j .rodata triple-gate
```

`.rodata` has virtual address `0x2000`, file offset `0x2000`, and size `0x80`. For addresses inside it:

```text
file offset = section file offset + (address - section virtual address)
```

The resulting offsets equal the static addresses in this sample. This is not true for every ELF.

| Address / offset | Size | Purpose | Bytes |
|---|---:|---|---|
| `0x2048` | 4 | Gate 2 target | `e7 10 4b 44` |
| `0x204c` | 4 | Gate 1 target | `35 77 c3 7c` |
| `0x2050` | 4 | Gate 1 key | `58 2e ae 05` |
| `0x2060` | 16 | First encrypted-flag block | `3d1a3902180736291c485812005e381d` |
| `0x2070` | 16 | Second encrypted-flag block | `1d261c0133344c72532e595b6d551c50` |

Gate 3's constants are immediate instruction operands, rather than entries in these tables.

## 9. Complete script 1: recover and decrypt

Save as `solve_triple_gate.py`. This Python 3.8+ script uses only the standard library, extracts tables from the binary, solves all three gates, verifies the recovered password against a reconstructed model, and decrypts the flag without executing the ELF. Offsets and instruction constants are specific to this sample.

```python
#!/usr/bin/env python3
"""Recover Triple Gate's password and flag using the standard library."""
import argparse
from pathlib import Path

MASK = 0xFFFFFFFF
PRIME = 0x01000193
SEED = 0x7578D2CD
TARGET = 0xF6109D6C
PRINTABLE = range(32, 127)


def gate3(segment):
    a, b, c = segment
    h1 = ((a ^ SEED) * PRIME) & MASK
    h2 = ((h1 ^ b) * PRIME) & MASK
    return h2 ^ c


def solve_last():
    matches = []
    for a in PRINTABLE:
        h1 = ((a ^ SEED) * PRIME) & MASK
        for b in PRINTABLE:
            h2 = ((h1 ^ b) * PRIME) & MASK
            c = h2 ^ TARGET
            if c in PRINTABLE:
                segment = bytes((a, b, c))
                if gate3(segment) != TARGET:
                    raise RuntimeError("Candidate verification failed")
                matches.append(segment)
    return matches


def check(password, t1, k1, t2):
    if len(password) != 13 or password[4] != 45 or password[9] != 45:
        return False
    if any((password[i] ^ k1[i]) != t1[i] for i in range(4)):
        return False
    if any(((9 * password[5+i] + i) & 255) != t2[i] for i in range(4)):
        return False
    return gate3(password[10:13]) == TARGET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 0x2080:
        raise SystemExit("Expected the supplied 64-bit little-endian ELF")
    t2 = data[0x2048:0x204C]
    t1 = data[0x204C:0x2050]
    k1 = data[0x2050:0x2054]
    first = bytes(t ^ k for t, k in zip(t1, k1))
    inverse9 = pow(9, -1, 256)
    second = bytes(((t-i) * inverse9) & 255 for i, t in enumerate(t2))
    matches = solve_last()
    print("Gate 1:", first.decode("ascii"))
    print("Gate 2:", second.decode("ascii"))
    print("Gate 3 printable matches:", matches)
    if len(matches) != 1:
        raise SystemExit("Expected one printable final-segment match")
    password = first + b"-" + second + b"-" + matches[0]
    if b"\x00" in password or not check(password, t1, k1, t2):
        raise SystemExit("Password failed the reconstructed checks")
    print("Password:", password.decode("ascii"))
    print("Gate verification: all three checks pass")
    encrypted = bytearray(31)
    encrypted[0:16] = data[0x2060:0x2070]
    encrypted[15:31] = data[0x2070:0x2080]
    flag = bytes(x ^ password[i % 13] for i, x in enumerate(encrypted))
    print("Flag:", flag.decode("ascii"))


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_triple_gate.py ./triple-gate
```

Output:

```text
Gate 1: mYmy
Gate 2: oWAy
Gate 3 printable matches: [b'6Mh']
Password: mYmy-oWAy-6Mh
Gate verification: all three checks pass
Flag: PCT{5haheen_h3ap_1ndu5_ec1648e}
```

**Next step:** verify that the unmodified binary accepts this password and prints the same flag. This independently checks our reconstruction.

## 10. Complete script 2: verify with the executable

Save as `verify_triple_gate.py`. Running through the ELF's dynamic loader avoids changing the uploaded file's executable permission. This step requires a compatible x86-64 Linux environment; static recovery above does not.

```python
#!/usr/bin/env python3
"""Verify a password and optionally compare the printed flag."""
import argparse
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("password")
    parser.add_argument("--expected-flag")
    parser.add_argument("--loader", type=Path,
                        default=Path("/lib64/ld-linux-x86-64.so.2"))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    loader = args.loader.resolve(strict=True)
    result = subprocess.run(
        [str(loader), str(binary), args.password],
        capture_output=True, text=True, timeout=5, check=False,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    prefix = "Correct! flag: "
    flags = [line[len(prefix):] for line in result.stdout.splitlines()
             if line.startswith(prefix)]
    if result.returncode != 0 or len(flags) != 1:
        raise SystemExit(f"Verification failed (exit code {result.returncode})")
    flag = flags[0]
    if not (flag.startswith("PCT{") and flag.endswith("}")):
        raise SystemExit("Unexpected flag format")
    if args.expected_flag is not None and flag != args.expected_flag:
        raise SystemExit("Printed flag differs from the expected value")
    print("Verified: the binary accepts the password and prints the flag.")


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 verify_triple_gate.py ./triple-gate 'mYmy-oWAy-6Mh' \
  --expected-flag 'PCT{5haheen_h3ap_1ndu5_ec1648e}'
```

The direct equivalent is:

```bash
/lib64/ld-linux-x86-64.so.2 ./triple-gate 'mYmy-oWAy-6Mh'
```

The original binary prints:

```text
   [TRIPLE GATE]  v1.0
Correct! flag: PCT{5haheen_h3ap_1ndu5_ec1648e}
```

Its exit status is `0`. The printed flag matches the independently decrypted value.

## 11. Common mistakes

| Mistake | Why it fails | Correction |
|---|---|---|
| Submitting the password | The requested flag is decoded output | Submit the `PCT{...}` value |
| Searching the entire password | Ignores independent gates | Solve each segment separately |
| Losing case | Changes validation and decryption | Preserve the exact password |
| Dividing gate 2 normally | Ignores byte wraparound | Multiply by 57 modulo 256 |
| Using global indices in gate 2 | The second loop resets its counter | Use local indices 0–3 |
| Adding a final multiplication in gate 3 | Does not match the disassembly | Stop after the third-byte XOR |
| Omitting 32-bit masks | Python integers do not wrap | Mask both multiplications |
| Truncating the derived third byte | Discards mismatching upper bits | Check its full value |
| Reading contiguous encrypted bytes | Misses the overlapping stores | Rebuild the buffer at offsets 0 and 15 |
| Omitting hyphens from the key | Changes key bytes and period | Use the entire 13-byte password |

## 12. What the challenge teaches

Each gate needs a precise model of its operations and integer width. Recognizing XOR, modular multiplication, and the final three-byte equation makes recovery small and deterministic except for a short pair search.

The output routine is also part of the puzzle: the password doubles as a decryption key, and overlapping memory writes determine the ciphertext layout. Recovering the password, reproducing those writes, and checking the original executable completes the chain of evidence.

**Password:** `mYmy-oWAy-6Mh`  
**Flag:** `PCT{5haheen_h3ap_1ndu5_ec1648e}`
