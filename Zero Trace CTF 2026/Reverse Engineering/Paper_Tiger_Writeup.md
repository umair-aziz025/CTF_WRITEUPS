# Paper Tiger — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 80 points  
**Provided file:** `paper-tiger`  
**Flag format:** `PCT{...}`

> Looks like noise until you flip it. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and overall approach

```text
PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}
```

The checker reverses the bits in each byte, XORs a position-dependent mask, and complements the result. Recovery undoes complement, XOR, and bit reversal in reverse order.

The investigation proceeds from the input-length check to the transformation loop, then to extracting constants, deriving the inverse, reconstructing the forward check, and running the recovered input through the unmodified binary.

## 2. Inspect the executable and locate validation

Run the following commands with the downloaded binary in the current directory:

```bash
file paper-tiger
sha256sum paper-tiger
strings -a paper-tiger
objdump -d -M intel paper-tiger
readelf -SW paper-tiger
objdump -s -j .rodata paper-tiger
```

The supplied file is a stripped, dynamically linked, little-endian x86-64 PIE ELF. Its interpreter is `/lib64/ld-linux-x86-64.so.2`. The SHA-256 fingerprint below identifies the exact analyzed file; it is not part of the flag algorithm:

```text
ba86e261fe72a30f0b15b24307a0920d9f55f5d7b5405715fc3979a0085798cd
```

Even though normal function names are stripped, imported calls such as `strlen`, `snprintf`, `fgets`, and `strcspn` reveal the input path. Startup code identifies the main routine at static address `0x1140`. All addresses here are static disassembly addresses; PIE permits a different runtime load base.

The program copies `argv[1]` with `snprintf`, or reads a line with `fgets` and removes its line ending using `strcspn`. Both routes reach:

```asm
1197: mov  rdi,rbx
119a: call strlen@plt
119f: cmp  rax,0x22
11a3: je   11d7
```

The required length is `0x22 = 34` bytes. A different length reaches the failure message. `strlen` counts bytes before the first NUL; the recovered ASCII flag has 34 characters and 34 bytes.

**Why this step:** it establishes the input size and leads directly to the transformation loop. Strings and the challenge hint are clues, but the machine code determines the actual operation.

**Next step:** follow the successful branch and translate its arithmetic into a byte-level equation.

## 3. Recognize the eight-bit reversal loop

The checker sets the position-dependent mask to zero and loads the target pointer:

```asm
11d7: xor r8d,r8d
11da: xor edi,edi
11dc: lea r9,[rip+0xe7d]       ; target at 0x2060
```

For each input byte it performs eight iterations:

```asm
11e8: movzx ecx,BYTE PTR [rbx+rdi]
11ec: mov   edx,0x8
11f1: xor   eax,eax
11f8: mov   esi,ecx
11fa: add   eax,eax
11fc: shr   cl,1
11fe: and   esi,0x1
1201: or    eax,esi
1203: sub   edx,0x1
1206: jne   11f8
```

Each iteration takes the source's least significant bit, shifts the accumulating result left, and appends that bit. After eight iterations, bit order is reversed:

```text
b7 b6 b5 b4 b3 b2 b1 b0 -> b0 b1 b2 b3 b4 b5 b6 b7
```

This reverses bits **inside each byte**. It does not reverse the order of characters in the string, rotate the byte, or simply complement its bits.

For example:

```text
P = 0x50 = 01010000
reverse8(P) = 00001010 = 0x0a
```

**Next step:** inspect the instructions after bit reversal. They add two more transformations before the comparison.

## 4. Recover the mask and complement operation

```asm
1208: xor eax,r8d
120b: not eax
120d: cmp al,BYTE PTR [r9+rdi]
1211: jne 11a5
1213: add rdi,0x1
1217: sub r8d,0x32
121b: cmp rdi,0x22
121f: jne 11e8
```

The mask starts at zero and decreases by `0x32 = 50` after each byte. The register is 32 bits, but the comparison uses only `al`. Therefore only the low eight bits of the mask matter:

```python
mask = (-50 * i) & 0xFF
```

The first mask bytes are:

```text
00 ce 9c 6a 38 06 d4 a2 ...
```

The update happens after the comparison, so the first byte uses zero, not `0xce`.

The complete forward transformation is:

```text
target[i] = NOT8(reverse8(input[i]) XOR ((-50*i) mod 256))
```

In Python:

```python
target_byte = (~(reverse8(value) ^ ((-50*i) & 255))) & 255
```

Python's `~` does not automatically produce an eight-bit result; the final mask is essential. Equivalently, complement a byte by XORing it with `0xff`.

The arithmetic mask depends on the position, not previous plaintext. Each input byte can therefore be recovered independently.

**Next step:** extract the 34 stored target bytes, then reverse the three operations in order.

## 5. Extract and invert the target

`.rodata` begins at virtual address `0x2000`, file offset `0x2000`, and has size `0x82`. Map addresses using:

```text
file offset = section file offset + (address - section virtual address)
```

The target address `0x2060` maps to file offset `0x2060`. Read 34 bytes through exclusive offset `0x2082`:

```python
target = data[0x2060:0x2082]
```

Target:

```text
f5f3494b092f0713a96f0989db6fcdc129ab0d1b2b37a75155a78fc3b18f178ba3cf
```

Reverse the forward operations in this order:

1. Undo NOT by complementing the target byte.
2. Undo XOR with the same position mask.
3. Undo bit reversal by reversing the eight bits again.

```text
input[i] = reverse8((target[i] XOR 0xff) XOR ((-50*i) mod 256))
```

Bit reversal is self-inverse, just like XOR with a fixed mask and bytewise complement. Composing their inverses gives one unique input byte for every target.

### Worked example: recover `PCT{`

| i | Target | Undo NOT | Mask | Undo XOR | Reverse bits | Character |
|---:|---|---|---|---|---|---|
| 0 | `f5` | `0a` | `00` | `0a` | `50` | `P` |
| 1 | `f3` | `0c` | `ce` | `c2` | `43` | `C` |
| 2 | `49` | `b6` | `9c` | `2a` | `54` | `T` |
| 3 | `4b` | `b4` | `6a` | `de` | `7b` | `{` |

At index 1, for example, reversing `C` gives `0xc2`. XORing with `0xce` gives `0x0c`; complementing gives `0xf3`, exactly the stored target.

**Why this approach:** each operation is reversible and the position mask is known. No key search, dictionary attack, or flag guessing is required.

**Next step:** implement these byte operations and verify the full result, not just the familiar prefix.

## 6. Complete solver script

Save this entire block as `solve_paper_tiger.py`. It uses only Python's standard library. The offsets are specific to the supplied sample, as established above. Static recovery does not execute the ELF.

```python
#!/usr/bin/env python3
"""Recover Paper Tiger's flag and verify its forward transformation."""
import argparse
from pathlib import Path

def reverse8(value):
    result = 0
    for _ in range(8):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 0x2082:
        raise SystemExit("Expected the supplied 64-bit little-endian ELF")
    target = data[0x2060:0x2082]
    flag = bytes(reverse8((value ^ 255) ^ ((-50*i) & 255))
                 for i, value in enumerate(target))
    rebuilt = bytes((~(reverse8(value) ^ ((-50*i) & 255))) & 255
                    for i, value in enumerate(flag))
    if len(flag) != 34 or b"\x00" in flag or rebuilt != target:
        raise SystemExit("Forward-model or length verification failed")
    print("Target:", target.hex())
    print("Recovered length:", len(flag))
    print("Forward-model verification: all 34 bytes match")
    print("Flag:", flag.decode("ascii"))

if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_paper_tiger.py ./paper-tiger
```

Tested output:

```text
Target: f5f3494b092f0713a96f0989db6fcdc129ab0d1b2b37a75155a78fc3b18f178ba3cf
Recovered length: 34
Forward-model verification: all 34 bytes match
Flag: PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}
```

The script re-encodes the recovered input and compares all 34 bytes against the extracted target. This checks the inverse and byte-width handling; the original executable provides a separate end-to-end check.

## 7. Complete executable-verification script

Save as `verify_paper_tiger.py`. It invokes the ELF through its Linux dynamic loader, avoiding a change to the uploaded file's executable permission. This step requires compatible x86-64 Linux libraries.

```python
#!/usr/bin/env python3
"""Verify a recovered input against the original executable."""
import argparse
import subprocess
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("candidate")
    parser.add_argument("--loader", type=Path,
                        default=Path("/lib64/ld-linux-x86-64.so.2"))
    args = parser.parse_args()
    result = subprocess.run(
        [str(args.loader.resolve(strict=True)),
         str(args.binary.resolve(strict=True)), args.candidate],
        capture_output=True, text=True, timeout=5, check=False,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    if result.returncode != 0 or (
        f"Correct! {args.candidate}" not in result.stdout.splitlines()
    ):
        raise SystemExit("The original binary did not accept the candidate")
    print("Verified: the original executable accepts this input.")

if __name__ == "__main__":
    main()
```

Run:

```bash
python3 verify_paper_tiger.py ./paper-tiger 'PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}'
```

Tested output:

```text
   [PAPER TIGER]  v1.0
Correct! PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}
Verified: the original executable accepts this input.
```

The executable returned exit status `0`. The equivalent direct command is:

```bash
/lib64/ld-linux-x86-64.so.2 ./paper-tiger 'PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}'
```

## 8. Common mistakes

| Mistake | Why it fails | Correction |
|---|---|---|
| Reversing the string | The loop reverses bits within each byte | Keep character positions unchanged |
| Treating bit reversal as NOT | The two operations are different | Reverse positions, then model complement separately |
| Using `50*i` instead of `-50*i` | Misses the subtraction in the mask update | Use `(-50*i) & 255` |
| Using `0xce` for the first mask | Updates the mask too early | The first mask is zero |
| Forgetting byte masking after NOT | Python produces an unbounded signed integer | Use `& 255` or XOR with `255` |
| Dropping leading zeros when reversing bits | Changes bit positions | Reverse exactly eight bits |
| Undoing bit reversal first | Applies the wrong inverse order | Undo NOT, then XOR, then reversal |

## 9. Why the solution works

The hint refers to bit manipulation, but precise recovery requires distinguishing reversal, XOR, and complement. The loop reveals all three operations and the changing mask. Each is invertible on an eight-bit value, so their composition has a direct inverse. Forward verification and actual execution confirm the result across the entire flag.

**Final flag:**

```text
PCT{sk4rdu_51gn4l_qu3t74_b9acd3a9}
```
