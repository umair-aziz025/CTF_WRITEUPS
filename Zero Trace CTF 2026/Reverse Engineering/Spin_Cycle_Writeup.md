# Spin Cycle — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 160 points  
**Provided file:** `spin-cycle`  
**Flag format:** `PCT{...}`

> Gears inside gears. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and overall approach

```text
PCT{sh4d0w_watchtow3r_radar_9c72f}
```

The checker XORs each byte with a repeating three-byte key, then rotates the result left by a position-dependent count. Recovery rotates right first and then repeats the XOR.

The investigation proceeds from the input-length check to the transformation loop, then to extracting constants, deriving the inverse, reconstructing the forward check, and running the recovered input through the unmodified binary.

## 2. Inspect the executable and locate validation

Run the following commands with the downloaded binary in the current directory:

```bash
file spin-cycle
sha256sum spin-cycle
strings -a spin-cycle
objdump -d -M intel spin-cycle
readelf -SW spin-cycle
objdump -s -j .rodata spin-cycle
```

The supplied file is a stripped, dynamically linked, little-endian x86-64 PIE ELF. Its interpreter is `/lib64/ld-linux-x86-64.so.2`. The SHA-256 fingerprint below identifies the exact analyzed file; it is not part of the flag algorithm:

```text
1921b369b78312c2112015363510f3ad524823c8d11ed5d3ea1bb6aeedb06da1
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

## 3. Identify the two repeating schedules

The checker loads a key pointer and a target pointer:

```asm
11d9: lea r9,[rip+0xe80]    ; key at 0x2060
11e0: mov edi,0xaaaaaaab
11e5: lea r8,[rip+0xe94]    ; target at 0x2080
```

The input index is held in `rdx`. The first arithmetic sequence calculates division by three using multiplication and a shift:

```asm
1206: imul rax,rdi
120e: shr  rax,0x21
1212: lea  esi,[rax+rax*2]
1215: mov  eax,edx
1217: sub  eax,esi
121b: movzx esi,BYTE PTR [r9+rax]
1222: xor  sil,BYTE PTR [rbx+rdx]
```

For the indices used here, multiplying by `0xAAAAAAAB` and shifting by 33 produces `floor(i/3)`. Subtracting three times that quotient gives `i % 3`. The key access therefore means:

```python
mixed = input[i] ^ key[i % 3]
```

A second sequence uses `0x24924925` and corrective shifts to compute division by seven. In equivalent arithmetic for this loop:

```text
q0 = (i * 0x24924925) >> 32
q7 = (((i - q0) >> 1) + q0) >> 2
rotation = i - 7*q7 + 1 = (i % 7) + 1
```

The final instructions are:

```asm
1238: lea ecx,[rax+rdx+0x1]
123c: rol sil,cl
123f: cmp sil,BYTE PTR [r8+rdx]
1243: je  11f0
```

`rol sil, cl` rotates an **eight-bit** value left. It is not a left shift: bits leaving the high end wrap back into the low end.

The complete forward equation is:

```text
target[i] = ROL8(input[i] XOR key[i % 3], (i % 7) + 1)
```

| Schedule | Values | Period |
|---|---|---:|
| Key index | 0, 1, 2, 0, 1, 2, ... | 3 |
| Rotation count | 1, 2, 3, 4, 5, 6, 7, 1, ... | 7 |

The combined schedule repeats every 21 positions. This explains the “gears inside gears” hint, but the actual flag bytes remain independent: no state from an earlier input byte is fed into the next check.

**Next step:** extract the short key and target array, then reverse rotation before XOR.

## 4. Extract the constants

`.rodata` starts at virtual address `0x2000`, file offset `0x2000`, and has size `0xa2`. An address inside this section maps using:

```text
file offset = section file offset + (address - section virtual address)
```

Here the relevant addresses and file offsets happen to be equal. Do not assume that for other ELF layouts.

| File offset | Length | Purpose |
|---|---:|---|
| `0x2060` | 3 bytes | Repeating XOR key |
| `0x2080` | 34 bytes | Expected transformed bytes |

Key:

```text
59 26 51
```

Target:

```text
12952822aa4eb684857197c40e2964c492e3c545910c5181d3e8c8033ec87341e609
```

These are raw bytes. The key is the three byte values `0x59`, `0x26`, `0x51`, not the ASCII characters of the text `592651`.

## 5. Reverse the transformation

Undo the operations in reverse order:

1. Rotate the target byte right by `(i % 7) + 1`.
2. XOR the result with `key[i % 3]`.

```text
input[i] = ROR8(target[i], (i % 7) + 1) XOR key[i % 3]
```

For an eight-bit value and count `r` from 1 through 7:

```python
ror8 = ((value >> r) | (value << (8-r))) & 0xFF
```

The mask removes bits beyond the byte width. XOR is self-inverse, and right rotation undoes left rotation, so every target byte determines exactly one input byte.

### Worked example: recover the prefix

| i | Target | Rotate right by | Result | XOR key | Plaintext |
|---:|---|---:|---|---|---|
| 0 | `0x12` | 1 | `0x09` | `0x59` | `0x50`, `P` |
| 1 | `0x95` | 2 | `0x65` | `0x26` | `0x43`, `C` |
| 2 | `0x28` | 3 | `0x05` | `0x51` | `0x54`, `T` |
| 3 | `0x22` | 4 | `0x22` | `0x59` | `0x7b`, `{` |

For the first byte, `P XOR 0x59 = 0x09`; rotating `0x09` left once produces the stored `0x12`.

**Why this approach:** rotation and XOR are bijections on bytes. Brute force would work but is unnecessary; the inverse formula recovers all 34 bytes in a single pass.

**Next step:** implement the inverse, then run the result through the forward equation and original executable.

## 6. Complete solver script

Save this entire block as `solve_spin_cycle.py`. It uses only Python's standard library. The offsets are specific to the supplied sample, as established above. Static recovery does not execute the ELF.

```python
#!/usr/bin/env python3
"""Recover Spin Cycle's flag and verify its forward transformation."""
import argparse
from pathlib import Path

def rol8(value, count):
    count %= 8
    return ((value << count) | (value >> ((8-count) % 8))) & 255

def ror8(value, count):
    count %= 8
    return ((value >> count) | (value << ((8-count) % 8))) & 255

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 0x20A2:
        raise SystemExit("Expected the supplied 64-bit little-endian ELF")
    key = data[0x2060:0x2063]
    target = data[0x2080:0x20A2]
    flag = bytes(ror8(value, i % 7 + 1) ^ key[i % 3]
                 for i, value in enumerate(target))
    rebuilt = bytes(rol8(value ^ key[i % 3], i % 7 + 1)
                    for i, value in enumerate(flag))
    if len(flag) != 34 or b"\x00" in flag or rebuilt != target:
        raise SystemExit("Forward-model or length verification failed")
    print("Key:", key.hex())
    print("Target:", target.hex())
    print("Recovered length:", len(flag))
    print("Forward-model verification: all 34 bytes match")
    print("Flag:", flag.decode("ascii"))

if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_spin_cycle.py ./spin-cycle
```

Tested output:

```text
Key: 592651
Target: 12952822aa4eb684857197c40e2964c492e3c545910c5181d3e8c8033ec87341e609
Recovered length: 34
Forward-model verification: all 34 bytes match
Flag: PCT{sh4d0w_watchtow3r_radar_9c72f}
```

The script re-encodes the recovered input and compares all 34 bytes against the extracted target. This checks the inverse and byte-width handling; the original executable provides a separate end-to-end check.

## 7. Complete executable-verification script

Save as `verify_spin_cycle.py`. It invokes the ELF through its Linux dynamic loader, avoiding a change to the uploaded file's executable permission. This step requires compatible x86-64 Linux libraries.

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
python3 verify_spin_cycle.py ./spin-cycle 'PCT{sh4d0w_watchtow3r_radar_9c72f}'
```

Tested output:

```text
   [SPIN CYCLE]  v1.0
Correct! PCT{sh4d0w_watchtow3r_radar_9c72f}
Verified: the original executable accepts this input.
```

The executable returned exit status `0`. The equivalent direct command is:

```bash
/lib64/ld-linux-x86-64.so.2 ./spin-cycle 'PCT{sh4d0w_watchtow3r_radar_9c72f}'
```

## 8. Common mistakes

| Mistake | Why it fails | Correction |
|---|---|---|
| Treating rotation as a shift | Loses bits that must wrap around | Use an eight-bit rotate |
| XORing before undoing rotation | Reverses the operations in the wrong order | Rotate right, then XOR |
| Rotating 32 bits instead of eight | Models a different instruction | `sil` is an eight-bit register |
| Using rotation counts 0–6 | Misses the final `+1` | Use `(i % 7) + 1` |
| Treating compiler division constants as keys | Confuses index calculations with data | Recognize `% 3` and `% 7` |
| Restarting both schedules together | They have different periods | Index the key and rotation independently |
| Parsing `592651` as six ASCII characters | Changes the key | Extract three raw bytes |

## 9. Why the solution works

The apparent complexity comes from two small repeating schedules and compiler-generated division code. Once reduced to XOR followed by an eight-bit rotation, the check is a straightforward bijection at every position. The short key and complete target array are available in the executable, so all 34 bytes follow from direct inversion.

**Final flag:**

```text
PCT{sh4d0w_watchtow3r_radar_9c72f}
```
