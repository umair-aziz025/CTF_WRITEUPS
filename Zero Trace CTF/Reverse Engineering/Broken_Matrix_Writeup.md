# Broken Matrix — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 274 points  
**Provided file:** `broken-matrix`  
**Flag format:** `PCT{...}`

> A dead pixel hides a byte. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and approach

The accepted input is:

```text
PCT{574ck_5kardu_5hahe3n_m3hran_26e}
```

The program requires a 36-byte input and treats it as a 6×6 grid stored row by row. It modifies one byte, reads the grid down its columns in a specified order, XORs the resulting stream with a repeating five-byte key, and compares the output against 36 stored bytes.

All these operations are reversible. The solution is to extract the constants, undo the repeating XOR, put each byte back into its original grid position, and undo the single-byte modification.

The investigation follows this sequence:

1. Inspect the file and strings to identify the executable and its clues.
2. Find the input length check and final comparison.
3. Trace how the program builds the comparison buffer.
4. Extract the column order, XOR key, and target bytes.
5. Reverse the transformation in the correct order.
6. Reapply the forward transformation and verify the flag with the original binary.

Unlike Brute Bastion and Chunk Norris, this challenge does not require recovering small hash preimages. The checker here uses a reversible transformation and `memcmp`.

## 2. Initial inspection: turn the hint into a testable hypothesis

The commands assume `broken-matrix` is in the current directory. Static inspection uses common Linux tools; the recovery script uses only the Python standard library.

```bash
file broken-matrix
sha256sum broken-matrix
strings -a broken-matrix
```

The supplied sample is a stripped, dynamically linked, little-endian x86-64 PIE ELF. Its interpreter is:

```text
/lib64/ld-linux-x86-64.so.2
```

SHA-256:

```text
54033dbbb956f37005309fa48638978406d33f5aed0efae56adaad153be6b431
```

Relevant strings include:

```text
   [BROKEN MATRIX]  v1.0
   a 6x6 memory grid was found after the glitch.
   encrypted flag: 655f520e395b285014f55834040d535b0a4e1d39400e5b50325e0f5b5554005e6c551450
   hint: the columns are scrambled, one cell is corrupted.
Nope. Access denied.
Correct! %s
5k3ff
```

Important imports include `strlen`, `snprintf`, `fgets`, `strcspn`, and `memcmp`.

These observations suggest a matrix-based transformation, but they do not yet tell us its exact order. The isolated text `5k3ff` might be a key; that must be confirmed by checking how the program uses it. Likewise, “one cell is corrupted” does not tell us the location or correction value.

**Why this step matters:** strings provide useful landmarks without requiring us to understand every instruction. The next task is to connect those landmarks to the executable's actual acceptance logic.

## 3. Locate input handling and the final comparison

```bash
objdump -d -M intel broken-matrix
```

Although the binary is stripped, startup code passes address `0x1160` to `__libc_start_main` as the main routine. Addresses below are static addresses from the disassembly; PIE means the runtime base can vary.

The program accepts either `argv[1]` or a line from standard input. Command-line input is copied using `snprintf`; standard input is read using `fgets` and has its line ending removed using `strcspn`.

Both paths reach this check:

```asm
11df: mov    rdi,rbx
11e2: call   strlen@plt
11e7: cmp    rax,0x24
11eb: je     1223
```

`0x24` is 36, matching the number of cells in a 6×6 grid. The length is measured in bytes before the first NUL; for the recovered ASCII flag, this is also its character count.

The final comparison is:

```asm
12af: mov    edx,0x24
12b4: lea    rsi,[rip+0xe85]    ; target at 0x2140
12bb: mov    rdi,r11           ; transformed input buffer
12be: call   memcmp@plt
12c3: mov    ebp,eax
12c5: test   eax,eax
12c7: jne    11ed              ; failure
```

On x86-64 System V, the first three arguments are passed in `rdi`, `rsi`, and `rdx`. Therefore this is equivalent to:

```c
memcmp(transformed_input, target, 36)
```

A zero result leads to success.

**Next step:** trace the instructions that populate `transformed_input`. This is more useful than attempting to guess the flag from the printed ciphertext.

## 4. Identify the working buffers and the corrupted cell

After the length check, the program copies the input to a temporary buffer:

```asm
1223: mov    r10,rsp
1226: mov    ecx,0x9
122b: lea    r11,[rsp+0x30]
1230: mov    rsi,rbx
1233: mov    rdi,r10
1236: mov    r8,r11
1246: rep movs DWORD PTR es:[rdi],DWORD PTR ds:[rsi]
```

Nine doublewords means `9 × 4 = 36` bytes are copied. The relevant buffers are:

| Location | Meaning |
|---|---|
| `rsp` / `r10` | Temporary row-major grid |
| `rsp + 0x30` / `r11` | Transformed output |
| `rsp + 0x60` / `rbx` | Original input |

Then one instruction implements the “dead pixel”:

```asm
1251: xor BYTE PTR [rsp+0x13],0xf2
```

Since the grid starts at `rsp`, this modifies zero-based byte index `0x13 = 19`:

```python
grid[19] ^= 0xF2
```

For a row-major grid of width six:

```text
row = 19 // 6 = 3
column = 19 % 6 = 1
```

The affected cell is therefore **row 3, column 1 with zero-based indexing**, or **the fourth row, second column** in ordinary counting.

This is a deterministic XOR applied to a copy of the input. The original input buffer remains available for the success message. There is no need to guess a damaged byte: both its position and the XOR mask are present in the code.

**Next step:** determine where that grid cell goes in the output and how the other bytes are transformed.

## 5. Recover the column traversal and repeating XOR

The checker loads two pointers:

```asm
1239: lea    r12,[rip+0xee0]    ; 0x2120: column order
1240: mov    r9d,0xcccccccd
1248: lea    rbp,[rip+0xed7]    ; 0x2126: XOR key
```

The outer loop picks a column from the first table:

```asm
1260: movzx  esi,BYTE PTR [r12]
1265: xor    ecx,ecx
1267: add    rsi,r10
```

`rsi` now points to the chosen column in the first row. The inner loop advances by six bytes each time:

```asm
1273: add    rsi,0x6
...
128e: xor    al,BYTE PTR [rsi-0x6]
```

The subtraction in the memory operand accounts for the pointer being advanced before the read. It reads row 0 first, then row 1, and so on; it does not skip the first row.

After six iterations, the outer loop advances to the next table entry and the next six-byte output block:

```asm
1299: cmp    rcx,0x6
129d: jne    1270
129f: add    edi,0x6
12a2: add    r12,0x1
12a6: add    r8,0x6
12aa: cmp    edi,0x24
12ad: jne    1260
```

### 5.1 Decode the apparent “magic number”

The instructions between the grid read setup and the XOR calculate the key index:

```asm
1270: lea    edx,[rdi+rcx]
1277: mov    rax,rdx
127a: imul   rdx,r9
127e: shr    rdx,0x22
1282: lea    edx,[rdx+rdx*4]
1285: sub    eax,edx
1287: cdqe
1289: movzx  eax,BYTE PTR [rbp+rax]
```

Here, `rdi` is the beginning of the current six-byte output block, and `rcx` is the row index. Let:

```text
i = rdi + rcx
```

For this loop's nonnegative indices, multiplying by `0xCCCCCCCD` and shifting right by 34 computes division by five. The subsequent instructions multiply the quotient by five and subtract it from the original index:

```text
q = floor(i / 5)
key_index = i - 5*q = i % 5
```

Thus, `0xCCCCCCCD` is part of the compiler's division optimization. It is not an additional encryption key.

The key repeats continuously across the entire 36-byte output. It does **not** restart at each column.

### 5.2 Express the complete forward transformation

Let `P` be the column order, `K` the five-byte key, and `G` the copied input after modifying byte 19. With `c` as the traversal-slot index and `r` as the row:

```text
i = 6*c + r
output[i] = G[6*r + P[c]] XOR K[i % 5]
```

The reconstructed checker is:

```python
def transform(candidate, column_order, key):
    grid = bytearray(candidate)
    grid[19] ^= 0xF2
    output = bytearray(36)
    for c, column in enumerate(column_order):
        for row in range(6):
            i = 6 * c + row
            output[i] = grid[6 * row + column] ^ key[i % 5]
    return bytes(output)
```

**Next step:** extract the three data regions referenced by this code and reverse the equation.

## 6. Extract the constants from the ELF

```bash
readelf -SW broken-matrix
objdump -s -j .rodata broken-matrix
```

The `.rodata` section starts at virtual address `0x2000`, file offset `0x2000`, and has size `0x164`.

For a referenced address inside this section:

```text
file offset = section file offset + (address - section virtual address)
```

Virtual addresses and file offsets happen to match for these constants in this sample. That is a verified property of this layout, not a general ELF rule.

| Static address / file offset | Size | Meaning | Value |
|---|---:|---|---|
| `0x2120` | 6 bytes | Column order | `00 01 05 03 02 04` |
| `0x2126` | 5 bytes | Repeating XOR key | `35 6b 33 66 66`, ASCII `5k3ff` |
| `0x2140` | 36 bytes | Comparison target | Ciphertext below |

```text
655f520e395b285014f55834040d535b0a4e1d39400e5b50325e0f5b5554005e6c551450
```

The raw target matches the hexadecimal text printed in the banner. The checker uses the raw bytes at `0x2140`, rather than parsing the printed hexadecimal string.

The column mapping is:

| Output indices | Original grid column, zero-based |
|---|---:|
| 0–5 | 0 |
| 6–11 | 1 |
| 12–17 | 5 |
| 18–23 | 3 |
| 24–29 | 2 |
| 30–35 | 4 |

Each output block lists that column's cells from top to bottom.

## 7. Reverse the transformation in the right order

The forward order is:

1. Copy input into the grid.
2. XOR grid byte 19 with `0xF2`.
3. Read the columns in order `[0, 1, 5, 3, 2, 4]`.
4. XOR the output stream with repeating key `5k3ff`.

The inverse runs those operations backward. XOR is self-inverse:

```text
(x XOR k) XOR k = x
```

For every ciphertext byte, undo the key XOR and write it directly to its original grid location:

```python
grid[6 * row + column_order[c]] = target[6 * c + row] ^ key[(6 * c + row) % 5]
```

This assignment performs both the XOR reversal and the inverse placement. After all 36 bytes are placed, undo the corrupted-cell operation:

```python
grid[19] ^= 0xF2
```

Before the repair, the reconstructed bytes are:

```text
PCT{574ck_5kardu_5h\x93he3n_m3hran_26e}
```

Here `\x93` denotes one non-ASCII byte, not four literal characters. At index 19:

```text
0x93 XOR 0xF2 = 0x61 = 'a'
```

### 7.1 Trace the corrupted cell end to end

Grid index 19 is row 3, column 1. Column 1 is visited in traversal slot 1, so the corresponding output index is:

```text
i = 6*1 + 3 = 9
```

At output index 9, the key index is `9 % 5 = 4`, giving key byte `0x66`. The ciphertext byte is `0xF5`:

```text
Undo stream XOR: 0xF5 XOR 0x66 = 0x93
Undo cell XOR:   0x93 XOR 0xF2 = 0x61 ('a')
```

This connects the hint to a specific instruction, grid coordinate, output position, and recovered character.

### 7.2 The recovered 6×6 grid

| Row | Column 0 | Column 1 | Column 2 | Column 3 | Column 4 | Column 5 |
|---:|---|---|---|---|---|---|
| 0 | P | C | T | { | 5 | 7 |
| 1 | 4 | c | k | _ | 5 | k |
| 2 | a | r | d | u | _ | 5 |
| 3 | h | a | h | e | 3 | n |
| 4 | _ | m | 3 | h | r | a |
| 5 | n | _ | 2 | 6 | e | } |

Reading this grid row by row gives the flag. No character guessing, language-based correction, or brute force is needed: the column table is a permutation and every operation is invertible.

## 8. Complete script 1: extract, reverse, and check the model

Save this entire block as `solve_broken_matrix.py`. It extracts constants directly from the supplied sample, reverses the checker, and re-encodes the result to verify that all 36 target bytes match. The offsets and corruption instruction are specific to the analyzed binary.

```python
#!/usr/bin/env python3
"""Recover Broken Matrix's flag using Python's standard library."""

import argparse
from pathlib import Path

SIZE = 6
LENGTH = SIZE * SIZE
PERM_OFFSET = 0x2120
KEY_OFFSET = 0x2126
KEY_LENGTH = 5
TARGET_OFFSET = 0x2140
CORRUPT_INDEX = 19
CORRUPT_MASK = 0xF2


def extract_constants(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a 64-bit little-endian ELF")
    if len(data) < TARGET_OFFSET + LENGTH:
        raise ValueError("File is too short for the expected target table")
    order = data[PERM_OFFSET:PERM_OFFSET + SIZE]
    key = data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
    target = data[TARGET_OFFSET:TARGET_OFFSET + LENGTH]
    if sorted(order) != list(range(SIZE)):
        raise ValueError("Column table is not a permutation of 0 through 5")
    return order, key, target


def encode(candidate, order, key):
    if len(candidate) != LENGTH:
        raise ValueError("Candidate must contain exactly 36 bytes")
    grid = bytearray(candidate)
    grid[CORRUPT_INDEX] ^= CORRUPT_MASK
    output = bytearray(LENGTH)
    for slot, column in enumerate(order):
        for row in range(SIZE):
            i = SIZE * slot + row
            output[i] = grid[SIZE * row + column] ^ key[i % len(key)]
    return bytes(output)


def recover(order, key, target):
    grid = bytearray(LENGTH)
    for slot, column in enumerate(order):
        for row in range(SIZE):
            i = SIZE * slot + row
            grid[SIZE * row + column] = target[i] ^ key[i % len(key)]
    before_repair = bytes(grid)
    grid[CORRUPT_INDEX] ^= CORRUPT_MASK
    return before_repair, bytes(grid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to broken-matrix")
    args = parser.parse_args()
    order, key, target = extract_constants(args.binary)
    before, flag = recover(order, key, target)
    print("Column order:", list(order))
    print("XOR key:", repr(key))
    print("Target:", target.hex())
    print("Before repair:", repr(before))
    print(
        f"Repair index {CORRUPT_INDEX}: "
        f"0x{before[CORRUPT_INDEX]:02x} XOR 0x{CORRUPT_MASK:02x} "
        f"= 0x{flag[CORRUPT_INDEX]:02x}"
    )
    if encode(flag, order, key) != target:
        raise SystemExit("Forward-model verification failed")
    if b"\x00" in flag:
        raise SystemExit("Recovered input contains a NUL, conflicting with strlen")
    print("Forward-model verification: all 36 target bytes match")
    print("Flag:", flag.decode("ascii"))


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_broken_matrix.py ./broken-matrix
```

Expected output:

```text
Column order: [0, 1, 5, 3, 2, 4]
XOR key: b'5k3ff'
Target: 655f520e395b285014f55834040d535b0a4e1d39400e5b50325e0f5b5554005e6c551450
Before repair: b'PCT{574ck_5kardu_5h\x93he3n_m3hran_26e}'
Repair index 19: 0x93 XOR 0xf2 = 0x61
Forward-model verification: all 36 target bytes match
Flag: PCT{574ck_5kardu_5hahe3n_m3hran_26e}
```

**Next step:** the forward-model check validates the inverse against our reconstructed transformation. The original executable provides the independent confirmation that the reconstruction is correct.

## 9. Complete script 2: verify against the original binary

Save as `verify_broken_matrix.py`. This uses the ELF's Linux loader to run the supplied binary without changing its executable permission. It requires compatible x86-64 Linux libraries; the recovery script itself does not execute the ELF.

```python
#!/usr/bin/env python3
"""Check a candidate against the original Broken Matrix executable."""

import argparse
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("candidate")
    parser.add_argument(
        "--loader", type=Path,
        default=Path("/lib64/ld-linux-x86-64.so.2"),
    )
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    loader = args.loader.resolve(strict=True)
    result = subprocess.run(
        [str(loader), str(binary), args.candidate],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    expected = f"Correct! {args.candidate}"
    if result.returncode != 0 or expected not in result.stdout.splitlines():
        raise SystemExit(f"Verification failed (exit code {result.returncode})")
    print("Verified: the original executable accepts this input.")


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 verify_broken_matrix.py ./broken-matrix 'PCT{574ck_5kardu_5hahe3n_m3hran_26e}'
```

Or use the equivalent direct command:

```bash
/lib64/ld-linux-x86-64.so.2 ./broken-matrix 'PCT{574ck_5kardu_5hahe3n_m3hran_26e}'
```

The original executable prints:

```text
   [BROKEN MATRIX]  v1.0
   a 6x6 memory grid was found after the glitch.
   encrypted flag: 655f520e395b285014f55834040d535b0a4e1d39400e5b50325e0f5b5554005e6c551450
   hint: the columns are scrambled, one cell is corrupted.
Correct! PCT{574ck_5kardu_5hahe3n_m3hran_26e}
```

It exits with status `0`.

## 10. Common mistakes and how to avoid them

| Mistake | Why it fails | Correct approach |
|---|---|---|
| XORing the ASCII hexadecimal characters | The printed text is an encoding of the target | Read the raw table or decode with `bytes.fromhex` |
| Treating `5k3ff` as hexadecimal | It is a five-byte ASCII key | Use bytes `35 6b 33 66 66` |
| Resetting the key for each column | The checker uses the global output index | Use `(6*slot + row) % 5` |
| Reading a row instead of a column | The input pointer advances by six bytes | Address the grid as `6*row + column` |
| Applying the permutation in the wrong direction | The table selects source columns | Place recovered bytes at `grid[6*row + order[slot]]` |
| Repairing ciphertext byte 19 | Index 19 belongs to the original grid layout | Reconstruct the grid first, then repair index 19 |
| Using index 18 for the “19th byte” | Assembly offset `0x13` is zero-based 19 | It is the twentieth byte, fourth row/second column |
| Ignoring `0x93` or replacing it by intuition | A plausible-looking flag is not sufficient evidence | Undo the exact XOR instruction |
| Treating `0xCCCCCCCD` as a key | It participates in optimized division by five | Translate the sequence into `i % 5` |
| Assuming static addresses are always file offsets | ELF mappings vary | Check the containing section |

## 11. What the challenge teaches

The useful move was to work backward from `memcmp`: identify the destination buffer, trace every write into it, and express the transformation using array indices. That exposed both the column traversal and the key schedule.

The “dead pixel” is one reversible XOR in a temporary grid. Once that instruction and the permutation are understood, the apparent corruption is fully recoverable. Every input byte maps to one target byte, so the solution takes a fixed 36-byte pass rather than a brute-force search.

**Final flag:**

```text
PCT{574ck_5kardu_5hahe3n_m3hran_26e}
```
