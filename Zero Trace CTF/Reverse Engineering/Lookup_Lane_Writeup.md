# Lookup Lane — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 250 points  
**Provided file:** `lookup-lane`  
**Flag format:** `PCT{...}`

> Every byte goes through the lookup lane. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and approach

```text
PCT{gwad4r_vault_mehran_484f5}
```

The executable requires exactly 30 input bytes. At each position `i`, it adds `5*i` to the input byte, keeps the low eight bits, and uses that result as an index into a 256-byte lookup table. The resulting table value must match a stored target byte.

The checker is equivalent to:

```python
table[(input_byte + 5 * i) % 256] == target[i]
```

The table contains each possible byte exactly once, so it is a permutation. Building its inverse lets us recover every input byte directly:

```python
input_byte = (inverse[target[i]] - 5 * i) % 256
```

The investigation proceeds from file identification to the length check, then to the transformation loop, table extraction, inversion, and verification with the original executable. No whole-flag brute force or binary patching is needed.

## 2. Initial inspection

Assume the provided binary is named `lookup-lane` in the current directory. Inspect it with:

```bash
file lookup-lane
sha256sum lookup-lane
strings -a lookup-lane
objdump -d -M intel lookup-lane
```

The file is a stripped, dynamically linked, little-endian x86-64 PIE executable. Its interpreter is:

```text
/lib64/ld-linux-x86-64.so.2
```

SHA-256 of the supplied sample:

```text
4ca769a94181a02666b900d6804ca3dc77abc011d7230cd26e0c20e2951b9cee
```

The imports identify useful operations: `strlen`, `snprintf`, `fgets`, `strcspn`, `puts`, and `__printf_chk`. Even without ordinary function symbols, these calls help distinguish input handling from validation and output.

The startup code passes static address `0x1140` as the main-function pointer to `__libc_start_main`. Static addresses below refer to the disassembly; the runtime load base can differ because the executable is PIE.

**Why this step:** the challenge hint suggests a lookup transformation, but we still need the actual table, index expression, and acceptance conditions. The code supplies those details.

**Next step:** follow the input buffer into the validation routine.

## 3. Recover the length requirement and input path

The main routine supports two input methods:

- With a command-line argument, it copies `argv[1]` into a 256-byte buffer using `snprintf` and `%s`.
- Otherwise, it reads a line using `fgets` and removes the line ending using `strcspn`.

Both paths reach:

```asm
1197: mov    rdi,rbx
119a: call   strlen@plt
119f: cmp    rax,0x1e
11a3: je     11d7
```

`0x1e` is decimal 30. A different length leads to the failure message.

```text
strlen(input) == 30
```

`strlen` counts bytes before the first NUL. For this ASCII flag, byte count and character count are equal.

**Next step:** follow the successful branch at `0x11d7`. Length tells us how many bytes to recover, while the following loop tells us how to recover them.

## 4. Translate the lookup loop

The program initializes the input index and loads two pointers:

```asm
11d7: xor    eax,eax
11d9: lea    rsi,[rip+0xe80]    ; table at 0x2060
11e0: lea    rcx,[rip+0xf79]    ; target at 0x2160
```

The transformation and comparison are:

```asm
11fa: lea    edx,[rax+rax*4]
11fd: add    dl,BYTE PTR [rbx+rax]
1200: movzx  edi,BYTE PTR [rcx+rax]
1204: movzx  edx,dl
1207: cmp    BYTE PTR [rsi+rdx],dil
120b: je     11f0
120d: jmp    11a5
```

Interpret the instructions in order:

| Instruction | Meaning |
|---|---|
| `lea edx,[rax+rax*4]` | Calculate `5*i` |
| `add dl,[rbx+rax]` | Add the current input byte to the low eight bits |
| `movzx edi,[rcx+rax]` | Read `target[i]` as an unsigned byte |
| `movzx edx,dl` | Convert the low-byte result to an index from 0 to 255 |
| `cmp [rsi+rdx],dil` | Compare the lookup result with the target byte |

The use of `dl` is important: arithmetic wraps modulo 256. The later `movzx` discards everything except that low-byte value and zero-extends it for indexing.

The successful branch increments `i` and checks the loop bound:

```asm
11f0: add    rax,0x1
11f4: cmp    rax,0x1e
11f8: je     120f
```

There are exactly 30 comparisons. Any mismatch goes to failure; matching every position reaches the success message.

### Reconstructed checker

This is readable pseudocode reconstructed from the machine code:

```python
def accepts(candidate, table, target):
    if len(candidate) != 30:
        return False
    for i, value in enumerate(candidate):
        index = (value + 5 * i) & 0xFF
        if table[index] != target[i]:
            return False
    return True
```

The checks are independent: the result at one position does not update a state used by later positions. This means each byte can be recovered separately.

**Next step:** extract the two arrays and determine whether the lookup mapping has a unique inverse.

## 5. Extract the table and target

Inspect the section layout and read-only data:

```bash
readelf -SW lookup-lane
objdump -s -j .rodata lookup-lane
```

The relevant section has:

```text
Section:         .rodata
Virtual address: 0x2000
File offset:     0x2000
Size:            0x17e
```

Convert static addresses within that section using:

```text
file offset = section file offset + (address - section virtual address)
```

For this sample, the table address `0x2060` maps to file offset `0x2060`, and the target address `0x2160` maps to file offset `0x2160`. Their equality is specific to this section layout.

| File offset | Length | Role |
|---|---:|---|
| `0x2060` | 256 bytes | Lookup table |
| `0x2160` | 30 bytes | Expected transformed bytes |

The target is:

```text
ed06d7e4a498c55ee17421279a3dcbfd8530fdca1b8318c64aaf3da6cebe
```

Extraction in Python is:

```python
data = Path("lookup-lane").read_bytes()
table = data[0x2060:0x2160]
target = data[0x2160:0x217E]
```

These are byte arrays, not arrays of multibyte integers. We do not need to unpack the target as little-endian words.

### Check invertibility instead of assuming it

The extracted table has 256 entries and 256 distinct values:

```python
len(table) == 256
len(set(table)) == 256
```

Since every entry is a byte, this establishes that each value from 0 through 255 occurs exactly once. Therefore the table is a permutation, and every target value has one table index.

If duplicate values had existed, we would have needed to retain all possible preimage indices. A simple inverse dictionary would silently discard alternatives. Checking uniqueness first avoids that error.

**Next step:** invert the permutation and undo the position-dependent addition.

## 6. Recover each byte mathematically

The forward equation is:

```text
table[(input[i] + 5*i) mod 256] = target[i]
```

Define the inverse table by:

```text
inverse[table[j]] = j
```

Applying it to both sides gives:

```text
(input[i] + 5*i) mod 256 = inverse[target[i]]
```

Subtract the position-dependent value modulo 256:

```text
input[i] = (inverse[target[i]] - 5*i) mod 256
```

The reverse order matters. First undo the lookup, then undo the addition. Subtracting `5*i` from the target before applying the inverse would generally produce the wrong byte because the table is not a linear arithmetic operation.

### Worked example: recover `PCT{`

| Index `i` | Target | Inverse-table index | Subtract `5*i` | Recovered byte |
|---:|---|---:|---:|---|
| 0 | `0xed` | 80 | `80 - 0 = 80` | `P` |
| 1 | `0x06` | 72 | `72 - 5 = 67` | `C` |
| 2 | `0xd7` | 94 | `94 - 10 = 84` | `T` |
| 3 | `0xe4` | 138 | `138 - 15 = 123` | `{` |

The expected flag prefix emerges directly from the bytes. Applying the same rule to all 30 positions produces:

```text
PCT{gwad4r_vault_mehran_484f5}
```

### Why this is efficient

Building the inverse takes 256 assignments. Recovering the flag takes another 30 lookup-and-subtract operations, so the work is proportional to `256 + flag_length`.

An alternative would try all 256 input bytes at each position, requiring at most `30*256 = 7,680` candidate checks. That is also small, but the inverse-table method expresses the underlying structure more directly and proves uniqueness for each position.

**Next step:** encode the inverse and forward model in a complete solver, then confirm its result with the original executable.

## 7. Complete script 1: extract, invert, and verify the model

Save the entire code block as `solve_lookup_lane.py`. It uses Python's standard library only. The offsets are specific to the supplied binary and were established from the disassembly and section layout above.

```python
#!/usr/bin/env python3
"""Recover Lookup Lane's flag by inverting its byte permutation."""
import argparse
from pathlib import Path

TABLE_OFFSET = 0x2060
TABLE_SIZE = 256
TARGET_OFFSET = 0x2160
FLAG_LENGTH = 30
STEP = 5


def extract(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a 64-bit little-endian ELF")
    if len(data) < TARGET_OFFSET + FLAG_LENGTH:
        raise ValueError("File is too short for the expected tables")
    table = data[TABLE_OFFSET:TABLE_OFFSET + TABLE_SIZE]
    target = data[TARGET_OFFSET:TARGET_OFFSET + FLAG_LENGTH]
    if len(set(table)) != TABLE_SIZE:
        raise ValueError("Lookup table is not a permutation of all 256 bytes")
    return table, target


def forward(candidate, table):
    return bytes(table[(value + STEP * i) & 0xFF]
                 for i, value in enumerate(candidate))


def recover(table, target):
    inverse = [0] * TABLE_SIZE
    for index, value in enumerate(table):
        inverse[value] = index
    return bytes((inverse[value] - STEP * i) & 0xFF
                 for i, value in enumerate(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to lookup-lane")
    args = parser.parse_args()
    table, target = extract(args.binary)
    flag = recover(table, target)
    print("Lookup entries:", len(table))
    print("Distinct lookup values:", len(set(table)))
    print("Target:", target.hex())
    print("Recovered length:", len(flag))
    if len(flag) != FLAG_LENGTH or b"\x00" in flag:
        raise SystemExit("Recovered input conflicts with the length check")
    if forward(flag, table) != target:
        raise SystemExit("Forward-model verification failed")
    print("Forward-model verification: all 30 target bytes match")
    print("Flag:", flag.decode("ascii"))


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_lookup_lane.py ./lookup-lane
```

Output:

```text
Lookup entries: 256
Distinct lookup values: 256
Target: ed06d7e4a498c55ee17421279a3dcbfd8530fdca1b8318c64aaf3da6cebe
Recovered length: 30
Forward-model verification: all 30 target bytes match
Flag: PCT{gwad4r_vault_mehran_484f5}
```

The forward check runs the recovered flag through the same transformation identified in the assembly. This checks the inverse arithmetic and extracted data, but real execution is still valuable as an independent confirmation of the reconstruction.

## 8. Complete script 2: verify with the original binary

Save as `verify_lookup_lane.py`. It invokes the ELF through its Linux dynamic loader, so the uploaded file does not need its executable permission changed. This verification requires a compatible x86-64 Linux environment and libraries. The static solver above does not execute the ELF.

```python
#!/usr/bin/env python3
"""Verify an input against the original Lookup Lane executable."""
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
        capture_output=True, text=True, timeout=5, check=False,
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
python3 verify_lookup_lane.py ./lookup-lane 'PCT{gwad4r_vault_mehran_484f5}'
```

Or use the direct command:

```bash
/lib64/ld-linux-x86-64.so.2 ./lookup-lane 'PCT{gwad4r_vault_mehran_484f5}'
```

The original executable prints:

```text
   [LOOKUP LANE]  v1.0
Correct! PCT{gwad4r_vault_mehran_484f5}
```

It exits with status `0`, confirming that the recovered input passes the actual checker.

## 9. Common mistakes and why they fail

| Mistake | Consequence | Correction |
|---|---|---|
| Reading the target as plaintext | The target contains substituted bytes | Follow the table lookup |
| Assuming the table is invertible | Duplicate entries could hide alternatives | Check all 256 entries are distinct |
| Computing `table[target[i]]` | Applies the forward table again | Build `inverse[table[j]] = j` |
| Subtracting before undoing the lookup | Reverses operations in the wrong order | Apply the inverse table first |
| Using `i` instead of `5*i` | Misreads `rax + rax*4` | Translate the expression carefully |
| Forgetting modulo 256 | Does not reproduce low-byte arithmetic | Use `% 256` or `& 0xFF` |
| Starting the index at one | Shifts every position-dependent adjustment | Use zero-based indices |
| Treating the arrays as 32-bit words | Changes byte ordering and grouping | Read raw bytes |
| Assuming virtual addresses equal file offsets | Can extract the wrong data in other ELFs | Map through the containing section |
| Stopping at a plausible-looking flag | A model error could remain | Verify the original executable |

## 10. What the challenge teaches

The lookup table hides the readable input, but it does not make recovery difficult when the table is available and bijective. The main reverse-engineering task is identifying the exact index expression and the width of its arithmetic.

Once the code is expressed as a byte permutation applied after a position-dependent addition, the inverse follows directly. The complete solution consists of extracting the arrays, checking the permutation property, reversing each operation, and confirming the resulting input through the unmodified binary.

**Final flag:**

```text
PCT{gwad4r_vault_mehran_484f5}
```
