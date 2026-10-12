# Link by Link — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 176 points  
**Provided file:** `link-by-link`  
**Flag format:** `PCT{...}`

> One byte feeds the next byte. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and approach

```text
PCT{p4rb4t_1ronwall_11ec77}
```

The program requires 27 input bytes. Starting from state `0x32`, it updates an eight-bit state for each input byte:

```text
new_state = (9 * previous_state + input_byte) mod 256
```

After every update, the state must equal a stored target byte. The previous state therefore becomes known at every position along the accepted path. Recovering the input requires only subtraction:

```text
input_byte = (target_byte - 9 * previous_state) mod 256
```

The investigation follows this chain:

1. Identify the ELF and locate the input-validation routine.
2. Recover the length requirement, initial state, and state-update equation.
3. Extract the stored target sequence.
4. Reverse each update using the known previous state.
5. Recompute the complete forward sequence and run the recovered flag through the original executable.

The “link” is the rolling state, not simply the preceding plaintext character. Correctly identifying that distinction is the main task.

## 2. Initial inspection

Assume the binary is named `link-by-link` in the current directory. Use:

```bash
file link-by-link
sha256sum link-by-link
strings -a link-by-link
objdump -d -M intel link-by-link
```

The supplied sample is a stripped, dynamically linked, little-endian x86-64 PIE ELF. Its interpreter is:

```text
/lib64/ld-linux-x86-64.so.2
```

SHA-256:

```text
eeab2e90e7deae2239876f685464f13d7bc097e2e3e1b1669b90d86f499d3e3b
```

Although ordinary function symbols are stripped, imported functions such as `strlen`, `snprintf`, `fgets`, `strcspn`, and `puts` identify input processing and output. Startup code passes static address `0x1140` to `__libc_start_main`, identifying the main routine.

Addresses in this write-up are static disassembly addresses. PIE means the binary can load at a different runtime base; it does not prevent analysis of these relative references.

**Next step:** locate the length check, then follow the branch that begins validation.

## 3. Identify input handling and required length

The program accepts a command-line argument or a line from standard input. It copies `argv[1]` using `snprintf`, or reads with `fgets` and removes the line ending using `strcspn`. Both routes use the same checker.

The length check is:

```asm
1197: mov    rdi,rbx
119a: call   strlen@plt
119f: cmp    rax,0x1b
11a3: je     11d7
```

`0x1b` is decimal 27. Any other length reaches the failure path.

```text
strlen(input) == 27
```

`strlen` counts bytes up to the first NUL byte. The recovered flag contains ASCII characters, so its byte count and character count are both 27.

**Why this matters:** the length fixes the number of validation steps and tells us how many target bytes to extract. It does not justify searching all 27 characters together.

**Next step:** inspect the state initialization and loop body to determine how the bytes are related.

## 4. Translate the chained check

The successful length branch initializes three important values:

```asm
11d7: xor    edx,edx
11d9: mov    ecx,0x32
11de: lea    rsi,[rip+0xe6b]    ; target at 0x2050
```

| Register | Meaning |
|---|---|
| `rdx` | Current input index, initially zero |
| `ecx` | State, initially `0x32` or decimal 50 |
| `rsi` | Pointer to the target sequence |
| `rbx` | Pointer to the input buffer |

The loop body is:

```asm
11fa: lea    eax,[rcx+rcx*8]
11fd: add    al,BYTE PTR [rbx+rdx]
1200: movzx  ecx,al
1203: cmp    BYTE PTR [rsi+rdx],al
1206: je     11f0
1208: jmp    11a5
```

Interpret these instructions in sequence:

1. `rcx + rcx*8` computes nine times the previous state.
2. `add al, ...` adds the current input byte to the low eight bits.
3. `movzx ecx, al` saves that resulting byte as the next state.
4. The new state is compared against the current target byte.
5. A mismatch immediately reaches failure.

Because the addition uses `al` and the state is reconstructed from `al`, only the low eight bits survive:

```python
state = (9 * state + input_byte) & 0xFF
```

This is arithmetic modulo 256. Python integers do not wrap automatically, so a Python model must explicitly use `& 0xFF` or `% 256`.

On a successful comparison, the program advances the index:

```asm
11f0: add    rdx,0x1
11f4: cmp    rdx,0x1b
11f8: je     120a
```

After 27 successful comparisons, it prints the success message with the original input.

### Reconstructed checker

This is readable pseudocode derived from the disassembly, not recovered original source:

```python
def accepts(candidate, target):
    if len(candidate) != 27:
        return False
    state = 0x32
    for i, value in enumerate(candidate):
        state = (9 * state + value) & 0xFF
        if state != target[i]:
            return False
    return True
```

**Next step:** extract the target sequence. Since every intermediate state is checked, that sequence gives us all the state values along the accepted execution.

## 5. Extract the stored states

Inspect the section layout and data:

```bash
readelf -SW link-by-link
objdump -s -j .rodata link-by-link
```

The relevant section is:

```text
Section:         .rodata
Virtual address: 0x2000
File offset:     0x2000
Size:            0x6b
```

The code references target address `0x2050`. Convert it through the containing section:

```text
file offset = section file offset + (target address - section address)
            = 0x2000 + (0x2050 - 0x2000)
            = 0x2050
```

Virtual addresses and file offsets happen to match here; they are not universally interchangeable.

The target has 27 bytes, ending at exclusive offset `0x206b`:

```python
target = data[0x2050:0x206B]
```

Its hexadecimal representation is:

```text
12e561e47448fa2cc03433fc4e2d03928307ab62a3ecb19cb3820f
```

This is a raw byte sequence. Reading it as 32-bit integers would introduce unnecessary grouping and endianness mistakes.

**Next step:** rearrange the state equation to solve for the input byte rather than searching for it.

## 6. Reverse the chain

Let `x[i]` be the input byte, `s[i]` the state after processing it, and `s[-1] = 50` the initial state. The forward recurrence is:

```text
s[i] = (9*s[i-1] + x[i]) mod 256
```

For an accepted input:

```text
s[i] = target[i]
```

Therefore:

```text
x[0] = (target[0] - 9*50) mod 256
x[i] = (target[i] - 9*target[i-1]) mod 256, for i > 0
```

The current input byte has coefficient one, so no modular inverse is needed. We simply subtract the known state contribution.

### Worked example: recover `PCT{`

| Index | Previous state | Current target | Recovery calculation | Character |
|---:|---:|---:|---|---|
| 0 | 50 | 18 | `(18 - 9*50) % 256 = 80` | `P` |
| 1 | 18 | 229 | `(229 - 9*18) % 256 = 67` | `C` |
| 2 | 229 | 97 | `(97 - 9*229) % 256 = 84` | `T` |
| 3 | 97 | 228 | `(228 - 9*97) % 256 = 123` | `{` |

For example, the first forward update confirms the inverse:

```text
(9*50 + 80) mod 256 = 530 mod 256 = 18 = 0x12
```

The next update uses state 18, not plaintext byte 80:

```text
(9*18 + 67) mod 256 = 229 = 0xe5
```

### Update the correct variable

A correct recovery loop is:

```python
previous = 0x32
for expected_state in target:
    recovered_byte = (expected_state - 9 * previous) & 0xFF
    previous = expected_state
```

Setting `previous = recovered_byte` would model a different transformation and corrupt the remaining output.

### Why chaining does not make this difficult

In the running checker, each input byte influences the state used at the next position. However, the binary stores the expected state after **every** byte. Those stored values remove uncertainty about the state on the accepted path.

For a known previous state and current target, there is exactly one input byte modulo 256. Recovering all 27 bytes requires a single pass. In fact, once the target array is available, each byte after the first can be computed directly from two adjacent target values.

If the program exposed only a final state, this reasoning would not determine every byte uniquely. The intermediate comparisons are what make this challenge directly reversible.

**Next step:** implement extraction and recovery, then recompute the entire forward sequence as a consistency check.

## 7. Complete script 1: recover and verify the state sequence

Save the full code as `solve_link_by_link.py`. It requires only Python's standard library. The target offset, length, initial state, and multiplier are specific to the analyzed sample.

```python
#!/usr/bin/env python3
"""Recover Link by Link's flag from its stored state sequence."""
import argparse
from pathlib import Path

TARGET_OFFSET = 0x2050
FLAG_LENGTH = 27
INITIAL_STATE = 0x32
MULTIPLIER = 9


def read_target(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a 64-bit little-endian ELF")
    end = TARGET_OFFSET + FLAG_LENGTH
    if len(data) < end:
        raise ValueError("File is too short for the expected target sequence")
    return data[TARGET_OFFSET:end]


def recover(target):
    previous = INITIAL_STATE
    output = bytearray()
    for expected in target:
        output.append((expected - MULTIPLIER * previous) & 0xFF)
        previous = expected
    return bytes(output)


def forward(candidate):
    state = INITIAL_STATE
    states = bytearray()
    for value in candidate:
        state = (MULTIPLIER * state + value) & 0xFF
        states.append(state)
    return bytes(states)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to link-by-link")
    parser.add_argument("--trace", action="store_true",
                        help="Show the recovery calculation for every byte")
    args = parser.parse_args()
    target = read_target(args.binary)
    flag = recover(target)
    print("Initial state:", INITIAL_STATE)
    print("Target:", target.hex())
    print("Recovered length:", len(flag))
    if len(flag) != FLAG_LENGTH or b"\x00" in flag:
        raise SystemExit("Recovered input conflicts with the length check")
    if forward(flag) != target:
        raise SystemExit("Forward-state verification failed")
    print("Forward-state verification: all 27 target bytes match")
    print("Flag:", flag.decode("ascii"))
    if args.trace:
        previous = INITIAL_STATE
        for i, (expected, value) in enumerate(zip(target, flag)):
            print(f"{i:02d}: ({expected:3d} - 9*{previous:3d}) % 256 "
                  f"= {value:3d} {chr(value)!r}")
            previous = expected


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_link_by_link.py ./link-by-link
```

Output:

```text
Initial state: 50
Target: 12e561e47448fa2cc03433fc4e2d03928307ab62a3ecb19cb3820f
Recovered length: 27
Forward-state verification: all 27 target bytes match
Flag: PCT{p4rb4t_1ronwall_11ec77}
```

To see every byte calculation:

```bash
python3 solve_link_by_link.py ./link-by-link --trace
```

**Next step:** run the candidate through the original executable. The forward model checks our arithmetic, while execution checks whether we reconstructed the actual validator correctly.

## 8. Complete script 2: verify with the original binary

Save as `verify_link_by_link.py`. Running through the Linux dynamic loader avoids changing the uploaded file's executable permission. This step needs a compatible x86-64 Linux environment and libraries; static recovery above does not execute the ELF.

```python
#!/usr/bin/env python3
"""Verify a candidate against the original Link by Link executable."""
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
python3 verify_link_by_link.py ./link-by-link 'PCT{p4rb4t_1ronwall_11ec77}'
```

Or use the direct command:

```bash
/lib64/ld-linux-x86-64.so.2 ./link-by-link 'PCT{p4rb4t_1ronwall_11ec77}'
```

The original executable prints:

```text
   [LINK BY LINK]  v1.0
Correct! PCT{p4rb4t_1ronwall_11ec77}
```

Its exit status is `0`, confirming that the recovered flag passes every check.

## 9. Common mistakes and why they fail

| Mistake | Consequence | Correction |
|---|---|---|
| Treating the previous state as the previous plaintext byte | Models a different chain | Use the previous target after each successful step |
| Starting from zero | Corrupts the first recovered byte | Initialize with `0x32`, decimal 50 |
| Reading `rcx + rcx*8` as multiplication by eight | Uses the wrong recurrence | It is multiplication by nine |
| Forgetting modulo 256 | Negative or oversized Python values do not reproduce byte arithmetic | Use `& 0xFF` or `% 256` |
| Updating the state before recovering the current byte | Uses the current target as both states | Recover first, then advance `previous` |
| Using a modular inverse of nine unnecessarily | Solves for the wrong unknown | The unknown input has coefficient one; subtract |
| Assuming a chained check requires brute force | Ignores the stored intermediate states | Recover from adjacent target values |
| Reading target bytes as larger integers | Changes grouping and interpretation | Extract the raw 27-byte sequence |
| Treating virtual addresses as file offsets without checking | Can extract unrelated data in another ELF | Map through the section headers |
| Stopping at the expected prefix | Does not validate the remaining chain | Check all 27 states and execute the binary |

## 10. What the challenge teaches

The key is to identify precisely what the loop carries from one iteration to the next. Here it carries the low-byte result of a multiplication and addition, not the original input character.

Once the state recurrence is written down, the stored comparison values reveal the entire accepted state sequence. Each input byte follows from a simple modular subtraction. Recomputing all states and confirming the flag with the original executable completes the evidence.

**Final flag:**

```text
PCT{p4rb4t_1ronwall_11ec77}
```
