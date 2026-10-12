# Chunk Norris — Detailed Reverse Engineering Write-up

**Category:** Reverse engineering  
**Challenge value:** 400 points  
**Provided file:** `chunk-norris`  
**Flag format:** `PCT{...}`

> Break it into pieces, break the pieces. Download the ELF binary, reverse it, and find the input it accepts. That input is the flag.

## 1. Result and overall approach

The accepted input is:

```text
PCT{kar4k0r4m_gho5t_a258f7}
```

The executable does not store the flag as a readable string. Instead, it requires an input of exactly **27 bytes**, splits it into **nine independent three-byte blocks**, and compares a modified FNV-1a hash of each block against a stored 32-bit fingerprint.

That structure is the weakness. Searching for all 27 characters together would be impractical, but recovering nine separate three-character blocks is easy. We can reduce the search further by reversing the final hash multiplication and calculating the third character from each candidate pair.

The investigation therefore follows a connected sequence:

1. Identify the executable and inspect its strings to locate useful input/output clues.
2. Follow the input handling in the disassembly to find the acceptance conditions.
3. Translate the hash loop into a precise model, including 32-bit arithmetic.
4. Extract its nine target fingerprints from the ELF.
5. Recover each short block independently and join the results.
6. Submit the recovered input to the original executable to verify the model.

No patching, buffer overflow, or bypass is needed. The goal is to recover an input that satisfies the original checks.

## 2. Initial inspection: what kind of file are we analyzing?

The commands below assume the downloaded binary is named `chunk-norris` in the current directory. Linux tools `file`, `strings`, `readelf`, and `objdump` are used for inspection; the solver needs Python 3.8 or later and no third-party packages.

```bash
file chunk-norris
sha256sum chunk-norris
strings -a chunk-norris
```

The file identification reports:

```text
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, stripped
```

SHA-256 of the supplied sample:

```text
600278a3d6889b2687bc5e440c27ef8be93b32371037e538867a41459a97df15
```

These properties guide the next step:

- **x86-64, little-endian:** use the appropriate instruction set and decode stored integers in little-endian order.
- **PIE:** the runtime load base can change. Addresses in this write-up refer to the static addresses shown by `objdump`, not fixed absolute runtime locations.
- **Stripped:** ordinary function names are missing, but imported library functions still identify useful operations.
- **Dynamically linked:** calls such as `strlen`, `fgets`, and `puts` help reveal the program's structure.

Relevant strings and imports include:

```text
fgets
snprintf
strlen
strcspn
puts
__printf_chk
   [CHUNK NORRIS]  v1.0
Nope. Access denied.
Correct! %s
```

There is no readable `PCT{...}` flag in the strings output. That alone does not prove hashing, but the challenge's “pieces” hint suggests looking for checks on small input blocks. The success and failure messages give us landmarks for locating the checker.

**Next step:** inspect the code around input handling and the branches that lead to those messages.

## 3. Find the input path and length requirement

Disassemble the executable in Intel syntax:

```bash
objdump -d -M intel chunk-norris
```

The startup code passes static address `0x1140` as the main-function pointer to `__libc_start_main`. This identifies the main routine even though its symbol name has been stripped.

The routine accepts input in two ways:

- If a command-line argument exists, it copies `argv[1]` into a 256-byte buffer using `snprintf` and the format `%s`.
- Otherwise, it reads from standard input using `fgets` and removes the line ending through `strcspn`.

Both paths reach the same validation logic. The first important check is:

```asm
1197: mov    rdi,rbx
119a: call   strlen@plt
119f: cmp    rax,0x1b
11a3: je     11d7
```

`0x1b` is decimal 27. A different length falls through to the failure message.

This establishes our first hard constraint:

```text
strlen(input) == 27
```

Strictly speaking, `strlen` measures bytes before the first NUL byte. The recovered flag is ASCII, so its byte count and character count are identical.

**Why this matters:** we now know the expected size, but length alone does not make whole-flag brute force feasible. We must determine whether the remaining checks couple all 27 bytes together or check smaller pieces independently.

**Next step:** follow the successful length-check branch at `0x11d7`.

## 4. Decode the fingerprint loop

The checker first loads a pointer to the target table and initializes a counter-like value:

```asm
11d7: lea    r8,[rip+0xe82]    ; target table at 0x2060
11de: mov    rsi,rbx           ; current input block
11e1: xor    edi,edi           ; initial block-dependent value = 0
```

It then initializes the hash and processes bytes:

```asm
11e8: mov    eax,edi
11ea: xor    edx,edx
11ec: xor    eax,0x811c9dc5
11f1: movzx  ecx,BYTE PTR [rsi+rdx]
11f5: add    rdx,0x1
11f9: xor    eax,ecx
11fb: imul   eax,eax,0x1000193
1201: cmp    rdx,0x3
1205: jne    11f1
```

Two constants identify the FNV-1a pattern:

| Constant | Role |
|---|---|
| `0x811c9dc5` | Standard 32-bit FNV offset basis |
| `0x01000193` | Standard 32-bit FNV prime |

The operation is **XOR first, then multiply**, which is the FNV-1a ordering. This variant changes the initial state for each block.

The comparison against `3` shows that each hash covers exactly three bytes. After the inner loop, the program compares the result and advances:

```asm
1207: cmp    eax,DWORD PTR [r8]
120a: jne    11a5             ; failure
120c: sub    edi,0x61c8864f
1212: add    r8,0x4           ; next 32-bit target
1216: add    rsi,0x3          ; next three input bytes
121a: cmp    edi,0x8ff34739
1220: jne    11e8
```

The input pointer advances by three bytes and the target pointer by four bytes. Each new block starts a fresh hash; it does not inherit the preceding block's hash result.

### 4.1 Understand the changing seed

The instruction subtracts `0x61c8864f` from a 32-bit register. Modulo `2^32`, this is equivalent to adding:

```text
2^32 - 0x61c8864f = 0x9e3779b1
```

For zero-based block index `i`:

```text
salt(i) = (i * 0x9e3779b1) mod 2^32
seed(i) = 0x811c9dc5 XOR salt(i)
```

After nine increments:

```text
(9 * 0x9e3779b1) mod 2^32 = 0x8ff34739
```

That matches the loop's exit comparison. Nine blocks multiplied by three bytes gives 27 bytes, independently confirming the length analysis.

### 4.2 Preserve 32-bit overflow

The hash lives in `eax`, a 32-bit register. Only the low 32 bits of each multiplication are retained. Python integers do not overflow automatically, so the equivalent operation must explicitly mask the result:

```python
h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
```

This arithmetic overflow is intentional hash behavior. It is unrelated to a memory or buffer overflow vulnerability.

### 4.3 Reconstructed validation logic

The following is readable pseudocode reconstructed from the disassembly, not recovered original source:

```c
bool check(const unsigned char *input) {
    if (strlen((const char *)input) != 27)
        return false;

    uint32_t salt = 0;
    for (unsigned i = 0; i < 9; i++) {
        uint32_t h = 0x811c9dc5u ^ salt;
        for (unsigned j = 0; j < 3; j++) {
            h ^= input[3 * i + j];
            h *= 0x01000193u;  // uint32_t wraps modulo 2^32
        }
        if (h != targets[i])
            return false;
        salt += 0x9e3779b1u;
    }
    return true;
}
```

**Next step:** the algorithm is now known, but we need the actual target values before solving it.

## 5. Extract the nine stored fingerprints

Inspect section locations and read-only data:

```bash
readelf -SW chunk-norris
objdump -s -j .rodata chunk-norris
```

The relevant section metadata is:

```text
Section:         .rodata
Virtual address: 0x2000
File offset:     0x2000
Size:            0x84
```

The code references the table at virtual address `0x2060`. Convert that address to a file offset using the containing section:

```text
file offset = section file offset + (target VA - section VA)
            = 0x2000 + (0x2060 - 0x2000)
            = 0x2060
```

The two values happen to match in this sample. Virtual addresses and file offsets are not generally interchangeable.

Each target is four bytes, and there are nine targets, so read 36 bytes at that offset. Since the ELF is little-endian, use the Python format `<9I`.

| Block index | Target hash | Recovered bytes |
|---:|---|---|
| 0 | `0xda06fc50` | `PCT` |
| 1 | `0x71a8ab19` | `{ka` |
| 2 | `0x5ed0b1fe` | `r4k` |
| 3 | `0x419a9e7c` | `0r4` |
| 4 | `0x4fdb1bd2` | `m_g` |
| 5 | `0x5766b230` | `ho5` |
| 6 | `0x18c0b52d` | `t_a` |
| 7 | `0x0189bfd5` | `258` |
| 8 | `0xa949621d` | `f7}` |

The recovered column is shown here for reference; the next sections explain how it is computed.

## 6. Choose a recovery strategy

### 6.1 Why independent block brute force works

A natural first alphabet is printable ASCII, bytes 32 through 126 inclusive. The flag format supports trying that alphabet, although the executable itself does not enforce printable characters.

There are 95 candidates per character. A full 27-character search would contain `95^27` possibilities, whereas solving the independent blocks requires at most:

```text
9 × 95^3 = 7,716,375 three-byte candidates
```

That is already manageable. If printable ASCII produced no solution, the search could be expanded to other bytes. For this sample, every block has exactly one printable match, and the concatenated input is accepted.

### 6.2 Improve the search by deriving the third byte

Let `p = 0x01000193`, and let `h2` be the hash state after two candidate bytes. For the third byte `c`, the stored target `t` is:

```text
 t = ((h2 XOR c) * p) mod 2^32
```

Because `p` is odd, it is relatively prime to `2^32`. Therefore it has a multiplicative inverse modulo `2^32`:

```python
inverse = pow(p, -1, 1 << 32)
```

Multiply the target by this inverse to undo the last multiplication:

```text
u = (t * inverse) mod 2^32
u = h2 XOR c
c = h2 XOR u
```

For every possible first and second character, calculate `c` directly and keep it only if it is a printable byte. This reduces the search to:

```text
9 × 95^2 = 81,225 candidate pairs
```

The reduction in candidate combinations is a factor of 95; exact runtime speedup depends on implementation overhead.

Do not mask the derived `c` to eight bits. If it is larger than 255, that pair does not have a valid one-byte completion. Masking it would hide that fact and create false candidates.

This does not mean arbitrary long FNV hashes can be uniquely reversed. The attack works because the program exposes independent fingerprints of tiny input blocks.

## 7. Complete script 1: extract and solve

Save the entire code block as `solve_chunk_norris.py`.

The script reads the target table from the supplied binary, supports both ordinary triple brute force and the faster inverse method, checks that every block has exactly one printable candidate, and rehashes the recovered result before printing it. The file offset is specific to the supplied sample, as established above.

```python
#!/usr/bin/env python3
"""Recover Chunk Norris's accepted input using only the standard library."""

import argparse
import struct
from pathlib import Path

MASK = 0xFFFFFFFF
MODULUS = 1 << 32
BASIS = 0x811C9DC5
PRIME = 0x01000193
STEP = 0x9E3779B1
BLOCK_SIZE = 3
BLOCK_COUNT = 9
TABLE_OFFSET = 0x2060
ALPHABET = range(32, 127)


def seed_for(index):
    return BASIS ^ ((index * STEP) & MASK)


def hash_block(block, index):
    h = seed_for(index)
    for byte in block:
        h = ((h ^ byte) * PRIME) & MASK
    return h


def read_targets(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a 64-bit little-endian ELF file")
    end = TABLE_OFFSET + BLOCK_COUNT * 4
    if len(data) < end:
        raise ValueError("File is too short to contain the expected hash table")
    return struct.unpack_from("<9I", data, TABLE_OFFSET)


def recover_bruteforce(target, index):
    matches = []
    seed = seed_for(index)
    for a in ALPHABET:
        h1 = ((seed ^ a) * PRIME) & MASK
        for b in ALPHABET:
            h2 = ((h1 ^ b) * PRIME) & MASK
            for c in ALPHABET:
                if ((h2 ^ c) * PRIME) & MASK == target:
                    matches.append(bytes((a, b, c)))
    return matches


def recover_inverse(target, index):
    matches = []
    seed = seed_for(index)
    inverse = pow(PRIME, -1, MODULUS)
    before_last_multiply = (target * inverse) & MASK
    for a in ALPHABET:
        h1 = ((seed ^ a) * PRIME) & MASK
        for b in ALPHABET:
            h2 = ((h1 ^ b) * PRIME) & MASK
            c = h2 ^ before_last_multiply
            if c in ALPHABET:
                block = bytes((a, b, c))
                if hash_block(block, index) != target:
                    raise RuntimeError("Internal candidate verification failed")
                matches.append(block)
    return matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to chunk-norris")
    parser.add_argument(
        "--method", choices=("inverse", "bruteforce"), default="inverse"
    )
    args = parser.parse_args()
    targets = read_targets(args.binary)
    recover = recover_inverse if args.method == "inverse" else recover_bruteforce
    blocks = []

    for index, target in enumerate(targets):
        matches = recover(target, index)
        print(f"block {index}: target=0x{target:08x} matches={matches!r}")
        if len(matches) != 1:
            raise SystemExit(
                f"Expected one printable match for block {index}; "
                f"found {len(matches)}. Check the sample, table, or alphabet."
            )
        blocks.append(matches[0])

    flag = b"".join(blocks)
    if len(flag) != BLOCK_SIZE * BLOCK_COUNT:
        raise SystemExit("Recovered input has the wrong length")
    for index, target in enumerate(targets):
        start = index * BLOCK_SIZE
        if hash_block(flag[start:start + BLOCK_SIZE], index) != target:
            raise SystemExit(f"Final hash check failed at block {index}")
    print("Flag:", flag.decode("ascii"))


if __name__ == "__main__":
    main()
```

Run the optimized method:

```bash
python3 solve_chunk_norris.py ./chunk-norris
```

To reproduce the same result through ordinary three-byte brute force:

```bash
python3 solve_chunk_norris.py ./chunk-norris --method bruteforce
```

Output:

```text
block 0: target=0xda06fc50 matches=[b'PCT']
block 1: target=0x71a8ab19 matches=[b'{ka']
block 2: target=0x5ed0b1fe matches=[b'r4k']
block 3: target=0x419a9e7c matches=[b'0r4']
block 4: target=0x4fdb1bd2 matches=[b'm_g']
block 5: target=0x5766b230 matches=[b'ho5']
block 6: target=0x18c0b52d matches=[b't_a']
block 7: target=0x0189bfd5 matches=[b'258']
block 8: target=0xa949621d matches=[b'f7}']
Flag: PCT{kar4k0r4m_gho5t_a258f7}
```

**Next step:** matching our reconstructed hash model is strong evidence, but it could still reproduce a mistake in our interpretation. Run the candidate through the original checker as an independent end-to-end confirmation.

## 8. Complete script 2: verify with the original executable

Save this code as `verify_chunk_norris.py`. It invokes the original executable through its Linux dynamic loader, so changing the uploaded file's executable permission is unnecessary. This step requires a compatible x86-64 Linux environment and libraries; static recovery does not.

```python
#!/usr/bin/env python3
"""Verify a candidate against the original Chunk Norris executable."""

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
        help="Path to a compatible Linux x86-64 dynamic loader",
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
python3 verify_chunk_norris.py ./chunk-norris 'PCT{kar4k0r4m_gho5t_a258f7}'
```

The equivalent direct command used to confirm the solution is:

```bash
/lib64/ld-linux-x86-64.so.2 ./chunk-norris 'PCT{kar4k0r4m_gho5t_a258f7}'
```

The original binary prints:

```text
   [CHUNK NORRIS]  v1.0
Correct! PCT{kar4k0r4m_gho5t_a258f7}
```

It exits with status `0`, confirming acceptance.

## 9. Common mistakes and why they fail

| Mistake | Consequence | Correction |
|---|---|---|
| Searching only with `strings` | The stored values are hashes, not the flag text | Trace the comparison logic |
| Brute-forcing all 27 characters together | The search space becomes impractical | Use the independent three-byte blocks |
| Using the same seed for every block | Later blocks do not match their targets | Apply the block-dependent salt |
| Reading targets as big-endian | Every fingerprint is decoded incorrectly | Use `<9I` |
| Forgetting 32-bit masking in Python | Python arithmetic diverges from the CPU | Mask multiplication and salt arithmetic |
| Multiplying before XOR | Implements the wrong hash order | Follow the XOR-then-multiply assembly |
| Confusing a virtual address with a file offset | Extracts unrelated bytes in other layouts | Map through the containing ELF section |
| Truncating the derived third byte | Invalid candidate pairs can appear valid | Require the full derived value to fit the alphabet |
| Treating printable uniqueness as universal uniqueness | Overstates what was searched | Report one match per block within the tested alphabet |
| Stopping after the solver prints a plausible flag | A reconstruction error could go unnoticed | Verify against the unmodified binary |

## 10. Relationship to Brute Bastion

The supplied Chunk Norris binary uses the same validation structure as Brute Bastion: the same 27-byte length, nine three-byte blocks, seed schedule, FNV-1a update, and target-table offset. Its banner and target fingerprints differ. This was confirmed from Chunk Norris's own disassembly before reusing the recovery method.

The original solver could therefore be run against the new binary without changing its algorithm. Reading the target table from the file, rather than hard-coding the previous challenge's hashes, makes that reuse possible. The scripts above use Chunk Norris names so this write-up can also be followed independently.

## 11. What made the challenge solvable?

The program stores fingerprints instead of plaintext, but each fingerprint covers only three bytes and can be checked independently. The position-dependent seed changes the target calculation without increasing the unknown input space. FNV-1a is a non-cryptographic hash, and its odd multiplication constant also lets us reverse the final multiplication to reduce the search further.

The key reverse-engineering decision was to follow the input pointer and hash initialization across loop iterations. Those instructions showed that this was nine small recovery problems rather than one large problem. Extracting the table, preserving the exact arithmetic, and verifying against the original executable completed the chain of evidence.

**Final flag:**

```text
PCT{kar4k0r4m_gho5t_a258f7}
```
