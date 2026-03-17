# Validator
---
## Challenge
**Name:** Validator  
**Category:** rev  
**Difficulty:** Medium  

The binary asks for a flag and checks it with an intentionally obfuscated per-byte predicate.

## Key observations

- The ELF is **64-bit PIE** and **not stripped** (symbols exist).
- The real check is performed per-byte by the function `zWqDapvkXfHB(byte ch, int idx)`.
- `hIKCTDqsfNLU()` is the driver that iterates indices and calls `zWqDapvkXfHB`.
- `zWqDapvkXfHB` uses `.rodata` lookup tables (all **68 bytes**):
  - `XKCFcEiGsfwe` (key-ish table)
  - `LojuzgBPJdWU` (expected masked value per index)
  - plus `oKyKxnebFuod` and `uJSFvJPHjoaB` (used in the obfuscation)

## Why â€œno bruteforceâ€ still works here

We didnâ€™t blindly bruteforce the whole flag space.

Instead, we:
1. Identified the **exact per-byte predicate function** (`zWqDapvkXfHB`) and its index parameter.
2. Used it as an **oracle** to invert the check **one byte at a time** (only 256 candidates per index).

Thatâ€™s an analysis-driven inversion of the validation logic.

## Practical solving method (oracle)

Because the binary is not stripped, GDB can directly call `zWqDapvkXfHB`.

The only problem is that `zWqDapvkXfHB` calls a very heavy obfuscation helper `wstLsACQERer()`.
To make the solver fast, we patched `wstLsACQERer` **in-memory** to a single `ret`:

```gdb
set {unsigned char}wstLsACQERer = 0xc3
```

Then we looped `idx=0..67` and tested `byte=0..255`, selecting the value where the function returns non-zero.

The full script used is in:
- `1. ctf/validator/gdb_solve_validator.txt`

## Flag

âœ… Verified by running the binary in the Kali VM.

```
VBD{I_kn0w_y0u_w0uld_us3_Opus_hehe_eafa09ad1898e0bcf9c0225076632225}
```

## Verification

On Kali:

```bash
echo 'VBD{I_kn0w_y0u_w0uld_us3_Opus_hehe_eafa09ad1898e0bcf9c0225076632225}' | ./validator
# => Congratulations! You found the correct flag.
```

## Solver script (embedded)

This is the exact GDB oracle script used to recover the flag byte-by-byte:

```gdb
set pagination off
file /home/kali/validator
start
# speed: skip heavy obfuscation helper (safe for oracle use)
set {unsigned char}wstLsACQERer = 0xc3
python
import gdb
import re

N = 68
sol = [None] * N
amb = {}

for idx in range(N):
  cands = []
  for b in range(256):
    ret = int(gdb.parse_and_eval(f"(int)zWqDapvkXfHB({b},{idx})"))
    if ret != 0:
      cands.append(b)
  if len(cands) == 1:
    sol[idx] = cands[0]
  else:
    amb[idx] = cands

print('N =', N)
print('ambiguous indices =', len(amb))
for i, (idx, cands) in enumerate(sorted(amb.items())[:20]):
  print(f'idx {idx}: count={len(cands)} sample={cands[:20]}')

# Resolve ambiguities with printable/flag heuristics
common = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-")
for idx, cands in amb.items():
  printable = [b for b in cands if 32 <= b < 127]
  common_print = [b for b in printable if b in common]
  if len(common_print) == 1:
    sol[idx] = common_print[0]
  elif len(printable) == 1:
    sol[idx] = printable[0]
  elif common_print:
    sol[idx] = common_print[0]
  elif printable:
    sol[idx] = printable[0]
  else:
    sol[idx] = cands[0]

out = bytes(sol)
text = out.decode('latin1', errors='replace')
print('candidate_text=', text)
print('candidate_hex =', out.hex())
m = re.search(r"VBD\{[^\}]*\}", text)
print('flag_match    =', m.group(0) if m else None)
end
quit
```

---
