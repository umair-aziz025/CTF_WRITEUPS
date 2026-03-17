# ReM3 Again - Reverse Engineering Challenge Writeup

**Challenge:** ReM3 Again  
**Category:** Reverse Engineering  
**Flag:** `KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}`

---

## Challenge Description

> Reverse me again if you can...

A 500MB binary file `rem3_again.ks` was provided (heavily padded with null bytes to slow down analysis).

---

## Initial Analysis

### File Information
```bash
$ file rem3_again.ks
rem3_again.ks: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped

$ ls -lh rem3_again.ks
-rwxr-xr-x 1 kali kali 500M Jan 20 04:44 rem3_again.ks
```

### Quick Test
```bash
$ echo 'KCTF{test}' | ./rem3_again.ks
=== KCTF Challenge ===
Enter flag: Failed!
```

The binary expects a specific flag format and validates it.

---

## Reverse Engineering Analysis

### Disassembly Overview

Using `objdump -d`, I identified the key functions:

| Function | Address | Purpose |
|----------|---------|---------|
| `main` | 0x1080 | Entry point, reads input |
| `p` | 0x13e0 | Generates permutation table |
| `t.constprop.0` | 0x1570 | Transform/cipher function |
| `eq.constprop.0` | 0x16b0 | Comparison function |
| `chk_first.constprop.0` | 0x1740 | Wrapper for checks |
| `cat3.constprop.0` | 0x1540 | Concatenates 3 data blocks |

### Key Observations

1. **Flag Length Check** at `0x1103`:
```asm
cmp    $0x26,%rsi    ; Flag must be 38 (0x26) characters
```

2. **Multiple Comparison Calls**: The `eq.constprop.0` function is called **4 times** with different target data:
   - Calls 1-3: Check against fake/decoy flags
   - Call 4: Check against the REAL flag

3. **Encrypted Data Blocks** in `.rodata`:
   - `x_g0/x_g1/x_g2` at 0x2108-0x2128 (decoy)
   - `x_f0/x_f1/x_f2` at 0x20d8-0x20f8 (decoy)
   - `x_d0/x_d1/x_d2` at 0x20a8-0x20c8 (decoy)
   - `x_r0/x_r1/x_r2` at 0x2138-0x2158 (**REAL target**)

---

## Solution: GDB Dynamic Analysis

Instead of reversing the complex cipher, I used GDB to extract the expected plaintext directly from memory during comparison.

### Step 1: Prepare Test Input
```bash
echo 'KCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}' > input.txt
```

### Step 2: Debug with GDB
```bash
gdb -q ./rem3_again.ks
(gdb) set pagination off
(gdb) set disable-randomization on
(gdb) break eq.constprop.0
(gdb) run < input.txt
```

### Step 3: Skip to the 4th Comparison
```
(gdb) continue   # Skip 1st decoy
(gdb) continue   # Skip 2nd decoy
(gdb) continue   # Skip 3rd decoy
# Now at 4th call - the REAL check
```

### Step 4: Dump Expected Value
```
(gdb) x/38xb $rsi
0x7fffffffe650: 0x4b 0x43 0x54 0x46 0x7b 0x61 0x4e 0x30
0x7fffffffe658: 0x54 0x68 0x33 0x72 0x5f 0x72 0x33 0x5f
0x7fffffffe660: 0x49 0x5f 0x68 0x30 0x50 0x45 0x5f 0x79
0x7fffffffe668: 0x30 0x55 0x5f 0x65 0x4e 0x6a 0x30 0x59
0x7fffffffe670: 0x45 0x44 0x5f 0x49 0x54 0x7d
```

### Step 5: Decode the Flag
```python
>>> bytes([0x4b,0x43,0x54,0x46,0x7b,0x61,0x4e,0x30,0x54,0x68,0x33,0x72,0x5f,
           0x72,0x33,0x5f,0x49,0x5f,0x68,0x30,0x50,0x45,0x5f,0x79,0x30,0x55,
           0x5f,0x65,0x4e,0x6a,0x30,0x59,0x45,0x44,0x5f,0x49,0x54,0x7d]).decode()
'KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}'
```

---

## Verification

```bash
$ echo 'KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}' | ./rem3_again.ks
=== KCTF Challenge ===
Enter flag: Success! Real flag accepted.
Now grab your points. :)
```

---

## Decoy Flags Found

The binary contains multiple fake flags designed to mislead:

| Check # | Expected Value | Type |
|---------|---------------|------|
| 1 | `GoogleCTF{n0_p01nts_th1s_1s_n0t_1t!!!}` | Decoy |
| 2 | (encrypted data) | Decoy |
| 3 | (encrypted data) | Decoy |
| 4 | `KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}` | **REAL** |

---

## Key Takeaways

1. **Don't Trust Static Analysis Alone**: The binary has multiple decoy checks - dynamic analysis reveals the real validation path.

2. **GDB is Powerful**: Instead of reversing complex ciphers, break at comparison functions and read expected values directly from memory.

3. **Multiple Comparisons = Red Herring**: When you see multiple `eq` or comparison calls, the last one is often the real check.

4. **500MB Size is Padding**: The massive file size is just null bytes appended to slow down analysis tools.

---

## Tools Used

- `file`, `strings` - Initial reconnaissance
- `objdump -d` - Disassembly
- `xxd` - Hex dump of .rodata section
- `gdb` - Dynamic analysis and memory inspection
- Python - Byte decoding

---

**Author:** MR. Umair  
**Date:** January 21, 2026  
**Competition:** KnightCTF 2026
