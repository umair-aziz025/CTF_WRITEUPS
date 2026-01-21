# ReM3 - Reverse Engineering Challenge Writeup

**Challenge:** ReM3  
**Category:** Reverse Engineering  
**Flag:** `KCTF{w3Lc0m3_T0_tHE_r3_w0rLD}`

---

## Challenge Description

A 500MB binary file `rem3.ks` was provided (heavily padded). The challenge was to reverse engineer the flag validation logic and extract the correct flag.

---

## Initial Analysis

### File Information
```bash
$ file rem3.ks
rem3.ks: ELF 64-bit LSB executable, x86-64, dynamically linked

$ ls -lh rem3.ks
-rwxr-xr-x 1 kali kali 500M Jan 20 03:23 rem3.ks
```

### Fake Flags in Strings
```bash
$ strings rem3.ks | grep KCTF
KCTF{fake_flag_for_reversers}
KCTF{hash_passes_but_fake!!!}
KCTF{str1ngs_lie_dont_trust!}
```

These are decoy flags designed to mislead analysts using simple `strings` approach.

---

## Reverse Engineering Analysis

### Program Flow

1. **Length Check**: Input must be exactly 29 characters (`0x1d`)
2. **FNV-1a Hash Check**: Compares hash against `0xe76fa3daba5d6f3a` - leads to fake flag
3. **XOR Transform**: Complex transformation function at `0x14c0`
4. **Multi-part Comparison**: Compares transformed input against encrypted target data

### Key Functions

#### Hash Check (Decoy Path)
At `0x1162-0x116f`:
```asm
movabs $0xe76fa3daba5d6f3a,%rax
cmp    %rax,%rdx
je     0x123d  ; Prints fake flag if hash matches
```

#### Transform Function at 0x14c0
This is the real validation - a complex XOR/rotation cipher:
- Uses two 64-bit keys: `r10 = 0x2f910ed35ca71942`, `r9 = 0x6a124de908b17733`
- Applies position-dependent XOR
- Applies rotate-left and rotate-right operations
- Uses cascading state variables

#### Target Encrypted Data (from .rodata)
```
0x2160: dc6bbb4dfd25e47ec326  (bytes 0-9)
0x2150: f572ab96fc8d551093c1  (bytes 10-19)
0x2140: fd81465b7e33838f2f    (bytes 20-28)
```

---

## Solution

### Transform Function Implementation

```python
#!/usr/bin/env python3
import struct
import string

r10 = 0x2f910ed35ca71942
r9 = 0x6a124de908b17733

def transform(data):
    """Replicate the XOR/rotation cipher at 0x14c0"""
    if len(data) != 29:
        data = data[:29] if len(data) > 29 else data + b'\x00' * (29 - len(data))
    data = bytearray(data)
    r8 = 0
    edi = 0
    esi = 0xffffffc3 & 0xffffffff
    
    for i in range(29):
        ebx = i & 7
        shift1 = ebx * 8
        
        # Extract byte from r10
        rax = (r10 >> shift1) & 0xff
        ecx = ((i * 8) + 0x10) & 0x38
        
        # XOR with input
        al = (rax + edi) & 0xff
        al = al ^ data[i]
        edi = (edi + 0x1d) & 0xffffffff
        
        # Rotate left
        r14_val = (r9 >> ecx) & 0xff
        r14_low = r14_val & 0x7
        al = ((al << r14_low) | (al >> (8 - r14_low))) & 0xff
        
        # More XOR operations
        r14_val2 = (r9 >> shift1) & 0xff
        al = (al + (esi & 0xff)) & 0xff
        ecx2 = r14_val2 ^ r8
        r8 = (r8 + 0x11) & 0xffffffff
        al = al ^ (ecx2 & 0xff)
        
        # Rotate right
        esi_low = esi & 0x7
        al = ((al >> esi_low) | (al << (8 - esi_low))) & 0xff
        
        data[i] = al
        
        # Update state for next iteration
        ecx3 = ((i * 8) + 0x18) & 0x38
        rbx_val = (r10 >> ecx3) & 0xff
        ecx_final = rbx_val ^ 0xa5
        ecx_final = (ecx_final + esi) & 0xff
        esi = (al + ecx_final) & 0xffffffff
    
    return bytes(data)
```

### Brute Force Solver

Since the transformation has cascading dependencies, we use a greedy character-by-character approach:

```python
target = bytes.fromhex('dc6bbb4dfd25e47ec326f572ab96fc8d551093c1fd81465b7e33838f2f')
charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + '_!@#$%'

# Known format: KCTF{.......................}
flag = bytearray(b'KCTF{' + b'A' * 23 + b'}')

for pos in range(5, 28):
    best_char = 'A'
    best_match = 0
    
    for c in charset:
        flag[pos] = ord(c)
        out = transform(bytes(flag))
        
        # Count cumulative matching bytes
        cumulative = sum(1 for i in range(pos+1) if out[i] == target[i])
        if cumulative > best_match:
            best_match = cumulative
            best_char = c
    
    flag[pos] = ord(best_char)
    print(f'Position {pos}: {best_char}')

print(f'Flag: {bytes(flag).decode()}')
```

### Output
```
Pos 5: w
Pos 6: 3
Pos 7: L
Pos 8: c
Pos 9: 0
Pos 10: m
Pos 11: 3
Pos 12: _
Pos 13: T
Pos 14: 0
Pos 15: _
Pos 16: t
Pos 17: H
Pos 18: E
Pos 19: _
Pos 20: r
Pos 21: 3
Pos 22: _
Pos 23: w
Pos 24: 0
Pos 25: r
Pos 26: L
Pos 27: D

Flag: KCTF{w3Lc0m3_T0_tHE_r3_w0rLD}
```

---

## Verification

```bash
$ echo 'KCTF{w3Lc0m3_T0_tHE_r3_w0rLD}' | ./rem3.ks
=== KCTF Reverse Challenge ===
Enter flag: Success! Real flag accepted.
```

---

## Key Takeaways

1. **Don't Trust Strings**: The binary contained multiple fake flags designed to trap lazy reversers
2. **Understand the Flow**: The FNV hash check was a red herring - the real validation used a custom cipher
3. **Custom Cipher Analysis**: The transform used XOR + rotations with position-dependent keys
4. **Cascading State**: Each byte's transformation depended on previous results, requiring character-by-character solving
5. **Size Padding**: The 500MB size was artificial padding to make analysis slower

---

## Tools Used

- `file` - Binary identification
- `strings` - Initial string extraction (revealed decoys)
- `objdump -d` - Disassembly
- Python3 - Cipher reimplementation and brute force

---

**Author:** stxrdust  
**Date:** January 20, 2026  
**Competition:** KnightCTF 2026
