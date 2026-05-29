# Ninja-Nerds (Forensics, 100) - Writeup

## Challenge
- Name: Ninja-Nerds
- Category: Forensics
- Difficulty: Medium
- Author: mrgreenhathacker
- Prompt: where are your little ninja-nerds?
- File: C:\Users\stxrdust\Downloads\challenge.png

## Goal
Recover the hidden flag from the PNG and output it in UMASS{...} format.

## High-level idea
This challenge used LSB steganography in a specific channel/bit ordering. Visual bit-plane inspection looked noisy, so the reliable method was brute-forcing channel order, bit-depth, bit-shift, and bit-packing direction, then regex searching decoded byte streams for UMASS{...}.

## Step-by-step solution

### 1) Basic triage
Check file metadata and obvious embedded strings.

```powershell
$img='C:\Users\stxrdust\Downloads\challenge.png'
Test-Path $img
Get-Item $img | Select-Object FullName,Length,LastWriteTime
python -c "from PIL import Image; img=Image.open(r'C:\Users\stxrdust\Downloads\challenge.png'); print(img.format, img.mode, img.size, img.info)"
python -c "import re; d=open(r'C:\Users\stxrdust\Downloads\challenge.png','rb').read(); print(re.findall(b'UMASS\\{[^}]{1,200}\\}', d))"
```

Result:
- PNG RGB, 640x360
- No metadata hints
- No direct raw-byte flag hit

### 2) PNG chunk check
Verify there are no custom chunks with embedded payloads.

```python
import struct
from collections import Counter

p = r"C:\Users\stxrdust\Downloads\challenge.png"
with open(p, "rb") as f:
    d = f.read()

assert d[:8] == b"\x89PNG\r\n\x1a\n"
o = 8
types = []
while o < len(d):
    ln = int.from_bytes(d[o:o+4], "big")
    typ = d[o+4:o+8]
    types.append(typ.decode("latin1"))
    o += 12 + ln
    if typ == b"IEND":
        break

print(Counter(types))
```

Result:
- Only standard chunks: IHDR, IDAT, IEND
- No custom chunk payload path

### 3) Bit-plane visual pass (sanity)
Rendered per-channel LSB plane images. They looked like natural noise and did not show clear text directly.

### 4) Robust extraction by brute-force decode search
This script solved the challenge.

```python
import re
import numpy as np
from PIL import Image

img = np.array(Image.open(r"C:\Users\stxrdust\Downloads\challenge.png").convert("RGB"), dtype=np.uint8)
patterns = [
    re.compile(rb"UMASS\{[^}]{1,200}\}"),
    re.compile(rb"flag\{[^}]{1,200}\}", re.I),
]

def bits_to_bytes(bits, msb=True):
    n = (len(bits) // 8) * 8
    bits = bits[:n].reshape(-1, 8)
    w = np.array([128, 64, 32, 16, 8, 4, 2, 1] if msb else [1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint8)
    return (bits * w).sum(axis=1).astype(np.uint8).tobytes()

orders = [
    ("RGB", [0, 1, 2]),
    ("RBG", [0, 2, 1]),
    ("GRB", [1, 0, 2]),
    ("GBR", [1, 2, 0]),
    ("BRG", [2, 0, 1]),
    ("BGR", [2, 1, 0]),
    ("R", [0]),
    ("G", [1]),
    ("B", [2]),
]

hits = []
for oname, ordc in orders:
    data = img[:, :, ordc].reshape(-1)
    for bits_used in [1, 2, 3, 4]:
        # Collect bit streams from bit0..bit(bits_used-1)
        bseq = [((data >> b) & 1).astype(np.uint8) for b in range(bits_used)]
        bits = np.concatenate(bseq)

        for shift in range(8):
            sbits = bits[shift:]
            for msb in [True, False]:
                by = bits_to_bytes(sbits, msb)
                for p in patterns:
                    m = p.search(by)
                    if m:
                        hits.append((oname, bits_used, shift, msb, m.group(0)))

print("hits:", len(hits))
for h in hits:
    print(h)
```

Output (key line):
- ("B", 1, 0, True, b"UMASS{perfectly-hidden-ready-to-strike}")

## Why this worked
- The payload is in the Blue channel LSB stream.
- Correct decode parameters:
  - Channel: B
  - Bits used: 1 (bit 0)
  - Shift: 0
  - Packing: MSB-first

## Final flag

```text
UMASS{perfectly-hidden-ready-to-strike}
```

## Repro one-liner (minimal)

```python
import re, numpy as np
from PIL import Image
img=np.array(Image.open(r"C:\Users\stxrdust\Downloads\challenge.png").convert("RGB"),dtype=np.uint8)
bits=(img[:,:,2].reshape(-1)&1).astype(np.uint8)
by=(bits[:(len(bits)//8)*8].reshape(-1,8)*np.array([128,64,32,16,8,4,2,1],dtype=np.uint8)).sum(axis=1).astype(np.uint8).tobytes()
print(re.search(rb"UMASS\{[^}]{1,200}\}",by).group(0).decode())
```
