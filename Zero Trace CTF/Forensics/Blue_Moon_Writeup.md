# Blue Moon — Detailed Steganography Write-up

**Category:** Steganography / Channel-Specific LSB Extraction  
**Category Value:** 250 points  
**Provided file:** `skyline_b.png`  
**Flag format:** `PCT{...}`

> Same technique, but whoever hid the data wrote their bits backwards.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{b1ts_1n_r3v3rs3_0rd3r}
```

The challenge provides a $480 \times 270$ RGB PNG image named `skyline_b.png`.

The title **"Blue Moon"** and description hint **"Same technique, but whoever hid the data wrote their bits backwards"** point directly to two critical steganographic modifications:

1. **Single-Channel Targeting:** Data is stored exclusively within the **Blue channel** (channel index 2).
2. **Reversed Bit-Order Packing (LSB-first):** Rather than standard Most Significant Bit (MSB-first) bit packing, the bits composing each payload byte are packed in **LSB-first** order (Bit 0 to Bit 7).

The investigation workflow follows a logical sequence:

1. Open `skyline_b.png` and extract the Blue channel intensity values from all 129,600 pixels.
2. Isolate the Least Significant Bit (Bit 0) of each Blue channel byte to form a 129,600-bit stream.
3. Group bits into 8-bit bytes using LSB-first bit assembly ($B = \sum_{j=0}^{7} b_j \cdot 2^j$).
4. Inspect the decoded payload and parse the length header `\x00\x00\x00\x1a` followed by the ASCII flag.
5. Recover the flag: `PCT{b1ts_1n_r3v3rs3_0rd3r}`.

**Next step:** analyze the image properties and bit capacity.

---

## 2. Initial inspection & Image channel analysis

Inspecting `skyline_b.png` metadata:

- **Dimensions:** $480 \times 270$ pixels
- **Color Space:** 8-bit RGB (3 channels per pixel)
- **Total Pixels:** $480 \times 270 = 129,600$ pixels
- **Blue Channel Capacity:** $129,600 \text{ bits} / 8 = 16,200 \text{ bytes}$

The Blue channel capacity (16.2 KB) easily accommodates the 30-byte hidden payload.

**Next step:** formulate the LSB-first mathematical extraction model.

---

## 3. Vulnerability analysis: LSB-First Bitstream Reassembly

In standard MSB-first bit packing:

$$B_{\text{MSB}} = \sum_{j=0}^{7} b_j \cdot 2^{7 - j} = ((((((b_0 \ll 1) | b_1) \ll 1) | b_2) \dots)$$

In this challenge, the creator packed bits in **LSB-first order**:

$$B_{\text{LSB}} = \sum_{j=0}^{7} b_j \cdot 2^j = b_0 + (b_1 \cdot 2) + (b_2 \cdot 4) + \dots + (b_7 \cdot 128)$$

In Python bitwise arithmetic:

```python
byte_val = 0
for j in range(8):
    byte_val |= (bits[i + j] << j)
```

### Decoded Payload Structure

| Offset Range | Value / Bytes | Description |
|---|---|---|
| 0x00 .. 0x03 | `\x00\x00\x00\x1a` (26) | Big-endian Payload Length Header |
| 0x04 .. 0x1D | `PCT{b1ts_1n_r3v3rs3_0rd3r}` | **Flag ASCII String Payload** |

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Bit Extraction Procedure

$$\begin{array}{|c|c|c|l|}
\hline
\text{Pixel Index} & \text{Blue Channel Value} & \text{LSB (Bit 0)} & \text{LSB-First Byte Assembly} \\
\hline
0 & 144 & 0 & \text{Bit 0 of Byte 0} = 0 \\
1 & 144 & 0 & \text{Bit 1 of Byte 0} = 0 \\
\dots & \dots & \dots & \dots \\
7 & 144 & 0 & \text{Bit 7 of Byte 0} = 0 \rightarrow \texttt{0x00} \\
\dots & \dots & \dots & \dots \\
32 & 144 & 0 & \text{Bit 0 of 'P'} = 0 \\
33 & 145 & 1 & \text{Bit 1 of 'P'} = 1 \ (\cdot 2) \\
34 & 144 & 0 & \text{Bit 2 of 'P'} = 0 \\
35 & 144 & 0 & \text{Bit 3 of 'P'} = 0 \\
36 & 145 & 1 & \text{Bit 4 of 'P'} = 1 \ (\cdot 16) \\
37 & 144 & 0 & \text{Bit 5 of 'P'} = 0 \\
38 & 145 & 1 & \text{Bit 6 of 'P'} = 1 \ (\cdot 64) \\
39 & 144 & 0 & \text{Bit 7 of 'P'} = 0 \rightarrow \mathbf{2 + 16 + 64 = 80 \ (\text{'P'})} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`blue_moon_solve.py`):

```python
#!/usr/bin/env python3
"""
Blue Moon Solver
Challenge: "Same technique, but whoever hid the data wrote their bits backwards."

Vulnerability / Analysis:
1. `skyline_b.png` is a 480x270 RGB PNG image.
2. The title ("Blue Moon") indicates that data is hidden exclusively inside the Blue channel (channel index 2).
3. The description hint ("wrote their bits backwards") specifies LSB-first bit packing (`b |= (bit << j)` for j in 0..7).
4. Extracting Bit 0 of the Blue channel pixel by pixel and packing bits LSB-first reveals:
     Header (4 bytes): length = 26 bytes (0x0000001A)
     Payload (26 bytes): PCT{b1ts_1n_r3v3rs3_0rd3r}
"""

import os
from PIL import Image

def solve():
    base_dir = os.path.dirname(__file__)
    img_path = os.path.join(base_dir, "skyline_b.png")

    if not os.path.exists(img_path):
        print(f"[-] Image file not found: {img_path}")
        return None

    img = Image.open(img_path)
    print(f"[*] Image Dimensions: {img.size}, Format: {img.format}, Mode: {img.mode}")

    pixels = list(img.getdata())
    
    # Extract Bit 0 of Blue Channel (p[2])
    bits = [p[2] & 1 for p in pixels]

    # Convert bitstream to bytes (8 bits per byte, LSB-first)
    payload = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (bits[i + j] << j)
        payload.append(byte_val)

    # Locate flag starting with PCT{
    flag_start = payload.find(b"PCT{")
    if flag_start != -1:
        flag_end = payload.find(b"}", flag_start) + 1
        flag = payload[flag_start:flag_end].decode("ascii")

        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
        return flag
    else:
        print("[-] Flag format PCT{...} not found in Blue channel LSB stream.")
        return None

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python blue_moon_solve.py
```

### Execution Output:

```text
[*] Image Dimensions: (480, 270), Format: PNG, Mode: RGB

==========================================
  FLAG: PCT{b1ts_1n_r3v3rs3_0rd3r}
==========================================
```

**Next step:** review common mistakes when decoding channel-specific LSB steganography.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Packing bits MSB-first | Outputting garbled non-printable characters | Use LSB-first bit assembly (`byte_val \|= (bit << j)`) |
| Interleaving Red and Green channels | Scrambling the single-channel bit stream | Extract LSB exclusively from the Blue channel (`pixel[2]`) |
| Stopping at `\x00` byte 0 | Returning empty flag string | Parse 4-byte length prefix or search for `PCT{` magic header |

---

## 8. What Made the Challenge Solvable?

1. **Clear Textual Clues:** "Blue Moon" identified Blue channel; "bits backwards" identified LSB-first bit order.
2. **Lossless PNG Storage:** Preserved exact pixel bit values without JPEG compression artifacts.
3. **Identifiable Flag Structure:** Standard `PCT{...}` prefix enabled instant payload validation.

---

## Final Flag

```text
PCT{b1ts_1n_r3v3rs3_0rd3r}
```
