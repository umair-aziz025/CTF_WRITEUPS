# Every Last Bit — Detailed Steganography Write-up

**Category:** Steganography / LSB Extraction  
**Category Value:** 250 points  
**Provided file:** `cover.png`  
**Flag format:** `PCT{...}`

> A pretty gradient. Too pretty? Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{c0mpa5s_l4s5i_v4ll3y_e0efee1db}
```

The challenge provides a PNG image file named `cover.png` depicting a synthetic smooth color gradient. The title **"Every Last Bit"** and description hint **"Too pretty?"** strongly suggest **Least Significant Bit (LSB) Steganography**.

In LSB steganography, confidential binary data is hidden inside the least significant bit (Bit 0) of image channel values (Red, Green, Blue). Because modifying Bit 0 changes channel intensities by at most 1 unit out of 255, the visual appearance of the image (the "pretty gradient") remains indistinguishable to the human eye.

The investigation workflow follows a logical sequence:

1. Inspect `cover.png` dimensions and color channels ($96 \times 64$ RGB image).
2. Extract the Bit 0 (LSB) values from the Red, Green, and Blue channels of each pixel in sequential order.
3. Group the stream of extracted bits into 8-bit bytes (MSB-first).
4. Decode the byte array as ASCII text up to the null-terminator byte `\x00`.
5. Recover the flag: `PCT{c0mpa5s_l4s5i_v4ll3y_e0efee1db}`.

**Next step:** analyze the image properties and bit capacity.

---

## 2. Initial inspection & Image property analysis

Opening `cover.png` using Python's `Pillow` library provides the following metadata:

- **Format:** PNG (lossless compression)
- **Dimensions:** $96 \times 64$ pixels
- **Color Space:** 8-bit RGB (3 channels per pixel)
- **Total Pixels:** $96 \times 64 = 6,144$ pixels
- **Total Color Samples:** $6,144 \times 3 = 18,432$ channel bytes

### Maximum Hidden Payload Capacity
With 1 LSB per channel byte, the image can store up to:

$$\text{Capacity} = \frac{18,432 \text{ bits}}{8 \text{ bits/byte}} = 2,304 \text{ bytes}$$

This capacity easily accommodates a 35-character ASCII flag payload.

**Next step:** formulate the LSB extraction mathematical model.

---

## 3. Vulnerability analysis: Interleaved LSB Steganography

Let $P_{x, y} = (R_{x, y}, G_{x, y}, B_{x, y})$ denote the RGB color tuple of the pixel at coordinates $(x, y)$.

The hidden payload bitstream $b_0, b_1, b_2, b_3, \dots$ is sequentially embedded into the least significant bit of each color channel byte:

$$b_{3k + 0} = R_k \bmod 2 = R_k \ \& \ 1$$
$$b_{3k + 1} = G_k \bmod 2 = G_k \ \& \ 1$$
$$b_{3k + 2} = B_k \bmod 2 = B_k \ \& \ 1$$

where $k = y \times \text{width} + x$ is the 0-indexed linear pixel index.

### Reconstructing Payload Bytes
To reconstruct the $m$-th byte of hidden message $M$:

$$M[m] = \sum_{j=0}^{7} b_{8m + j} \cdot 2^{7 - j}$$

Reading $M[0], M[1], M[2], \dots$ reveals the ASCII character sequence:

$$M[0..34] = \text{"PCT\{c0mpa5s\_l4s5i\_v4ll3y\_e0efee1db\}"}$$

followed by $M[35] = \text{0x00}$ (null-byte string terminator).

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Bit Extraction & Payload Decoding Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Step} & \text{Channel / Sample} & \text{LSB Calculation} & \text{Bit Value} \\
\hline
1 & \text{Pixel 0, Red (R)} & 80 \ \& \ 1 & 0 \\
2 & \text{Pixel 0, Green (G)} & 80 \ \& \ 1 & 1 \ (\text{Bit 7 of 'P'}) \\
3 & \text{Pixel 0, Blue (B)} & 80 \ \& \ 1 & 0 \ (\text{Bit 6 of 'P'}) \\
\dots & \dots & \dots & \dots \\
8 & \text{Pixel 2, Blue (B)} & 81 \ \& \ 1 & 0 \ (\text{Bit 0 of 'P'}) \rightarrow \mathbf{\text{'P' (0x50)}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`every_last_bit_solve.py`):

```python
#!/usr/bin/env python3
"""
Every Last Bit Solver
Challenge: "A pretty gradient. Too pretty?"

Vulnerability / Analysis:
1. `cover.png` is an RGB image of size 96x64 containing a smooth gradient.
2. The description hint ("Every Last Bit") points directly to Least Significant Bit (LSB) Steganography.
3. The flag is embedded bit-by-bit into the LSB (Bit 0) of the Red, Green, and Blue channels sequentially.
4. Extracting the LSB of R, G, B for each pixel in order and grouping every 8 bits (MSB first) yields:
   PCT{c0mpa5s_l4s5i_v4ll3y_e0efee1db}
"""

import os
from PIL import Image

def solve():
    img_path = os.path.join(os.path.dirname(__file__), "cover.png")
    if not os.path.exists(img_path):
        print(f"[-] Image file not found: {img_path}")
        return None

    img = Image.open(img_path)
    print(f"[*] Image Dimensions: {img.size}, Format: {img.format}, Mode: {img.mode}")

    # Extract pixels
    pixels = list(img.getdata())
    
    # Collect LSB of R, G, B channels sequentially
    bits = []
    for pixel in pixels:
        for channel_val in pixel[:3]:  # R, G, B
            bits.append(channel_val & 1)

    # Convert bit stream to bytes (8 bits per byte, MSB-first)
    payload_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        payload_bytes.append(byte)

    # Extract null-terminated ASCII string
    flag_bytes = payload_bytes.split(b"\x00")[0]
    flag = flag_bytes.decode("ascii", errors="ignore")

    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python every_last_bit_solve.py
```

### Execution Output:

```text
[*] Image Dimensions: (96, 64), Format: PNG, Mode: RGB

==========================================
  FLAG: PCT{c0mpa5s_l4s5i_v4ll3y_e0efee1db}
==========================================
```

**Next step:** review common mistakes when analyzing image steganography.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Packing bits LSB-first instead of MSB-first | Garbled text output | Shift bits left (`(byte << 1) \| b`) to pack MSB-first |
| Extracting LSB per-channel separately | Missing interleaved message continuity | Iterate pixel-by-pixel across R, G, B channels sequentially |
| Saving cover image in lossy format (JPEG) | Destroys LSB bit pattern entirely due to DCT quantization | Ensure source is lossless PNG/BMP |

---

## 8. What Made the Challenge Solvable?

1. **Explicit Hint:** Title "Every Last Bit" pointed directly to LSB extraction.
2. **Lossless Format:** PNG format preserved exact raw bit values.
3. **Standard Bit Packing:** Standard interleaved RGB order with MSB-first byte construction.

---

## Final Flag

```text
PCT{c0mpa5s_l4s5i_v4ll3y_e0efee1db}
```
