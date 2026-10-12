# Khunjerab Zigzag — Detailed Cryptography Write-up

**Category:** Cryptography / Transposition Cipher  
**Category Value:** 450 points  
**Provided file:** `zigzag.txt`  
**Flag format:** `PCT{...}`

> Up and down, like the road through the Khunjerab pass. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{d35ert_cipher_ciph3r_ch17r4l_942}
```

The challenge provides a single 37-character ciphertext string in `zigzag.txt`:
```text
Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}
```

The title **"Khunjerab Zigzag"** and description hint **"Up and down"** point directly to the **Rail Fence (Zigzag) Transposition Cipher**. In a Rail Fence cipher, characters of the plaintext message are written sequentially along a diagonal "zigzag" path up and down across $N$ horizontal rails, and then read off row-by-row to produce the scrambled ciphertext.

Testing potential rail counts $N \in \{2, 3, 4, 5, 6, \dots, 10\}$ shows that **$N = 5$ rails** aligns the scrambled characters back into the valid flag structure:
```text
PCT{d35ert_cipher_ciph3r_ch17r4l_942}
```

The investigation workflow follows a logical sequence:

1. Inspect `zigzag.txt` and note that the character frequency distribution matches ASCII flag characters (including `P`, `C`, `T`, `{`, `}`, and `_`).
2. Identify the hint "Up and down" as the Rail Fence / Zigzag transposition cipher.
3. Formulate the mathematical rail indexing sequence $R(i)$ for length $L = 37$.
4. Test candidate rail depths $N \in [2, 10]$.
5. Decrypt using $N = 5$ rails to recover the plaintext.

**Next step:** analyze the ciphertext properties and confirm character preservation.

---

## 2. Initial inspection & Ciphertext analysis

Opening `zigzag.txt` yields the string:

```text
Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}
```

### Key Observations
1. **Length:** Exactly 37 characters long.
2. **Character Set:** Contains uppercase letters (`P`, `C`, `T`), lowercase letters, digits, underscores (`_`), and curly braces (`{`, `}`).
3. **No Substitution:** The presence of `P`, `C`, `T`, `{`, `}` indicates an anagram/transposition cipher where individual characters were rearranged rather than substituted.

**Next step:** formulate the Rail Fence transposition model.

---

## 3. Vulnerability analysis: The Rail Fence (Zigzag) Transposition Model

In a Rail Fence cipher with $N$ rails, the rail index $r(i)$ for character index $i \in \{0, 1, \dots, L-1\}$ follows a periodic triangle wave of period $2(N - 1)$:

$$\text{Period } P = 2(N - 1)$$
$$r(i) = \begin{cases} i \bmod P & \text{if } (i \bmod P) < N \\ P - (i \bmod P) & \text{if } (i \bmod P) \ge N \end{cases}$$

### Visualizing 5-Rail Zigzag Pattern for $L = 37$
For $N = 5$ rails, the period $P = 2(5 - 1) = 8$. The rail index sequence for positions $i = 0 \dots 36$ is:

```text
Rail 0: 0 . . . . . . . 8 . . . . . . . 16 . . . . . . . 24 . . . . . . . 32 . . . .
Rail 1: . 1 . . . . . 7 . 9 . . . . . 15 . 17 . . . . . 23 . 25 . . . . . 31 . 33 . . . 
Rail 2: . . 2 . . . 6 . . . 10 . . . 14 . . . 18 . . . 22 . . . 26 . . . 30 . . . 34 . .
Rail 3: . . . 3 . 5 . . . . . 11 . 13 . . . . . 19 . 21 . . . . . 27 . 29 . . . . . 35 .
Rail 4: . . . . 4 . . . . . . . 12 . . . . . . . 20 . . . . . . . 28 . . . . . . . 36
```

### Character Distribution per Rail ($N = 5$)

- **Rail 0:** 5 characters (indices 0, 8, 16, 24, 32)
- **Rail 1:** 9 characters (indices 1, 7, 9, 15, 17, 23, 25, 31, 33)
- **Rail 2:** 9 characters (indices 2, 6, 10, 14, 18, 22, 26, 30, 34)
- **Rail 3:** 9 characters (indices 3, 5, 11, 13, 19, 21, 27, 29, 35)
- **Rail 4:** 5 characters (indices 4, 12, 20, 28, 36)

Concatenating the characters collected from Rail 0 to Rail 4 generates the 37-character ciphertext string `Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}`.

**Next step:** execute the reverse mapping algorithm to reconstruct the original plaintext.

---

## 4. Rail Fence Decryption Algorithm with 5 Rails

To decrypt the ciphertext:
1. Rebuild the list of row assignments for each position $0 \dots L-1$.
2. Count how many characters were written to each rail.
3. Slice the ciphertext string into $N$ substrings corresponding to the counts of each rail.
4. Traverse the original index sequence $i = 0 \dots L-1$ and pop the next character from the respective rail substring.

Applying this process with $N = 5$ rails yields:

$$\text{Ciphertext} \longrightarrow \text{PCT\{d35ert\_cipher\_ciph3r\_ch17r4l\_942\}}$$

**Next step:** present the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 solver script (`zigzag_solve.py`):

```python
#!/usr/bin/env python3
"""
Khunjerab Zigzag Solver
Challenge: "Up and down, like the road through the Khunjerab pass."

Vulnerability / Analysis:
The challenge presents a transposition ciphertext stored in `zigzag.txt`:
  Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}

The description hint ("Up and down") refers to the classic Rail Fence (Zigzag) Cipher.
Characters of the plaintext are written diagonally down and up across `N` horizontal rails,
and then concatenated row by row to form the ciphertext.

By iterating potential rail counts (from 2 to 10), decoding with 5 rails reconstructs
the original flag plaintext:
  PCT{d35ert_cipher_ciph3r_ch17r4l_942}
"""

import sys

def rail_fence_decode(ciphertext, rails):
    """
    Decryption function for Rail Fence Cipher with specified rail count.
    Rebuilds the zigzag index sequence and maps ciphertext characters back to their original positions.
    """
    # Create the repeating rail pattern (e.g. for 5 rails: 0, 1, 2, 3, 4, 3, 2, 1)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    
    # Generate rail assignment for each position in the ciphertext length
    rows = [pattern[i % len(pattern)] for i in range(len(ciphertext))]
    
    # Count how many characters belong to each rail
    counts = [rows.count(r) for r in range(rails)]
    
    # Split ciphertext into per-rail chunks
    rail_data = []
    pos = 0
    for count in counts:
        rail_data.append(list(ciphertext[pos:pos + count]))
        pos += count
        
    # Traverse the original zigzag path and pick characters from corresponding rail chunks
    plaintext = []
    for rail in rows:
        plaintext.append(rail_data[rail].pop(0))
        
    return "".join(plaintext)

def solve():
    ciphertext = "Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}"
    print(f"[*] Input Ciphertext: {ciphertext}")
    print("[*] Testing Rail Fence rail counts (2..10)...")

    target_flag = None
    for rails in range(2, 10):
        result = rail_fence_decode(ciphertext, rails)
        print(f"    Rails {rails:2d}: {result}")
        if result.startswith("PCT{"):
            target_flag = result

    if target_flag:
        print(f"\n==========================================")
        print(f"  FLAG: {target_flag}")
        print(f"==========================================")
    else:
        print("[-] Flag format PCT{...} not found.")

if __name__ == '__main__':
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python zigzag_solve.py
```

### Execution Output:

```text
[*] Input Ciphertext: Prr__Cete_rcl9T5_hc3h44{3cpih1r2dip7}
[*] Testing Rail Fence rail counts (2..10)...
    Rails  2: P3rhr4_4_{C3ectpei_hr1crl29dTi5p_7h}c
    Rails  3: Prhcrl19rTr5__2h_cd3Chi4e4p{t37cep}i_
    Rails  4: Pt32her_4d4rrc{i3l_9cppT_5i7h_Ch1}rce
    Rails  5: PCT{d35ert_cipher_ciph3r_ch17r4l_942}
    Rails  6: P_cccip3lCre9hiph4Ttre5417r{___rh32}d
    Rails  7: P_r_4hp1{hcCrelc3r72c39treThpd}ii45__
    Rails  8: P_e9c{hp133T__rCr5hcr72p4_certlh4id}i
    Rails  9: P_e9c{i27dh33T__rCr5hc1i}prp4_certlh4

==========================================
  FLAG: PCT{d35ert_cipher_ciph3r_ch17r4l_942}
==========================================
```

**Next step:** review common mistakes when analyzing transposition ciphers.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Assuming substitution cipher | Frequency analysis or frequency mapping fails because bytes were unchanged | Notice preserved flag characters (`P`, `C`, `T`, `{`, `}`) and test transposition |
| Omitting spaces or underscores | Shifted character counts corrupt the zigzag rail alignment | Include all characters (`_`, `{`, `}`) in length calculation |
| Testing incorrect rail range | Stopping at $N = 3$ or $N = 4$ misses the true solution | Test rail counts $N \in [2, 15]$ systematically |

---

## 8. What Made the Challenge Solvable?

1. **Clear Textual Clue:** "Up and down" specifically indicated the zigzag trajectory of the Rail Fence cipher.
2. **Preserved Flag Alphabet:** Characters were only transposed, leaving `PCT{` recognisable upon correct alignment.
3. **Small Key Space:** Brute-forcing the number of rails ($N \in [2, 10]$) takes less than 1 millisecond.

---

## Final Flag

```text
PCT{d35ert_cipher_ciph3r_ch17r4l_942}
```
