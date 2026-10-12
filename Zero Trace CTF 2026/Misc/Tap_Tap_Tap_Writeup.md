# Tap Tap Tap — Detailed Cryptography Write-up

**Category:** Cryptography / Classical Ciphers  
**Category Value:** 120 points  
**Provided file:** `message (1).txt`  
**Flag format:** `PCT{...}`

> Telegraph from the Khyber outpost. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{hunza_cha1_chai_rad4r_sukkur_fd2}
```

The challenge provides a text file `message (1).txt` containing a single line of space-separated dots (`.`) and dashes (`-`).

The title **"Tap Tap Tap"** and description hint **"Telegraph"** refer directly to **International Morse Code**, a transmission protocol that encodes textual characters as sequences of short (dots) and long (dashes) audio/visual signals.

The investigation workflow follows a logical sequence:

1. Open `message (1).txt` and inspect the space-separated signal tokens.
2. Recognize the non-standard extension token `..--.-` as the Morse code representation for the underscore symbol (`_`).
3. Translate each space-separated token into its corresponding ASCII character.
4. Join the decoded characters to construct the plaintext message string: `HUNZA_CHA1_CHAI_RAD4R_SUKKUR_FD2`.
5. Convert the text to lowercase and format inside `PCT{...}` to obtain the flag.

**Next step:** analyze the input tokens and character mappings.

---

## 2. Initial inspection & Signal analysis

Opening `message (1).txt` yields the following raw string:

```text
.... ..- -. --.. .- ..--.- -.-. .... .- .---- ..--.- -.-. .... .- .. ..--.- .-. .- -.. ....- .-. ..--.- ... ..- -.- -.- ..- .-. ..--.- ..-. -.. ..---
```

### Key Observations
1. **Signal Format:** Binary pulse encoding consisting of dots (`.`) and dashes (`-`).
2. **Delimiters:** Tokens are separated by single spaces (` `), denoting individual character boundaries.
3. **Punctuation Token:** `..--.-` represents the underscore character (`_`).

**Next step:** formulate the Morse code translation table.

---

## 3. Vulnerability analysis: International Morse Code Translation

International Morse Code maps alphanumeric characters to unique variable-length dot-dash combinations.

### Token Mapping Breakdown

$$\begin{array}{|c|l|c||c|l|c|}
\hline
\text{Token} & \text{Morse Signal} & \text{Character} & \text{Token} & \text{Morse Signal} & \text{Character} \\
\hline
1 & \texttt{....} & \mathbf{H} & 17 & \texttt{.-.} & \mathbf{R} \\
2 & \texttt{..-} & \mathbf{U} & 18 & \texttt{.-} & \mathbf{A} \\
3 & \texttt{-.} & \mathbf{N} & 19 & \texttt{-..} & \mathbf{D} \\
4 & \texttt{--..} & \mathbf{Z} & 20 & \texttt{....-} & \mathbf{4} \\
5 & \texttt{.-} & \mathbf{A} & 21 & \texttt{.-.} & \mathbf{R} \\
6 & \texttt{..--.-} & \mathbf{\_} & 22 & \texttt{..--.-} & \mathbf{\_} \\
7 & \texttt{-.-.} & \mathbf{C} & 23 & \texttt{...} & \mathbf{S} \\
8 & \texttt{....} & \mathbf{H} & 24 & \texttt{..-} & \mathbf{U} \\
9 & \texttt{.-} & \mathbf{A} & 25 & \texttt{-.-} & \mathbf{K} \\
10 & \texttt{.----} & \mathbf{1} & 26 & \texttt{-.-} & \mathbf{K} \\
11 & \texttt{..--.-} & \mathbf{\_} & 27 & \texttt{..-} & \mathbf{U} \\
12 & \texttt{-.-.} & \mathbf{C} & 28 & \texttt{.-.} & \mathbf{R} \\
13 & \texttt{....} & \mathbf{H} & 29 & \texttt{..--.-} & \mathbf{\_} \\
14 & \texttt{.-} & \mathbf{A} & 30 & \texttt{..-.} & \mathbf{F} \\
15 & \texttt{..} & \mathbf{I} & 31 & \texttt{-..} & \mathbf{D} \\
16 & \texttt{..--.-} & \mathbf{\_} & 32 & \texttt{..---} & \mathbf{2} \\
\hline
\end{array}$$

Concatenating all decoded tokens produces:

$$\text{Plaintext} \longrightarrow \text{HUNZA\_CHA1\_CHAI\_RAD4R\_SUKKUR\_FD2}$$

Lowercasing and wrapping in `PCT{...}` yields `PCT{hunza_cha1_chai_rad4r_sukkur_fd2}`.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Morse Code Decoding Procedure

To decode the payload:
1. Split the raw text file string by spaces to isolate individual character tokens.
2. Look up each token in a standard International Morse Code dictionary.
3. Handle numbers (`.----` = 1, `....-` = 4, `..---` = 2) and underscores (`..--.-` = `_`).
4. Reassemble the decoded character array into the final flag string.

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`tap_tap_tap_solve.py`):

```python
#!/usr/bin/env python3
"""
Tap Tap Tap Solver
Challenge: "Telegraph from the Khyber outpost."

Vulnerability / Analysis:
1. The file `message (1).txt` contains space-separated Morse code signals (`.`, `-`).
2. The description hints ("Tap Tap Tap", "Telegraph") refer to International Morse Code.
3. `..--.-` represents the underscore character (`_`).
4. Parsing and translating the signals yields:
   HUNZA_CHA1_CHAI_RAD4R_SUKKUR_FD2
5. Formatting to lowercase within `PCT{...}` recovers the flag:
   PCT{hunza_cha1_chai_rad4r_sukkur_fd2}
"""

import os

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '..--.-': '_', '.-.-.-': '.', '--..--': ',', '..--..': '?'
}

def solve():
    base_dir = os.path.dirname(__file__)
    msg_path = os.path.join(base_dir, "message (1).txt")

    if not os.path.exists(msg_path):
        print(f"[-] Input file not found: {msg_path}")
        return None

    with open(msg_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    print(f"[*] Raw Morse Code Input:\n{content}\n")

    tokens = content.split()
    decoded_letters = []

    for token in tokens:
        if token in MORSE_CODE_DICT:
            decoded_letters.append(MORSE_CODE_DICT[token])
        else:
            print(f"[!] Warning: Unknown token '{token}'")
            decoded_letters.append(token)

    decoded_text = "".join(decoded_letters)
    print(f"[+] Decoded Text: {decoded_text}")

    flag = f"PCT{{{decoded_text.lower()}}}"
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
$ python tap_tap_tap_solve.py
```

### Execution Output:

```text
[*] Raw Morse Code Input:
.... ..- -. --.. .- ..--.- -.-. .... .- .---- ..--.- -.-. .... .- .. ..--.- .-. .- -.. ....- .-. ..--.- ... ..- -.- -.- ..- .-. ..--.- ..-. -.. ..---

[+] Decoded Text: HUNZA_CHA1_CHAI_RAD4R_SUKKUR_FD2

==========================================
  FLAG: PCT{hunza_cha1_chai_rad4r_sukkur_fd2}
==========================================
```

**Next step:** review potential pitfalls when translating Morse code signals.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Confusing `C` (`-.-.`) and `K` (`-.-`) | Misspelling words (e.g. `CHA1` vs `KHA1`) | Match dot/dash length exactly against standard lookup dictionary |
| Missing underscore symbol (`..--.-`) | Words run together without delimiters | Include non-alphanumeric Morse punctuation rules in lookup table |
| Forgetting to lowercase string | Flag format rejection | Convert output string to lowercase before wrapping in `PCT{...}` |

---

## 8. What Made the Challenge Solvable?

1. **Clear Textual Clues:** "Tap Tap Tap" and "Telegraph" directly indicated Morse code.
2. **Explicit Delimiters:** Spaces between tokens allowed unambiguous character boundary isolation.
3. **Standard Encoding:** Standard International Morse alphabet with standard underscore representation.

---

## Final Flag

```text
PCT{hunza_cha1_chai_rad4r_sukkur_fd2}
```
