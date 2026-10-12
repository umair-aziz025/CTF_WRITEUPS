# Lock Inside Lock — Detailed Forensics & Cryptography Write-up

**Category:** Forensics / Password Cracking  
**Category Value:** 310 points  
**Provided files:** `outer.zip`, `wordlist.txt`  
**Flag format:** `PCT{...}`

> A lock inside a lock. Download the file(s), work out what was done to the flag, and undo it. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{53n7inel_minar37_ironw4ll_da17e5}
```

The challenge presents a double-encrypted nested ZIP archive `outer.zip` alongside a dictionary wordlist `wordlist.txt` containing 30 candidate passwords.

The investigation workflow follows a logical sequence:

1. Perform a dictionary attack against `outer.zip` using the candidates in `wordlist.txt`.
2. Discover the valid password for `outer.zip`: `patch`.
3. Extract `outer.zip` to obtain `inner.zip` and `hint.txt`.
4. Read `hint.txt` to discover the rule for the inner layer password: `"second password = first password, reversed, in CAPITAL letters."`
5. Apply the string transformation on `patch` to derive the inner password: $\text{reverse}(\text{"patch"}) \rightarrow \text{"hctap"} \rightarrow \text{upper}() \rightarrow \text{"HCTAP"}$.
6. Extract `inner.zip` using `HCTAP` to obtain `flag.txt` and read the flag.

**Next step:** analyze the input files and archive properties.

---

## 2. Initial inspection & Archive structure analysis

We are given two files:
- `outer.zip`: 656 bytes PKZIP archive.
- `wordlist.txt`: 212 bytes plain-text wordlist with 30 candidate words.

### Wordlist Contents (`wordlist.txt`):
```text
mehran, patch, minaret, packet, watchtower, skardu, chai, quetta,
monsoon, shadow, beacon, shaheen, vault, gwadar, anchor, kebab,
taxila, fortress, signal, falcon, mirage, chitral, ghazi, radar,
hunza, rohtas, relay, desert, lassi, sentinel
```

**Next step:** execute dictionary attack on the outer archive.

---

## 3. Vulnerability analysis: Dictionary Attack & Password Transformation

### Layer 1: Outer ZIP Cracking
Iterating through each line of `wordlist.txt` as a decryption key for `outer.zip` tests candidate passwords against standard PKZIP encryption headers.

Password entry #2 `patch` successfully unlocks `outer.zip`.

### Layer 2: Inner ZIP Password Derivation
Inspecting `hint.txt` reveals:
```text
second password = first password, reversed, in CAPITAL letters.
```

Mathematically, let $P_1 = \text{"patch"}$. The second key $P_2$ is defined by:

$$P_2 = \text{upper}\left( \text{reverse}(P_1) \right) = \text{upper}(\text{"hctap"}) = \text{"HCTAP"}$$

Using `HCTAP` unlocks `inner.zip` and exposes `flag.txt`.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Extraction Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Stage} & \text{Target Archive} & \text{Key / Method} & \text{Extracted Artifacts} \\
\hline
1 & \text{outer.zip} & \text{Dictionary Attack } (\texttt{wordlist.txt}) \rightarrow \text{"patch"} & \text{inner.zip, hint.txt} \\
2 & \text{hint.txt} & \text{Plaintext Inspection} & \text{"second password = first password, reversed..."} \\
3 & \text{inner.zip} & \text{String Transformation } (\text{"patch"} \rightarrow \text{"HCTAP"}) & \text{flag.txt} \\
4 & \text{flag.txt} & \text{Plaintext Reading} & \text{PCT\{53n7inel\_minar37\_ironw4ll\_da17e5\}} \\
\hline
\end{array}$$

**Next step:** write and execute the Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`lock_inside_lock_solve.py`):

```python
#!/usr/bin/env python3
"""
Lock Inside Lock Solver
Challenge: "A lock inside a lock."

Vulnerability / Analysis:
1. `outer.zip` is protected with a password from `wordlist.txt`.
2. Dictionary attack on `outer.zip` yields the password: `patch`.
3. Extracting `outer.zip` produces two files: `inner.zip` and `hint.txt`.
4. `hint.txt` contains: "second password = first password, reversed, in CAPITAL letters."
5. Reversing `patch` gives `hctap`, and converting to uppercase gives `HCTAP`.
6. Unzipping `inner.zip` using `HCTAP` reveals `flag.txt`:
   PCT{53n7inel_minar37_ironw4ll_da17e5}
"""

import os
import zipfile

def solve():
    base_dir = os.path.dirname(__file__)
    outer_zip_path = os.path.join(base_dir, "outer.zip")
    wordlist_path = os.path.join(base_dir, "wordlist.txt")
    extract_dir = os.path.join(base_dir, "extracted")
    
    os.makedirs(extract_dir, exist_ok=True)

    print(f"[*] Step 1: Loading wordlist from {wordlist_path}...")
    with open(wordlist_path, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} candidate passwords.")
    print(f"[*] Step 2: Attempting dictionary attack on {outer_zip_path}...")
    
    outer_pwd = None
    with zipfile.ZipFile(outer_zip_path, "r") as zf:
        for pwd in passwords:
            try:
                zf.extractall(path=extract_dir, pwd=pwd.encode("utf-8"))
                outer_pwd = pwd
                print(f"[+] Outer ZIP cracked! Password: '{outer_pwd}'")
                break
            except Exception:
                continue

    if not outer_pwd:
        print("[-] Failed to crack outer.zip with wordlist.")
        return None

    # Inspect hint.txt
    hint_path = os.path.join(extract_dir, "hint.txt")
    if os.path.exists(hint_path):
        with open(hint_path, "r", encoding="utf-8") as f:
            hint_text = f.read().strip()
        print(f"[*] Step 3: Extracted hint: '{hint_text}'")

    # Deriving inner password
    inner_pwd = outer_pwd[::-1].upper()
    print(f"[*] Step 4: Derived inner password (reversed & capitalized): '{inner_pwd}'")

    inner_zip_path = os.path.join(extract_dir, "inner.zip")
    inner_extract_dir = os.path.join(extract_dir, "inner")
    
    print(f"[*] Step 5: Extracting {inner_zip_path} with password '{inner_pwd}'...")
    with zipfile.ZipFile(inner_zip_path, "r") as zf:
        zf.extractall(path=inner_extract_dir, pwd=inner_pwd.encode("utf-8"))

    flag_path = os.path.join(inner_extract_dir, "flag.txt")
    with open(flag_path, "r", encoding="utf-8") as f:
        flag = f.read().strip()

    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify execution output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python lock_inside_lock_solve.py
```

### Execution Output:

```text
[*] Step 1: Loading wordlist from 1. ctf/TODAY\wordlist.txt...
[*] Loaded 30 candidate passwords.
[*] Step 2: Attempting dictionary attack on 1. ctf/TODAY\outer.zip...
[+] Outer ZIP cracked! Password: 'patch'
[*] Step 3: Extracted hint: 'second password = first password, reversed, in CAPITAL letters.'
[*] Step 4: Derived inner password (reversed & capitalized): 'HCTAP'
[*] Step 5: Extracting 1. ctf/TODAY\extracted\inner.zip with password 'HCTAP'...

==========================================
  FLAG: PCT{53n7inel_minar37_ironw4ll_da17e5}
==========================================
```

**Next step:** review potential pitfalls when cracking nested archives.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Encoding password as ASCII string instead of `bytes` | `TypeError` or failed decryption in Python `zipfile` | Use `pwd.encode('utf-8')` |
| Overlooking string reversal order | Keying `PATCH` instead of `HCTAP` fails `inner.zip` extraction | Reverse the string first (`hctap`), then apply uppercase (`HCTAP`) |
| Manually trying all 30 words | Slow and error-prone process | Automate dictionary testing using Python `zipfile` |

---

## 8. What Made the Challenge Solvable?

1. **Small Wordlist Key Space:** Only 30 candidates, allowing sub-millisecond dictionary testing.
2. **Explicit Password Rule Hint:** Clear text transformation instructions inside `hint.txt`.
3. **Standard PKZIP Format:** Compatible with Python's built-in `zipfile` module.

---

## Final Flag

```text
PCT{53n7inel_minar37_ironw4ll_da17e5}
```
