# Russian Dolls — Detailed Forensics Write-up

**Category:** Forensics / Archive Decompression  
**Category Value:** 180 points  
**Provided file:** `dolls.zip`  
**Flag format:** `PCT{...}`

> An archive within an archive within an archive.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{unz1p_1t_thr33_t1m3s}
```

The challenge provides a ZIP archive named `dolls.zip` (606 bytes). The title **"Russian Dolls"** and description hint **"An archive within an archive within an archive"** refer to a Matryoshka-style nested archive hierarchy.

The investigation workflow follows a logical sequence:

1. Unpack `dolls.zip` to obtain `layer1.zip` and `readme.txt`.
2. Unpack `layer1.zip` to obtain `layer2.zip` and `readme.txt`.
3. Unpack `layer2.zip` to obtain `flag.txt`.
4. Read `flag.txt` to recover the flag: `PCT{unz1p_1t_thr33_t1m3s}`.

**Next step:** analyze the archive layer structure.

---

## 2. Initial inspection & Archive structure analysis

We begin with `dolls.zip` (606 bytes).

### Archive Traversal Hierarchy:

- **Level 0 (`dolls.zip`):** Contains `layer1.zip` and `readme.txt`.
- **Level 1 (`layer1.zip`):** Contains `layer2.zip` and `readme.txt`.
- **Level 2 (`layer2.zip`):** Contains `flag.txt`.

Unpacking exactly 3 layers reaches the core plaintext document `flag.txt`.

**Next step:** formulate the recursive extraction model.

---

## 3. Vulnerability analysis: Recursive Archive Decompression

Nested archives (zip bombs or matryoshka archives) use repeated compression to obscure internal files or test automated extraction scripts.

Because no encryption passwords were set on any layer, an automated loop recursively unzips each archive layer until a non-archive text file (`flag.txt`) is reached.

$$\text{dolls.zip} \xrightarrow{\text{Unzip 1}} \text{layer1.zip} \xrightarrow{\text{Unzip 2}} \text{layer2.zip} \xrightarrow{\text{Unzip 3}} \text{flag.txt} \longrightarrow \mathbf{\text{PCT\{unz1p\_1t\_thr33\_t1m3s\}}}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Archive Extraction Breakdown

$$\begin{array}{|c|l|l|l|}
\hline
\text{Layer} & \text{Input Archive} & \text{Extracted Artifacts} & \text{Status} \\
\hline
0 & \text{dolls.zip} & \text{layer1.zip, readme.txt} & \text{Next layer found} \\
1 & \text{layer1.zip} & \text{layer2.zip, readme.txt} & \text{Next layer found} \\
2 & \text{layer2.zip} & \text{flag.txt} & \mathbf{\text{Core Flag Found}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`russian_dolls_solve.py`):

```python
#!/usr/bin/env python3
"""
Russian Dolls Solver
Challenge: "An archive within an archive within an archive."

Vulnerability / Analysis:
1. `dolls.zip` is a nested ZIP archive (Russian Matryoshka doll structure).
2. Layer 0 (`dolls.zip`): Contains `layer1.zip` and `readme.txt`.
3. Layer 1 (`layer1.zip`): Contains `layer2.zip` and `readme.txt`.
4. Layer 2 (`layer2.zip`): Contains `flag.txt`.
5. Unpacking 3 layers reveals `flag.txt`:
   PCT{unz1p_1t_thr33_t1m3s}
"""

import os
import zipfile

def solve():
    base_dir = os.path.dirname(__file__)
    curr_archive = os.path.join(base_dir, "dolls.zip")
    extract_base = os.path.join(base_dir, "extracted_dolls")

    if not os.path.exists(curr_archive):
        print(f"[-] Input file not found: {curr_archive}")
        return None

    layer = 0
    flag = None
    visited = set()

    while zipfile.is_zipfile(curr_archive) and curr_archive not in visited:
        visited.add(curr_archive)
        print(f"[*] Step {layer}: Unpacking {os.path.basename(curr_archive)}...")

        target_dir = os.path.join(extract_base, f"layer_{layer}")
        os.makedirs(target_dir, exist_ok=True)

        with zipfile.ZipFile(curr_archive, "r") as zf:
            zf.extractall(target_dir)
            files = zf.namelist()
            print(f"    Extracted files: {files}")

            if "flag.txt" in files:
                flag_path = os.path.join(target_dir, "flag.txt")
                with open(flag_path, "r", encoding="utf-8", errors="ignore") as f:
                    flag = f.read().strip()
                print(f"[+] Reached core layer with flag.txt!")
                break
            else:
                next_zips = [os.path.join(target_dir, f) for f in files if f.endswith(".zip")]
                if next_zips:
                    curr_archive = next_zips[0]
                else:
                    print("[-] No further nested zip archives found.")
                    break

        layer += 1

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
$ python russian_dolls_solve.py
```

### Execution Output:

```text
[*] Step 0: Unpacking dolls.zip...
    Extracted files: ['layer1.zip', 'readme.txt']
[*] Step 1: Unpacking layer1.zip...
    Extracted files: ['layer2.zip', 'readme.txt']
[*] Step 2: Unpacking layer2.zip...
    Extracted files: ['flag.txt']
[+] Reached core layer with flag.txt!

==========================================
  FLAG: PCT{unz1p_1t_thr33_t1m3s}
==========================================
```

**Next step:** review potential pitfalls when automating archive decompression.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Unbounded loop without visited tracking | Infinite recursion loop if zip references previously extracted folder | Keep track of visited file paths (`visited.add(path)`) |
| Stopping at `layer1.zip` | Assuming single-layer extraction | Check for nested archives inside extracted output directories |

---

## 8. What Made the Challenge Solvable?

1. **Clear Metaphor:** Description "archive within an archive within an archive" specified matryoshka nesting.
2. **Unencrypted Archives:** No password protection was applied to any layer.
3. **Small Depth:** Only 3 layers deep, extracting in less than 1 millisecond.

---

## Final Flag

```text
PCT{unz1p_1t_thr33_t1m3s}
```
