# Audio Notes — Detailed Forensics Write-up

**Category:** Forensics / Audio Metadata Extraction  
**Category Value:** 275 points  
**Provided file:** `recording.wav`  
**Flag format:** `PCT{...}`

> A recording with some tags attached. Read them.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{w4v_t4gs_t3ll_st0r13s}
```

The challenge provides a WAV audio file named `recording.wav` (32,090 bytes). The description hint **"A recording with some tags attached. Read them."** points directly to **Audio Metadata Tags**.

In multimedia container formats such as WAV (RIFF format), metadata tags (Title, Artist, Comment, Software) are stored inside optional metadata chunks appended to the binary stream.

The investigation workflow follows a logical sequence:

1. Inspect `recording.wav` container chunks using binary analysis / Python regex.
2. Locate the RIFF `LIST` metadata chunk appended at offset 32,044.
3. Parse the `INFO` subchunk containing the `ICMT` (Comments) metadata tag.
4. Extract the ASCII payload stored inside the `ICMT` tag: `PCT{w4v_t4gs_t3ll_st0r13s}`.

**Next step:** analyze the WAV file chunk structure.

---

## 2. Initial inspection & RIFF file structure analysis

Inspecting `recording.wav` binary headers:

- **File Signature:** `RIFF` (Bytes 0..3: `52 49 46 46`)
- **Format:** `WAVE` (Bytes 8..11: `57 41 56 45`)
- **Audio Chunk:** `fmt ` chunk followed by raw PCM audio sample `data` chunk.
- **Metadata Chunk:** `LIST` chunk appended after audio samples at offset 32,044.

### Hex Breakdown of Metadata Chunk (`0x7D2C` / offset 32,044):

```text
Offset    Hex Bytes                                          ASCII Equivalent
00032044  4c 49 53 54 26 00 00 00 49 4e 46 4f 49 43 4d 54  LIST&...INFOICMT
00032060  1a 00 00 00 50 43 54 7b 77 34 76 5f 74 34 67 73  ....PCT{w4v_t4gs
00032076  5f 74 33 6c 6c 5f 73 74 30 72 31 33 73 7d        _t3ll_st0r13s}
```

**Next step:** formulate the RIFF metadata chunk specification.

---

## 3. Vulnerability analysis: RIFF `LIST-INFO` Metadata Tags

The Resource Interchange File Format (RIFF) specification defines an `INFO` list chunk containing standardized four-character subchunk identifiers:

- `INAM`: Track Title
- `IART`: Artist / Performer
- `ICRD`: Creation Date
- `ICMT`: General Comments / Notes

In `recording.wav`, the author embedded the flag inside the `ICMT` comment subchunk:

$$\text{LIST Subchunk} = \texttt{"INFO"} + \texttt{"ICMT"} + \text{Length (26 bytes)} + \texttt{"PCT\{w4v\_t4gs\_t3ll\_st0r13s\}"}$$

Because audio playback software processes only the `fmt ` and `data` chunks for playback, metadata tags remain invisible during normal audio listening but are easily read by inspecting file metadata.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Metadata Extraction Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Offset Range} & \text{Chunk Identifier} & \text{Payload Content} & \text{Semantic Meaning} \\
\hline
\text{0x00 .. 0x03} & \texttt{RIFF} & \text{Header Preamble} & \text{RIFF File Container} \\
\text{0x2C .. 0x7D2B} & \texttt{data} & \text{PCM Audio Samples} & \text{Audio Signal Data} \\
\text{0x7D2C .. 0x7D37} & \texttt{LIST} / \texttt{INFO} & \text{Metadata Container} & \text{RIFF INFO List} \\
\text{0x7D34 .. 0x7D51} & \texttt{ICMT} & \texttt{PCT\{w4v\_t4gs\_t3ll\_st0r13s\}} & \mathbf{\text{Comment Tag Payload}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`audio_notes_solve.py`):

```python
#!/usr/bin/env python3
"""
Audio Notes Solver
Challenge: "A recording with some tags attached. Read them."

Vulnerability / Analysis:
1. `recording.wav` is a WAV audio file containing RIFF LIST-INFO metadata at the end of the file (offset 32,044).
2. The description hint ("tags attached. Read them.") points to metadata tags (such as ID3 or RIFF INFO tags).
3. Parsing the `ICMT` (Comments) metadata subchunk inside the RIFF `LIST` chunk reveals the flag string:
   PCT{w4v_t4gs_t3ll_st0r13s}
"""

import os
import re

def solve():
    base_dir = os.path.dirname(__file__)
    wav_path = os.path.join(base_dir, "recording.wav")

    if not os.path.exists(wav_path):
        print(f"[-] Input file not found: {wav_path}")
        return None

    with open(wav_path, "rb") as f:
        data = f.read()

    print(f"[*] Loaded {wav_path} ({len(data)} bytes)")

    # Locate RIFF LIST INFO chunk
    list_offset = data.find(b"LIST")
    if list_offset != -1:
        print(f"[+] Found RIFF LIST metadata chunk at byte offset {list_offset}")
        list_chunk = data[list_offset:]
        print(f"    Raw LIST chunk header: {list_chunk[:16]}")

    # Extract flag matching PCT{...}
    match = re.search(rb"PCT\{[^\}]+\}", data)
    if match:
        flag = match.group(0).decode("ascii")
        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
        return flag
    else:
        print("[-] Flag format PCT{...} not found in metadata tags.")
        return None

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python audio_notes_solve.py
```

### Execution Output:

```text
[*] Loaded 1. ctf/TODAY\recording.wav (32090 bytes)
[+] Found RIFF LIST metadata chunk at byte offset 32044
    Raw LIST chunk header: b'LIST&\x00\x00\x00INFOICMT'

==========================================
  FLAG: PCT{w4v_t4gs_t3ll_st0r13s}
==========================================
```

**Next step:** review common mistakes when analyzing audio metadata.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Playing the audio expecting acoustic DTMF or Morse tones | No flag audible in acoustic channel | Check file headers and metadata tags first |
| Stripping metadata during audio re-encoding | Erasing `LIST-INFO` chunk payload | Inspect raw binary file or use `exiftool` / Python binary parsing |
| Missing trailing metadata chunks | Overlooking data after `data` audio chunk | Search entire file bytes for `LIST` or `ID3` headers |

---

## 8. What Made the Challenge Solvable?

1. **Clear Hint:** "recording with some tags attached. Read them" explicitly indicated audio metadata.
2. **Standard Container Format:** RIFF WAVE `LIST-INFO` `ICMT` tag standard format.
3. **Plaintext Storage:** Payload stored as unencrypted ASCII string inside the comment subchunk.

---

## Final Flag

```text
PCT{w4v_t4gs_t3ll_st0r13s}
```
