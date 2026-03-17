# Zippy
---
**Category:** Forensics  
**Points:** 75  
**Difficulty:** Easy  
**Author:** VBD

## Challenge Description

> How much data is lost during compression? dont keep the lock and key at the same place

**Challenge File:** `locked_files.rar` (357 bytes)

## Solution

### Step 1: Initial Analysis

The challenge provides a small RAR archive (357 bytes). Examining the hex dump reveals interesting structure:

```
00000120: 00 03 53 54 4D 10 07 3A 66 6F 72 67 6F 74 70 61  ..STM..:forgotpa
00000130: 73 73 77 6F 72 64 C4 BA 24 44 03 23 F8 40 42 52  sswordÃ„Âº$D.#Ã¸@BR
```

Key observations:
- `STM` marker indicates an **NTFS Alternate Data Stream** in RAR5 format
- Stream name: `:forgotpassword`
- The RAR contains `locked_files.zip`

### Step 2: Extracting the RAR

The hint "dont keep the lock and key at the same place" suggests the password is hidden somewhere in the archive itself.

Trying `forgotpassword` as the RAR password:

```bash
7z x -pforgotpassword locked_files.rar
```

**Success!** Extracts `locked_files.zip` which is **AES-256 encrypted**.

### Step 3: Finding the ZIP Password

The key insight comes from the hint "How much data is lost during compression?"

- ZIP uses **lossless Deflate** compression - no data is lost in the compressed content
- But RAR on NTFS can store **Alternate Data Streams** (ADS), which are invisible in normal extraction on Linux

Extracting on Windows with 7-Zip shows:
```
Alternate Streams: 1
Alternate Streams Size: 32
```

### Step 4: Reading the Alternate Data Stream

On Windows, checking the NTFS streams:

```powershell
Get-Item locked_files.zip -Stream *
```

Output:
```
Stream         Length
------         ------
:$DATA            203
forgotpassword     32
```

Reading the hidden stream:

```powershell
Get-Content -Path locked_files.zip -Stream forgotpassword
```

Output:
```
8d364896e034aabe3fc9fd2e05fb1cbe
```

### Step 5: Final Extraction

Using the discovered password:

```bash
7z x -p8d364896e034aabe3fc9fd2e05fb1cbe locked_files.zip
```

**Flag:** `VBD{c99a11a53a3748269e3f86d7ac38df11}`

## Key Takeaways

1. **RAR5 format** can store NTFS Alternate Data Streams
2. **ADS are invisible** when extracting on Linux or non-NTFS filesystems
3. The hint "lock and key at the same place" = password stored in the same archive as an ADS
4. "Data lost during compression" = nothing is lost in the main content, but ADS data is "lost" on non-Windows extraction
5. Always extract RAR archives on Windows/NTFS when dealing with potential ADS

## Tools Used

- 7-Zip for extraction with ADS support
- PowerShell `Get-Item -Stream` and `Get-Content -Stream` for ADS access
- `xxd`/`Format-Hex` for hex analysis
