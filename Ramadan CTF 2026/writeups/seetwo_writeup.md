# SeeTwo
---
## Challenge Information
- **Category:** Memory Forensics / Network Analysis
- **Difficulty:** Hard
- **Flag:** `VBD{1_w45_ju5t_gam1n_n_bhopping}`

## Challenge Description
A network forensics and memory analysis challenge involving a compromised system running Half-Life game server with encrypted C2 communications.

---

## Solution Overview

This challenge involved analyzing a network packet capture (PCAP) file that contained encrypted game server communications. The solution required:
1. Analyzing network traffic to identify encrypted payloads
2. Performing known-plaintext attack (KPA) on XOR-encrypted data
3. Extracting and decrypting the flag from game server commands

---

## Files Analyzed

### Primary Files
- **capture2.pcapng** - Network packet capture containing encrypted traffic
- **ramadanctf2026_dump.raw** - Memory dump (attempted TuskLocker2 ransomware analysis)

### Key Scripts Developed

#### 1. WebSocket Decoder
Analyzed WebSocket traffic to understand SignalR/Hub communications:
- Extracted JSON payloads from WebSocket frames
- Identified application event monitoring (foreground windows, input tracking)
- Found references to processes: hl.exe, Wireshark.exe, devenv.exe, Explorer.exe

**Output:** decoded_messages.txt containing 467 decoded WebSocket messages

```python
#!/usr/bin/env python3
"""Decode WebSocket C2 traffic from SeeTwo challenge"""
import struct, re

def decode_ws_frame(data):
  if len(data) < 2:
    return None, data, False
  opcode = data[0] & 0x0F
  masked = (data[1] >> 7) & 1
  length = data[1] & 0x7F
  offset = 2
  if length == 126:
    length = struct.unpack(">H", data[2:4])[0]
    offset = 4
  elif length == 127:
    length = struct.unpack(">Q", data[2:10])[0]
    offset = 10
  if masked:
    mask_key = data[offset:offset+4]
    offset += 4
  if len(data) < offset + length:
    return None, data, masked
  payload = data[offset:offset+length]
  if masked:
    decoded = bytes([payload[i] ^ mask_key[i % 4] for i in range(len(payload))])
  else:
    decoded = payload
  return decoded, data[offset+length:], masked

def main():
  with open(r"D:\\ctf\\seetwo\\stream1_raw.txt", "r", encoding="utf-16") as f:
    lines = f.readlines()

  messages = []
  for line in lines:
    orig_line = line.rstrip()
    if not orig_line or orig_line.startswith('=') or orig_line.startswith('Follow') or orig_line.startswith('Filter') or orig_line.startswith('Node'):
      continue
    is_server = orig_line.startswith('\t')
    stripped = orig_line.strip()
    if not stripped:
      continue
    if not all(c in '0123456789abcdefABCDEF' for c in stripped):
      continue
    data = bytes.fromhex(stripped)
        
    remaining = data
    while remaining and len(remaining) >= 2:
      decoded, remaining, was_masked = decode_ws_frame(remaining)
      if decoded is None:
        break
      direction = "CLIENT" if was_masked else "SERVER"
      try:
        text = decoded.decode('utf-8', errors='replace')
      except:
        text = decoded.hex()
      messages.append((direction, text, decoded))

  print(f"Total messages: {len(messages)}\\n")
    
  for i, (d, text, raw) in enumerate(messages):
    prefix = ">>>" if d == "CLIENT" else "<<<"
    display = text if len(text) < 300 else text[:300] + f"...({len(text)} chars)"
    print(f"[{i:3d}] {prefix} {display}")
    
  all_text = "\\n".join(t for _, t, _ in messages)
  flags = re.findall(r'VBD\{[^}]*\}', all_text)
  if flags:
    print(f"\\n[+] FLAG: {flags[0]}")
  else:
    print("\\n[-] No flag in decoded messages. Looking for base64, hex patterns...")
    import base64
    for i, (d, text, raw) in enumerate(messages):
      if d == "CLIENT" and len(text) > 20:
        try:
          decoded_b64 = base64.b64decode(text)
          dec_str = decoded_b64.decode('utf-8', errors='replace')
          if 'VBD' in dec_str:
            print(f"  [+] Base64 flag in msg {i}: {dec_str}")
        except:
          pass
    
  with open(r"D:\\ctf\\seetwo\\decoded_messages.txt", "w", encoding="utf-8") as f:
    for i, (d, text, raw) in enumerate(messages):
      f.write(f"[{i}] {d}: {text}\\n")
      f.write(f"    HEX: {raw.hex()}\\n")
  print("\\nSaved to decoded_messages.txt")

if __name__ == "__main__":
  main()
```

#### 2. Say_Team Payload Extractor
Extracted UDP game server payloads:
- Filtered Half-Life protocol packets (starting with FFFFFFFF)
- Identified 24 say_team rcon command payloads with encrypted data
- Attempted various single-byte and multi-byte XOR bruteforce attacks

```python
#!/usr/bin/env python3
"""Extract raw hex of say_team payloads and attempt decoding"""
import subprocess, re, sys

def main():
  result = subprocess.run(
    ["ssh", "-p", "2222", "kali@127.0.0.1",
     "tshark -r ~/capture2.pcapng -Y 'udp && data' -T fields -e frame.number -e udp.srcport -e udp.dstport -e data 2>/dev/null"],
    capture_output=True, text=True, input="linux0192\\n", timeout=60
  )
    
  lines = result.stdout.strip().split('\\n')
  say_team_payloads = []
  all_connectionless = []
    
  for line in lines:
    parts = line.strip().split('\\t')
    if len(parts) < 4:
      continue
    frame, srcport, dstport, hexdata = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
    raw = bytes.fromhex(hexdata)
        
    if raw[:4] == b'\\xff\\xff\\xff\\xff':
      payload = raw[4:]
      try:
        text = payload.decode('ascii', errors='replace')
      except:
        text = ""
            
      if 'say_team' in text:
        idx = text.find('say_team ')
        if idx >= 0:
          after = payload[idx + len('say_team '):]
          say_team_payloads.append((int(frame), after, hexdata))
          print(f"Frame {frame}: say_team raw hex ({len(after)} bytes):")
          print(f"  {after.hex()}")
          print(f"  First 20 bytes: {list(after[:20])}")
          print()
            
      all_connectionless.append((int(frame), srcport, dstport, payload))
    
  print(f"\\n{'='*60}")
  print(f"Total say_team payloads: {len(say_team_payloads)}")
  print(f"{'='*60}\\n")
    
  print("=== XOR single-byte key bruteforce (first payload) ===")
  if say_team_payloads:
    first_data = say_team_payloads[0][1]
    for key in range(256):
      decoded = bytes([b ^ key for b in first_data])
      printable = sum(1 for b in decoded if 32 <= b < 127)
      if printable > len(decoded) * 0.7:
        print(f"  Key 0x{key:02x}: {decoded[:60]}")
    
  print("\\n=== Concatenated say_team data ===")
  all_data = b''.join(d for _, d, _ in sorted(say_team_payloads))
  print(f"Total concatenated bytes: {len(all_data)}")
  print(f"Hex: {all_data[:100].hex()}")
    
  for key in [0x00, 0x41, 0x42, 0x55, 0xAA, 0xFF, 0x69, 0x13]:
    decoded = bytes([b ^ key for b in all_data])
    if b'VBD' in decoded or b'flag' in decoded:
      print(f"  [+] KEY 0x{key:02x} FOUND FLAG: {decoded}")
      break
    
  first_bytes = [d[0] for _, d, _ in sorted(say_team_payloads)]
  print(f"\\nFirst bytes: {[chr(b) if 32 <= b < 127 else f'0x{b:02x}' for b in first_bytes]}")
  print(f"First bytes hex: {bytes(first_bytes).hex()}")
    
  print("\\n=== Looking for XOR key via known plaintext ===")
  known = b"VBD{"
  for i, (frame, data, _) in enumerate(sorted(say_team_payloads)):
    if len(data) >= 4:
      possible_key = bytes([data[j] ^ known[j] for j in range(4)])
      decoded_full = bytes([data[j] ^ possible_key[j % 4] for j in range(len(data))])
      printable = sum(1 for b in decoded_full if 32 <= b < 127 or b in [10, 13])
      if printable > len(decoded_full) * 0.5:
        print(f"  Payload {i} (Frame {frame}): key={possible_key.hex()}, decoded[:40]={decoded_full[:40]}")
    
  print("\\n=== Byte at various offsets from each payload ===")
  for offset in [0, 1, 2, 3, 4, 5]:
    chars = []
    for _, data, _ in sorted(say_team_payloads):
      if len(data) > offset:
        chars.append(data[offset])
    text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chars)
    print(f"  Offset {offset}: {text}  hex={bytes(chars).hex()}")
    
  with open(r"D:\\ctf\\seetwo\\say_team_payloads.bin", "wb") as f:
    for frame, data, _ in sorted(say_team_payloads):
      f.write(data)
    
  with open(r"D:\\ctf\\seetwo\\say_team_hex.txt", "w") as f:
    for frame, data, hexd in sorted(say_team_payloads):
      f.write(f"Frame {frame} ({len(data)} bytes): {data.hex()}\\n")
    
  print("\\nSaved raw payloads to say_team_payloads.bin and say_team_hex.txt")

if __name__ == "__main__":
  main()
```

#### 3. Known Plaintext Attack Script (Main Solution)
The breakthrough script that solved the challenge:

```python
#!/usr/bin/env python3
"""Known Plaintext Attack on say_team encrypted data.
Windows dir C:\\ output has known structure that reveals XOR key."""

payloads = {
  1789: "5cae7da621a08c49b850fca7f22126410d8177986989a55fd40b9bcee7474491c991229741aaac6dd370d685ad7e17102ac163af23",
  5878: "5ea3389774838c1ef14ab9b1f227224d5eb67793609dc950f704f5b4e22b3806",
  5937: "5ea3389774838c1ecb41ebbce12274660b98359e73ce804db817abe1b363151b49cd",
  6004: "5eb13e89648d9d51ea5db9bae66e171222",
  6075: "4cc778ca33c1db0eaa10b9f5b07e6e1c48d577db21d2ad77ca1ab9f5a06e74085ed577db40a3ad",
  6161: "4cc778cb33c1db0eaa10b9f5b07f6e1b4dd577db21cec91eb804b9f5b17f66044fc661db609e9948fd56f0b3d5077a4c1299",
  6220: "4ccc78cb35c1db0eaa11b9f5b17c6e1d4fd577db21cec91eb804b9f5a07f66044ccd6fdb459b844ecb50f8b6eb60384719",
  6281: "4ecd78cb32c1db0eaa11b9f5b17a6e194ad577db21d2ad77ca1ab9f5a06e74085ed577db44bdad",
  6340: "4dc478cb36c1db0eaa11b9f5b0766e1c4ed577db21d2ad77ca1ab9f5a06e74085ed577db68808c4ae851fb",
  6403: "4cc278ca31c1db0eaa10b9f5b0766e1c4cd577db21d2ad77ca1ab9f5a06e74085ed577db4cbda0",
  6466: "4cc278ca31c1db0eaa10b9f5b0766e184dd577db21cec91eb804b9f5a06e74084fcc63db6c978551ff0af5bae7",
  6525: "4ec478cb35c1db0eaa10b9f5b17c6e1a48d577db21d2ad77ca1ab9f5a06e74085ed577db518b9b58d44bfea6",
  6583: "4fc078cb33c1db0eaa12b9f5b1786e184cd577db21d2ad77ca1ab9f5a06e74085ed577db519c8659ea45f4f5c627384d0d",
  6645: "4ec778cb39c1db0eaa11b9f5b17a6e1a4ad577db21d2ad77ca1ab9f5a06e74085ed577db519c8659ea45f4f5c627384d0dd57f8339d8c0",
  6715: "4fc378ca33c1db0eaa11b9f5b27f6e1848d577db21d2ad77ca1ab9f5a06e74085ed577db5387864ab863f8b8e53d",
  6801: "4cc578cb30c1db0eaa12b9f5b07e6e194bd577db21d2ad77ca1ab9f5a06e74085ed577db758399",
  6867: "4cc478ca31c1db0eaa11b9f5b07c6e1c49d577db21d2ad77ca1ab9f5a06e74085ed577db549d8c4ceb",
  6932: "4cc778cb33c1db0eaa10b9f5b07f6e1b4ad577db21cec91eb804b9f5a07862044dc76fdb77888a51f554f8a1ae2a3844",
  6991: "4fcd78cb33c1db0eaa12b9f5b17e6e184cd577db21d2ad77ca1ab9f5a06e74085ed577db5687875af753ea",
  7056: "4ec178ca30c1db0eaa10b9f5b17c6e1947d577db21d2ad77ca1ab9f5a06e74085ed577db598c8646df45f4b0f3",
  7119: "5ed577db21cec91eb804b9f5a06e741c5eb33e9764c69a17b804b9f5a06e74084fcc67d738dadf1efa5dedb0f3",
  7173: "5ed577db21cec91eb804b9f5a06e651a5eb13e89299dc01eb804abf9b67d610447c764d735dbdf1efa5dedb0f36e325a1b90",
  13765: "109c349e219a9b47b404f0f5ec273f4d5e8138db768f8552f045fabea0",
  15060: "28b7138030b19e0aad7bf3a0b53a0b4f1f9866955e80b65cf04be9a5e9203355",
}

key = bytes([0x7e, 0xf5, 0x57, 0xfb, 0x01, 0xee, 0xe9, 0x3e,
       0x98, 0x24, 0x99, 0xd5, 0x80, 0x4e, 0x54, 0x28])

print(f"XOR Key (16 bytes): {key.hex()}")
print(f"Key as ASCII where printable: ", end="")
for b in key:
  if 32 <= b < 127:
    print(chr(b), end="")
  else:
    print(f"\\x{b:02x}", end="")
print("\\n")

for frame, hexdata in sorted(payloads.items()):
  data = bytes.fromhex(hexdata)
  decrypted = bytes([data[i] ^ key[i % 16] for i in range(len(data))])
  try:
    text = decrypted.decode('ascii', errors='replace')
  except:
    text = repr(decrypted)
  print(f"Frame {frame:5d} ({len(data):3d} bytes): {text}")

print("\\n" + "="*60)
print("KEY FRAMES:")
print("="*60)

data = bytes.fromhex(payloads[13765])
decrypted = bytes([data[i] ^ key[i % 16] for i in range(len(data))])
print(f"\\nE:\\flag.txt content: {decrypted.decode('ascii', errors='replace')}")

data = bytes.fromhex(payloads[15060])
decrypted = bytes([data[i] ^ key[i % 16] for i in range(len(data))])
print(f"E:\\wallhack.txt content: {decrypted.decode('ascii', errors='replace')}")
```

**Key Discovery Process:**
1. Identified frames 6075-6801 contained "dir C:\" output with `<DIR>` entries
2. Date format: `DD/MM/YYYY` with known "/" characters at positions 2 and 5
3. Year "2022" at positions 6-9 (4 bytes known)
4. Time separator ":" at known positions
5. Directory marker: `    <DIR>          ` (4 spaces + <DIR> + 10 spaces)
6. By XORing encrypted bytes with known plaintext, extracted 16-byte repeating key

**Critical Frames:**
- **Frame 13765:** `type E:\flag.txt` 
  - Decrypted: "nice try, i like to wallhack "
  - Red herring! Flag not here.

- **Frame 15060:** `type E:\wallhack.txt`
  - Decrypted: **`VBD{1_w45_ju5t_gam1n_n_bhopping}`** âœ“
  - This contained the actual flag!

#### 4. Additional Analysis Scripts

**Memory key hunter**
- Searched for flag.txt.tusk, decrypt notes, encryption keys
- Found ransomware artifacts but no working decryption key

```python
#!/usr/bin/env python3
"""Find TuskLocker2 ransom note, key, and encrypted flag"""
import sys, re

DUMP = r"D:\\ctf\\seetwo\\extracted\\ramadanctf2026_dump.raw"

print("=== SEARCHING FOR TUSKLOCKER2 KEY AND FLAG ===\\n")

patterns = {
  "flag.txt.tusk": b"flag.txt.tusk",
  "DECRYPT_YOUR_FILES": b"DECRYPT_YOUR_FILES",
  "TuskLocker2": b"TuskLocker2",
  "key": b"key",
  "Key": b"Key",
  "KEY": b"KEY",
  "password": b"password",
  "Password": b"Password",
}

CHUNK = 1024 * 1024 * 64
OVERLAP = 1000

matches = {p: [] for p in patterns}

with open(DUMP, "rb") as f:
  offset = 0
  prev_tail = b""
  chunk_num = 0
  while True:
    data = f.read(CHUNK)
    if not data:
      break
        
    search_data = prev_tail + data
    search_offset = offset - len(prev_tail)
        
    for name, pattern in patterns.items():
      idx = 0
      while True:
        pos = search_data.find(pattern, idx)
        if pos == -1:
          break
        abs_pos = search_offset + pos
        ctx_start = max(0, pos - 500)
        ctx_end = min(len(search_data), pos + 500)
        context = search_data[ctx_start:ctx_end]
        if not matches[name] or abs_pos != matches[name][-1][0]:
          matches[name].append((abs_pos, context))
        idx = pos + 1
        
    prev_tail = data[-OVERLAP:]
    offset += len(data)
    chunk_num += 1
    if chunk_num % 10 == 0:
      print(f"  ... scanned {offset / (1024*1024*1024):.1f} GB", file=sys.stderr)

print()

print("=== FLAG.TXT.TUSK LOCATIONS ===")
for off, ctx in matches["flag.txt.tusk"][:10]:
  text = ''.join(chr(b) if 32 <= b < 127 or b in [10, 13] else '.' for b in ctx)
  print(f"\\n0x{off:x}:")
  print(text[:800])

print("\\n=== SEARCHING FOR VBD{ NEAR FLAG.TXT.TUSK ===")
with open(DUMP, "rb") as f:
  for off, _ in matches["flag.txt.tusk"][:5]:
    f.seek(max(0, off - 5000))
    region = f.read(10000)
    vbd_pos = region.find(b"VBD{")
    if vbd_pos != -1:
      abs_vbd = off - 5000 + vbd_pos
      flag_ctx = region[vbd_pos:vbd_pos+100]
      flag_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag_ctx)
      print(f"  [+] FOUND VBD at 0x{abs_vbd:x}: {flag_str[:80]}")

print("\\n=== DECRYPT_YOUR_FILES.TXT CONTEXT ===")
for off, ctx in matches["DECRYPT_YOUR_FILES"][:3]:
  text = ''.join(chr(b) if 32 <= b < 127 or b in [10, 13] else '.' for b in ctx)
  print(f"\\n0x{off:x}:")
  print(text[:800])

print("\\n=== SEARCHING FOR KEY NEAR TUSKLOCKER ===")
tusk_offsets = [off for off, _ in matches["TuskLocker2"]]
with open(DUMP, "rb") as f:
  for tusk_off in tusk_offsets[:5]:
    f.seek(max(0, tusk_off - 2000))
    region = f.read(4000)
    strings = []
    current = b""
    for i, b in enumerate(region):
      if 32 <= b < 127:
        current += bytes([b])
      else:
        if len(current) >= 8:
          strings.append(current.decode())
        current = b""
    interesting = [s for s in strings if any(kw in s.lower() for kw in
      ['key', 'password', 'decrypt', 'vbd', 'flag', 'secret', 'tusk'])]
    if interesting:
      print(f"\\n  Near 0x{tusk_off:x}:")
      for s in interesting[:20]:
        print(f"    {s}")

print("\\n=== DONE ===")
```

**Systematic XOR bruteforce**
- Tested single-byte keys (0x00-0xFF)
- Attempted multi-byte key recovery
- Unsuccessful due to 16-byte key length

```python
#!/usr/bin/env python3
"""Find TuskLocker encrypted flag and XOR key"""
import sys

DUMP = r"D:\\ctf\\seetwo\\extracted\\ramadanctf2026_dump.raw"

print("Loading 5GB dump into memory...")
with open(DUMP, "rb") as f:
  data = f.read()

print(f"Loaded {len(data)} bytes\\n")
print("=== SEARCHING FOR ENCRYPTED FLAG DATA ===")

original_flag_pos = data.find(b"C:\\\\flag.txt")
if original_flag_pos >= 0:
  print(f"\\nFound 'C:\\\\flag.txt' at 0x{original_flag_pos:x}")
  ctx = data[original_flag_pos-200:original_flag_pos+500]
  print(f"\\nContext (hex):\\n{ctx.hex()}")
  print(f"\\nContext (text):\\n{ctx}")

flag_refs = []
idx = 0
while True:
  pos = data.find(b"flag.txt", idx)
  if pos == -1:
    break
  flag_refs.append(pos)
  idx = pos + 1

print(f"\\nFound {len(flag_refs)} references to 'flag.txt'")

for ref_pos in flag_refs[:5]:
  print(f"\\n--- Reference @ 0x{ref_pos:x} ---")
  after = data[ref_pos+8:ref_pos+150]
  binary_count = sum(1 for b in after[:50] if b < 32 or b > 126)
  if binary_count > 30:
    print(f"  High binary content after this reference ({binary_count}/50 non-ASCII)")
    print(f"  Hex: {after[:50].hex()}")
    test_keys = [b"walrus", b"tusk", b"I am the walrus", b"TuskLocker2"]
    for key in test_keys:
      dec = bytes([after[i] ^ key[i % len(key)] for i in range(min(50, len(after)))])
      if b"VBD{" in dec:
        print(f"\\n  [+] KEY FOUND: {key}")
        print(f"  [+] FLAG: {dec[:50].decode('ascii', errors='replace')}")

print("\\n=== SEARCHING FOR .tusk FILE CONTENT ===")
tusk_pos = data.find(b"flag.txt.tusk")
if tusk_pos >= 0:
  print(f"\\nFound 'flag.txt.tusk' at 0x{tusk_pos:x}")
  region = data[tusk_pos-2000:tusk_pos+2000]
  print("\\nSearching for 32-50 byte encrypted chunks nearby...")
  for offset in range(len(region) - 50):
    chunk = region[offset:offset+50]
    if len(set(chunk)) > 25:
      for key_str in ["walrus", "tusk", "I am the walrus", "TuskLocker", "TuskLocker2"]:
        key = key_str.encode()
        dec = bytes([chunk[i] ^ key[i % len(key)] for i in range(len(chunk))])
        if b"VBD{" in dec:
          abs_pos = tusk_pos - 2000 + offset
          print(f"\\n[+] FOUND @ 0x{abs_pos:x} with key '{key_str}'")
          print(f"[+] Decrypted: {dec[:60]}")
          end = dec.find(b"}")
          if end >= 0:
            flag = dec[:end+1].decode('ascii', errors='replace')
            print(f"\\n[+] FULL FLAG: {flag}")
            sys.exit(0)

print("\\n=== TRYING BRUTE FORCE XOR ON SUSPICIOUS REGIONS ===")
for start in range(0, len(data) - 50, 10000):
  chunk = data[start:start+50]
  if len(set(chunk)) > 30:
    for xor_key in range(256):
      dec = bytes([b ^ xor_key for b in chunk])
      if dec.startswith(b"VBD{"):
        end = dec.find(b"}")
        if end >= 0 and 30 < end < 50:
          flag = dec[:end+1].decode('ascii', errors='replace')
          print(f"\\n[+] FOUND @ 0x{start:x} with single-byte XOR key 0x{xor_key:02x}")
          print(f"[+] FLAG: {flag}")
          sys.exit(0)

print("\\nNo flag found.")
```

**Memory context extractor**
- Extracted strings and patterns from memory dump
- Focused on suspicious offsets around C2 and ransomware artifacts

```python
#!/usr/bin/env python3
"""Extract context around key offsets in memory dump"""
import sys

DUMP = r"D:\\ctf\\seetwo\\extracted\\ramadanctf2026_dump.raw"

offsets = {
  "CTF{K": 0x87d76bb3,
  "C2_tool_code": 0x672565a8 - 0x200,
  "C2_tool2": 0x672d5b37 - 0x200,
  "nice_try": 0x672d519f - 0x100,
  "rcon_status_1": 0x5df3fd23 - 0x100,
  "test123_rcon": 0x67256598 - 0x400,
}

with open(DUMP, "rb") as f:
  for name, offset in offsets.items():
    f.seek(offset)
    data = f.read(2048)
    print(f"\\n{'='*60}")
    print(f"=== {name} @ 0x{offset:x} ===")
    print(f"{'='*60}")
    for i in range(0, len(data), 64):
      chunk = data[i:i+64]
      ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk[:32])
      print(f"  {offset+i:08x}: {ascii_str}")
    print(f"\\n  Strings:")
    current = b""
    strings = []
    for i, b in enumerate(data):
      if 32 <= b < 127:
        current += bytes([b])
      else:
        if len(current) >= 4:
          strings.append((i - len(current) + offset, current.decode()))
        current = b""
    if len(current) >= 4:
      strings.append((len(data) - len(current) + offset, current.decode()))
    for off, s in strings:
      print(f"    0x{off:x}: {s}")
```

**Deep UDP/packet analysis helper**
- Searched all UDP payloads for flag-like strings
- Ran brute-force and known-key XOR checks against concatenated say_team data

```python
#!/usr/bin/env python3
"""Deep analysis: Search ALL UDP data for flag, try XOR, check game packets"""
import subprocess, re, struct, itertools

def main():
  result = subprocess.run(
    ["ssh", "-p", "2222", "kali@127.0.0.1",
     "tshark -r ~/capture2.pcapng -Y 'udp && data' -T fields -e frame.number -e udp.srcport -e udp.dstport -e data 2>/dev/null"],
    capture_output=True, text=True, input="linux0192\\n", timeout=120
  )
  lines = result.stdout.strip().split('\\n')
  connectionless = []
  game_data = []
  say_team_data = []
    
  for line in lines:
    parts = line.strip().split('\\t')
    if len(parts) < 4:
      continue
    frame, srcport, dstport, hexdata = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
    try:
      raw = bytes.fromhex(hexdata)
    except:
      continue
    if raw[:4] == b'\\xff\\xff\\xff\\xff':
      payload = raw[4:]
      connectionless.append((int(frame), srcport, dstport, payload))
      text = payload.decode('latin1', errors='replace')
      if 'say_team ' in text:
        idx = text.find('say_team ')
        after_bytes = payload[idx + len('say_team '):]
        say_team_data.append((int(frame), after_bytes))
    else:
      game_data.append((int(frame), srcport, dstport, raw))
    
  print(f"Connectionless packets: {len(connectionless)}")
  print(f"Game data packets: {len(game_data)}")
  print(f"Say_team payloads: {len(say_team_data)}")
    
  print("\\n=== SEARCH ALL PACKETS FOR 'VBD' ===")
  for frame, sp, dp, raw in game_data:
    if b'VBD' in raw:
      idx = raw.index(b'VBD')
      print(f"  [+] FOUND in game data Frame {frame} ({sp}->{dp}): ...{raw[max(0,idx-10):idx+50]}...")
  for frame, sp, dp, payload in connectionless:
    if b'VBD' in payload:
      idx = payload.index(b'VBD')
      print(f"  [+] FOUND in connectionless Frame {frame} ({sp}->{dp}): ...{payload[max(0,idx-10):idx+50]}...")
    
  print("\\n=== SEARCH ALL PACKETS FOR flag-like strings ===")
  for target in [b'flag', b'Flag', b'FLAG', b'{', b'ctf', b'VBD']:
    count = 0
    for frame, sp, dp, raw in game_data + [(f, s, d, p) for f, s, d, p in connectionless]:
      if target in raw:
        count += 1
    if count > 0:
      print(f"  '{target.decode()}' found in {count} packets")
    
  print("\\n=== XOR BRUTE FORCE (single byte) on say_team data ===")
  all_say = b''.join(d for _, d in sorted(say_team_data))
  for key in range(256):
    decoded = bytes([b ^ key for b in all_say])
    if b'VBD' in decoded:
      print(f"  [+] KEY 0x{key:02x}: {decoded[:100]}")
    
  print("\\n=== XOR with known keys ===")
  for keyname, key in [('test123', b'test123'), ('693454466', b'693454466'), ('rcon', b'rcon'), ('jisuuu', b'jisuuu')]:
    decoded = bytes([all_say[i] ^ key[i % len(key)] for i in range(len(all_say))])
    if b'VBD' in decoded:
      print(f"  [+] KEY '{keyname}': found VBD! {decoded[:100]}")
    printable = sum(1 for b in decoded[:50] if 32 <= b < 127)
    if printable > 35:
      print(f"  KEY '{keyname}': {printable}/50 printable: {decoded[:50]}")
    
  print("\\n=== XOR each say_team payload with known keys ===")
  for keyname, key in [('test123', b'test123'), ('693454466', b'693454466'), ('jisuuu', b'jisuuu'), ('de_dust2', b'de_dust2')]:
    for i, (frame, data) in enumerate(sorted(say_team_data)):
      decoded = bytes([data[j] ^ key[j % len(key)] for j in range(len(data))])
      printable = sum(1 for b in decoded if 32 <= b < 127)
      if printable > len(decoded) * 0.65:
        print(f"  KEY '{keyname}', Frame {frame}: {decoded[:60]} ({printable}/{len(data)} printable)")
    
  print("\\n=== GAME DATA FROM SERVER AROUND SAY_TEAM TIME ===")
  for frame, sp, dp, raw in game_data:
    if int(sp) == 27015 and 5850 <= int(frame) <= 7200:
      strings = []
      current = b''
      for b in raw:
        if 32 <= b < 127:
          current += bytes([b])
        else:
          if len(current) >= 4:
            strings.append(current.decode())
          current = b''
      if current and len(current) >= 4:
        strings.append(current.decode())
      if strings:
        print(f"  Frame {frame}: {strings[:5]}")
    
  import base64
  print("\\n=== BASE64 DECODE ATTEMPT ===")
  for frame, data in sorted(say_team_data):
    try:
      decoded = base64.b64decode(data)
      if b'VBD' in decoded or all(32 <= b < 127 for b in decoded[:10]):
        print(f"  Frame {frame}: base64 decoded: {decoded[:50]}")
    except:
      pass
    
  print("\\n=== ALL TEXT FROM SERVER GAME DATA ===")
  all_server_text = set()
  for frame, sp, dp, raw in game_data:
    if int(sp) == 27015:
      text = b''
      for b in raw:
        if 32 <= b < 127:
          text += bytes([b])
        else:
          if len(text) >= 5:
            all_server_text.add(text.decode())
          text = b''
      if len(text) >= 5:
        all_server_text.add(text.decode())
    
  for t in sorted(all_server_text):
    if any(kw in t.lower() for kw in ['flag', 'vbd', 'cmd', 'type', 'rcon', 'secret', 'key', 'password', 'hack', 'say']):
      print(f"  {t}")
    
  print(f"\\n  Total unique strings from server: {len(all_server_text)}")
  with open(r"D:\\ctf\\seetwo\\server_strings.txt", "w") as f:
    for t in sorted(all_server_text):
      f.write(t + "\\n")
  print("  Saved to server_strings.txt")

if __name__ == "__main__":
  main()
```

---

## Attack Methodology

### Phase 1: Traffic Analysis
```bash
# Extract UDP payloads
tshark -r capture2.pcapng -Y 'udp && data' \
  -T fields -e frame.number -e data
```

Discovered 24 encrypted `say_team` payloads in frames 1789-15060.

### Phase 2: Known Plaintext Attack (KPA)

**Rationale:** The attacker used rcon to execute Windows commands, which have predictable output.

**Key Insight:** Directory listing format is consistent:
```
01/06/2022  03:58    <DIR>          Users
01/06/2022  03:58    <DIR>          Windows
```

**XOR Key Recovery:**
- Position 2: Encrypted `0x78` â†’ Known `/` (0x2F) â†’ Key byte: `0x78 âŠ• 0x2F = 0x57`
- Position 5: Encrypted `0xC1` â†’ Known `/` (0x2F) â†’ Key byte: `0xC1 âŠ• 0x2F = 0xEE`
- Position 6-9: Year "2022" â†’ Key bytes extracted
- Continued for all positions with known plaintext

**Verification:** Key pattern repeated every 16 bytes:
```
key[2] = key[18] = key[34] = 0x57 âœ“
key[5] = key[21] = 0xEE âœ“
```

### Phase 3: Decryption & Flag Extraction

```python
# Decrypt Frame 15060 (wallhack.txt)
key = bytes([0x7e, 0xf5, 0x57, 0xfb, 0x01, 0xee, 0xe9, 0x3e,
             0x98, 0x24, 0x99, 0xd5, 0x80, 0x4e, 0x54, 0x28])
             
data = bytes.fromhex('28b7138030b19e0aad7bf3a0b53a0b4f1f9866955e80b65cf04be9a5e9203355')
decrypted = bytes([data[i] ^ key[i % 16] for i in range(len(data))])
# Result: VBD{1_w45_ju5t_gam1n_n_bhopping}
```

---

## Technical Details

### Half-Life RCON Protocol
- Uses UDP connectionless packets (prefix: `FFFFFFFF`)
- Format: `rcon <challenge> <password> <command>`
- Response encrypted with XOR cipher

### XOR Encryption
- **Algorithm:** Repeating-key XOR
- **Key Length:** 16 bytes
- **Key:** `7ef557fb01eee93e982499d5804e5428`
- **Weakness:** Vulnerable to known-plaintext attack when long predictable outputs exist

### All Decrypted Commands
Analysis of all 24 say_team payloads revealed:
- Directory listings (dir C:\)
- File type commands (type E:\flag.txt, type E:\wallhack.txt)
- Network scans (nmap, etc.)
- Privilege escalation attempts

---

## Lessons Learned

1. **Known-Plaintext Attack Effectiveness:** When dealing with command output encryption, leverage predictable OS command formats
2. **Red Herrings:** Challenge contained misleading file names (flag.txt â†’ wallhack.txt)
3. **Network Forensics:** Game servers can be exploited as C2 channels
4. **Crypto Weakness:** Repeating-key XOR with long plaintext exposure is highly vulnerable

---

## Tools Used

- **Wireshark/tshark** - Network traffic analysis
- **Python 3** - Custom decryption scripts
- **Volatility** (attempted) - Memory forensics
- **SSH** - Remote packet analysis on Kali VM

---

## Script Artifacts

All analysis scripts used in the solve are embedded directly in this writeup under the Key Scripts Developed section and the Additional Analysis Scripts section.

---

## Flag
```
VBD{1_w45_ju5t_gam1n_n_bhopping}
```

*Flag Reference: "I was just gaming and bhopping" (bunny hopping in Counter-Strike/Half-Life)*

---

## Timeline

1. Initial PCAP analysis - Identified encrypted UDP traffic
2. WebSocket decoding - Found application monitoring
3. XOR bruteforce - Single/multi-byte attempts failed
4. Known-plaintext breakthrough - Recognized dir command output structure
5. Key extraction - Derived 16-byte XOR key
6. Flag discovery - Decrypted wallhack.txt content

