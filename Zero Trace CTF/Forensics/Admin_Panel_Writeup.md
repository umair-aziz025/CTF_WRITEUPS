# Admin Panel — Detailed Forensics Write-up

**Category:** Forensics / PCAP Network Analysis  
**Category Value:** 200 points  
**Provided file:** `capture.pcap`  
**Flag format:** `PCT{...}`

> Someone logged into the admin panel over plain HTTP. Recover the credentials.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}
```

The challenge provides a packet capture file named `capture.pcap` (4,644 bytes) recording plain unencrypted HTTP traffic.

The investigation workflow follows a logical sequence:

1. Inspect `capture.pcap` to identify HTTP request methods and status codes.
2. Locate the initial unauthenticated `GET /admin` request resulting in `HTTP/1.1 401 Unauthorized` with header `WWW-Authenticate: Basic realm="admin"`.
3. Locate the subsequent authenticated `GET /admin` request containing the header:
   `Authorization: Basic YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59`.
4. Perform Base64 decoding on `YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59`.
5. Extract credentials: `admin:PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}`.

**Next step:** analyze the network trace sequence.

---

## 2. Initial inspection & Network trace analysis

Inspecting the packet stream in `capture.pcap`:

```http
GET /admin HTTP/1.1
Host: example.local
User-Agent: Mozilla/5.0

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="admin"

GET /admin HTTP/1.1
Host: example.local
User-Agent: Mozilla/5.0
Authorization: Basic YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59

HTTP/1.1 200 OK
```

### Key Observations
1. **Unencrypted Protocol:** Traffic was transmitted over cleartext HTTP (TCP port 80).
2. **Authentication Protocol:** HTTP Basic Authentication (RFC 7617).
3. **No Cryptographic Protection:** Basic Auth transmits credentials as plain Base64 strings without encryption, hashing, or salt.

**Next step:** formulate the HTTP Basic Authentication vulnerability model.

---

## 3. Vulnerability analysis: Insecurity of HTTP Basic Authentication

HTTP Basic Authentication sends credentials in the HTTP `Authorization` request header formatted as:

$$\text{Authorization: Basic } \text{Base64}(\text{username} + \text{":"} + \text{password})$$

Because Base64 is an encoding algorithm rather than an encryption cipher, any eavesdropper on the network path can decode the payload instantly:

$$\text{Base64}^{-1}(\text{"YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59"}) \longrightarrow \text{"admin:PCT\{b4s1c\_4uth\_1s\_n0t\_3ncrypt10n\}"}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Packet Analysis Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Packet \#} & \text{HTTP Action} & \text{Header / Data} & \text{Analysis} \\
\hline
1 & \text{GET /admin} & \text{None} & \text{Initial access attempt} \\
2 & \text{401 Unauthorized} & \texttt{WWW-Authenticate: Basic} & \text{Server requests Basic Auth} \\
3 & \text{GET /admin} & \texttt{Authorization: Basic YWRt\dots} & \text{Client submits Base64 credentials} \\
4 & \text{200 OK} & \text{Authenticated Page} & \text{Successful login} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`admin_panel_solve.py`):

```python
#!/usr/bin/env python3
"""
Admin Panel Solver
Challenge: "Someone logged into the admin panel over plain HTTP. Recover the credentials."

Vulnerability / Analysis:
1. `capture.pcap` contains unencrypted HTTP traffic.
2. The packet trace shows an HTTP 401 Unauthorized challenge (`WWW-Authenticate: Basic realm="admin"`) for GET /admin.
3. The client subsequently authenticates using HTTP Basic Authentication:
     Header: Authorization: Basic YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59
4. HTTP Basic Authentication merely encodes "username:password" in Base64 (providing zero encryption).
5. Base64 decoding `YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59` reveals:
     admin:PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}
"""

import os
import re
import base64

def solve():
    base_dir = os.path.dirname(__file__)
    pcap_path = os.path.join(base_dir, "capture.pcap")

    if not os.path.exists(pcap_path):
        print(f"[-] Input file not found: {pcap_path}")
        return None

    with open(pcap_path, "rb") as f:
        data = f.read()

    print(f"[*] Loaded pcap trace ({len(data)} bytes)")

    # Search for Authorization: Basic header
    match = re.search(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", data)
    if not match:
        print("[-] HTTP Basic Authorization header not found in pcap.")
        return None

    b64_cred = match.group(1).decode("ascii")
    print(f"[+] Found Authorization Header: 'Authorization: Basic {b64_cred}'")

    decoded_cred = base64.b64decode(b64_cred).decode("utf-8")
    print(f"[+] Decoded Credentials: '{decoded_cred}'")

    if ":" in decoded_cred:
        username, flag = decoded_cred.split(":", 1)
        print(f"    Username: {username}")
        print(f"    Password: {flag}")
    else:
        flag = decoded_cred

    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python admin_panel_solve.py
```

### Execution Output:

```text
[*] Loaded pcap trace (4644 bytes)
[+] Found Authorization Header: 'Authorization: Basic YWRtaW46UENUe2I0czFjXzR1dGhfMXNfbjB0XzNuY3J5cHQxMG59'
[+] Decoded Credentials: 'admin:PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}'
    Username: admin
    Password: PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}

==========================================
  FLAG: PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}
==========================================
```

**Next step:** review common mistakes when analyzing network traffic captures.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Assuming HTTP Basic Auth is encrypted | Treating Base64 string as a cryptographic hash or cipher | Recognized Base64 encoding pattern and decode directly |
| Looking only for HTML form POST parameters | Missing HTTP protocol-level Basic Auth headers | Filter packet trace for `Authorization: Basic` headers |

---

## 8. What Made the Challenge Solvable?

1. **Unencrypted HTTP Protocol:** Transmitting credentials in cleartext over port 80.
2. **Insecure Authentication Scheme:** HTTP Basic Auth uses reversible Base64 encoding.
3. **Complete Packet Capture:** The pcap file recorded both the 401 challenge and 200 OK authenticated requests.

---

## Final Flag

```text
PCT{b4s1c_4uth_1s_n0t_3ncrypt10n}
```
