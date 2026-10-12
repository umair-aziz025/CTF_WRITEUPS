# 🌐 Web — Zero Trace CTF

**7 challenges solved** covering the most common web exploitation techniques against a live CTF server at `45.67.87.142`.

---

## Challenge Index

| # | Challenge | Points | Vulnerability | Flag | Writeup |
|---|-----------|--------|---------------|------|---------|
| 1 | **Lost in the Hallways** | — | Path Traversal (LFI) | `PCT{d1r3ct0ry_tr4v3rs4l_r34d_4ny_f1l3}` | [📝 Writeup](Web_Writeups.md#1-lost-in-the-hallways) |
| 2 | **Ask the Server Nicely** | — | SSRF | `PCT{ssrf_t0_1nt3rn4l_s3rv1c3}` | [📝 Writeup](Web_Writeups.md#2-ask-the-server-nicely) |
| 3 | **Template of Doom** | — | SSTI (Jinja2) | `PCT{ssti_j1nj4_t3mpl4t3_rc3}` | [📝 Writeup](Web_Writeups.md#3-template-of-doom) |
| 4 | **Token of Trust** | — | Weak JWT Secret | `PCT{w34k_jwt_s3cr3t_brut3_f0rc3d}` | [📝 Writeup](Web_Writeups.md#4-token-of-trust) |
| 5 | **Query the Vault** | — | SQL Injection | `PCT{sql1_1nj3ct10n_byp4ss_4uth}` | [📝 Writeup](Web_Writeups.md#5-query-the-vault) |
| 6 | **Echo Chamber** | — | Reflected XSS | `PCT{r3fl3ct3d_xss_st34l_c00k13}` | [📝 Writeup](Web_Writeups.md#6-echo-chamber) |
| 7 | **Trusted Webhook** | — | SSRF + JWT Algorithm Confusion | `PCT{ssrf_plus_jwt_alg_confusion_m@00m}` | [📝 Writeup](Web_Writeups.md#7-trusted-webhook) |

---

## Full Writeup

All 7 writeups are consolidated in [Web_Writeups.md](Web_Writeups.md).

---

## Topics Covered

- **Path Traversal (LFI):** Unsanitized file path reading to expose secrets
- **SSRF:** Reaching internal services via user-controlled URL fetching; integer IP bypass
- **SSTI:** Jinja2 template injection for remote code execution via global object chain
- **JWT Attacks:** Weak secret brute-force; algorithm confusion (RS256 → HS256 with public key as HMAC secret)
- **SQL Injection:** Auth bypass with comment-termination payload (`admin'--`)
- **XSS:** Reflected XSS with cookie stealing via admin-set cookie
