# 🚩 CTF Writeups Collection

> A comprehensive, fully-documented collection of CTF challenge writeups across 4 competitions. Every challenge includes step-by-step analysis, exploit scripts, and the recovered flag.

---

## 👤 Author

**MR. Umair Aziz** — Security researcher & CTF player  
📊 **4 CTFs** | **80+ Challenges Solved** | **7 Categories**

---

## 📚 Table of Contents

- [🕵️ Zero Trace CTF 2026](#️-zero-trace-ctf-2026) — 50 challenges across 6 categories
- [🕌 Ramadan CTF 2026](#-ramadan-ctf-2026) — 21 challenges
- [🏆 KnightCTF 2026](#-knightctf-2026) — 11 challenges
- [🏙️ UMass CTF 2026](#️-umass-ctf-2026) — 7 challenges

---

## 🕵️ Zero Trace CTF 2026

**Format:** Jeopardy-style | **Total Challenges:** 50 | **Total Points:** 10,960+

> Full-spectrum CTF covering cryptography, forensics, reverse engineering, web exploitation, OSINT, and miscellaneous challenges.

📂 [**Browse Full CTF Folder →**](Zero%20Trace%20CTF%202026/)

---

### 🔐 Cryptography — [9 Challenges](Zero%20Trace%20CTF%202026/Cryptography/)

> RSA attacks, ECDSA nonce reuse, Mersenne Twister state recovery, Diffie-Hellman discrete log, stream cipher analysis

| # | Challenge | Points | Flag | Writeup | Challenge File |
|---|-----------|:------:|------|:-------:|:--------------:|
| 1 | Ephemeral Reuse | 350 | `PCT{ecdsa_nonce_reuse_kills_private_key}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Ephemeral_Reuse_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Ephemeral_Reuse.txt) |
| 2 | Glitch Pair | 325 | `PCT{fault_attack_rsa_crt_gcd}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Glitch_Pair_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Glitch_Pair.txt) |
| 3 | Needle in Six Keys | 300 | `PCT{hastad_broadcast_cube_root_attack}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Needle_In_Six_Keys_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Needle_In_Six_Keys.txt) |
| 4 | Twin Keys | 300 | `PCT{shared_primes_break_rsa}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Twin_Keys_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Twin_Keys.txt) |
| 5 | Small Diffie-Hellman | 275 | `PCT{discrete_log_baby_step_giant_step}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Small_Diffie_Hellman_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Small_Diffie_Hellman.txt) |
| 6 | Twister | 250 | `PCT{mersenne_twister_state_recovered}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Twister_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/twister_solve.txt) |
| 7 | Weighted Checksum | 200 | `PCT{linear_congruence_system_solved}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Weighted_Checksum_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Weighted_Checksum.txt) |
| 8 | Plus One | 150 | `PCT{stream_cipher_keystream_reuse}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Plus_One_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Plus_One.txt) |
| 9 | Related Messages II | 125 | `PCT{franklin_reiter_related_message}` | [📝](Zero%20Trace%20CTF%202026/Cryptography/Related_Messages_II_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Cryptography/challenges/Related_Messages_II.txt) |

---

### 🕵️ Forensics — [9 Challenges](Zero%20Trace%20CTF%202026/Forensics/)

> Steganography (LSB, EXIF), PCAP analysis, file carving, SQLite forensics, audio metadata, encoding chains

| # | Challenge | Points | Flag | Writeup | Challenge File |
|---|-----------|:------:|------|:-------:|:--------------:|
| 1 | Ghost in the Pixel | 300 | `PCT{gh0st_1n_th3_p1x3l_z3r0_tr4c3}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Ghost_in_the_Pixel_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/ghost.png) |
| 2 | Audio Notes | 275 | `PCT{1d3_t4g_h1dd3n_m3ss4g3}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Audio_Notes_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/recording.wav) |
| 3 | Blue Moon | 250 | `PCT{r3v3rs3d_b1t_lsb_st3g0}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Blue_Moon_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/skyline_b.png) |
| 4 | Squashed | 250 | `PCT{c0mpr3ss3d_m3t4d4t4_1n_png}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Squashed_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/serverroom.png) |
| 5 | Double Trouble | 230 | `PCT{p33l_3v3ry_l4y3r}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Double_Trouble_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/README_DECRYPT.txt) |
| 6 | Admin Panel | 200 | `PCT{http_cr3d3nt14ls_1n_pl41n_s1ght}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Admin_Panel_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/capture.pcap) |
| 7 | Russian Dolls | 180 | `PCT{4rch1v3_1ns1d3_4rch1v3}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Russian_Dolls_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/dolls.zip) |
| 8 | Trailing Spaces | 160 | `PCT{wh1t3sp4c3_enc0d3d_m3ss4g3}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Trailing_Spaces_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/memo.txt) |
| 9 | Hidden Table | 90 | `PCT{sq1ite_h1dd3n_t4bl3_d4t4}` | [📝](Zero%20Trace%20CTF%202026/Forensics/Hidden_Table_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Forensics/challenges/app.db) |

---

### 💻 Reverse Engineering — [9 Challenges](Zero%20Trace%20CTF%202026/Reverse%20Engineering/)

> ELF binary analysis, custom VM disassembly, hash cracking, anti-debug bypass, Z3 SMT solving

| # | Challenge | Points | Flag | Writeup | Binary |
|---|-----------|:------:|------|:-------:|:------:|
| 1 | Broken Matrix | 500 | `PCT{m4tr1x_0p3r4t10ns_r3v3rs3d}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Broken_Matrix_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/broken-matrix) |
| 2 | Brute Bastion | 450 | `PCT{h4sh_brut3_f0rc3d}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Brute_Bastion_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/brute-bastion) |
| 3 | Chunk Norris | 425 | `PCT{png_chunk_byp4ss}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Chunk_Norris_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/chunk-norris) |
| 4 | Triple Gate | 400 | `PCT{thr33_l4y3r_k3y_ch3ck}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Triple_Gate_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/triple-gate) |
| 5 | Rotate & Add | 400 | `PCT{r3v3rs3_l1k3_4_pr0}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Rotate_And_Add_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/crackme) |
| 6 | Link by Link | 350 | `PCT{l1nk3d_l1st_trav3rs4l}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Link_by_Link_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/link-by-link) |
| 7 | Lookup Lane | 325 | `PCT{lookup_t4bl3_xor_k3y}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Lookup_Lane_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/lookup-lane) |
| 8 | Spin Cycle | 300 | `PCT{r0t4t3_4nd_xor_r3v3rs3d}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Spin_Cycle_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/spin-cycle) |
| 9 | Paper Tiger | 275 | `PCT{d3bug_byp4ss_f4k3_ch3ck}` | [📝](Zero%20Trace%20CTF%202026/Reverse%20Engineering/Paper_Tiger_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Reverse%20Engineering/challenges/paper-tiger) |

---

### 🌐 Web Exploitation — [7 Challenges](Zero%20Trace%20CTF%202026/Web/)

> Path traversal, SSRF, Server-Side Template Injection, JWT attacks, SQL injection, Reflected XSS

| # | Challenge | Vulnerability | Flag | Writeup |
|---|-----------|--------------|------|:-------:|
| 1 | Lost in the Hallways | Path Traversal (LFI) | `PCT{d1r3ct0ry_tr4v3rs4l_r34d_4ny_f1l3}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#1-lost-in-the-hallways) |
| 2 | Ask the Server Nicely | SSRF | `PCT{ssrf_t0_1nt3rn4l_s3rv1c3}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#2-ask-the-server-nicely) |
| 3 | Template of Doom | SSTI — Jinja2 RCE | `PCT{ssti_j1nj4_t3mpl4t3_rc3}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#3-template-of-doom) |
| 4 | Token of Trust | Weak JWT Secret Brute-force | `PCT{w34k_jwt_s3cr3t_brut3_f0rc3d}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#4-token-of-trust) |
| 5 | Query the Vault | SQL Injection Auth Bypass | `PCT{sql1_1nj3ct10n_byp4ss_4uth}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#5-query-the-vault) |
| 6 | Echo Chamber | Reflected XSS + Cookie Theft | `PCT{r3fl3ct3d_xss_st34l_c00k13}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#6-echo-chamber) |
| 7 | Trusted Webhook | SSRF + JWT Algorithm Confusion | `PCT{ssrf_plus_jwt_alg_confusion_m@00m}` | [📝](Zero%20Trace%20CTF%202026/Web/Web_Writeups.md#7-trusted-webhook) |

---

### 🧩 Miscellaneous — [9 Challenges](Zero%20Trace%20CTF%202026/Misc/)

> Brainfuck execution, file header repair, Morse code, ZigZag cipher, onion encoding, password-protected archives

| # | Challenge | Points | Flag | Writeup | Challenge File |
|---|-----------|:------:|------|:-------:|:--------------:|
| 1 | Khunjerab Zigzag | 200 | `PCT{z1gz4g_d3c0d3d}` | [📝](Zero%20Trace%20CTF%202026/Misc/Khunjerab_Zigzag_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/zigzag.txt) |
| 2 | Onion | 175 | `PCT{p33l1ng_l4y3rs_0f_enc0d1ng}` | [📝](Zero%20Trace%20CTF%202026/Misc/Onion_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/onion.txt) |
| 3 | Tap Tap Tap | 150 | `PCT{m0rs3_c0d3_t4pp3d_0ut}` | [📝](Zero%20Trace%20CTF%202026/Misc/Tap_Tap_Tap_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/Tap_Tap_Tap.txt) |
| 4 | Operator Asleep | 140 | `PCT{c4ll_s1gn_d3c0d3d}` | [📝](Zero%20Trace%20CTF%202026/Misc/Operator_Asleep_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/Operator_Asleep.txt) |
| 5 | Broken Header | 130 | `PCT{h34d3r_r3p41r3d_png_c4rv3d}` | [📝](Zero%20Trace%20CTF%202026/Misc/Broken_Header_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/corrupted.dat) |
| 6 | Dynamic Code | 120 | `PCT{br41nfuck_3x3cut3d}` | [📝](Zero%20Trace%20CTF%202026/Misc/Dynamic_Code_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/program.bf) |
| 7 | Every Last Bit | 110 | `PCT{lsb_st3g_1n_png}` | [📝](Zero%20Trace%20CTF%202026/Misc/Every_Last_Bit_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/cover.png) |
| 8 | Lock Inside Lock | 100 | `PCT{n3st3d_z1p_w1th_p4ssw0rd}` | [📝](Zero%20Trace%20CTF%202026/Misc/Lock_Inside_Lock_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/outer.zip) |
| 9 | Noisy Brain | 90 | `PCT{w0rdl1st_d3crypt3d}` | [📝](Zero%20Trace%20CTF%202026/Misc/Noisy_Brain_Writeup.md) | [📁](Zero%20Trace%20CTF%202026/Misc/challenges/loader.py) |

---

### 🔍 OSINT — [7 Challenges](Zero%20Trace%20CTF%202026/OSINT/)

> Historical research, geolocation, image metadata, landmark identification, Google Plus Codes

| # | Challenge | Points | Flag | Writeup |
|---|-----------|:------:|------|:-------:|
| 1 | Cat and Mouse | 150 | `PCT{thomas_tenex_bbn}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#cat-and-mouse) |
| 2 | The Magician's Trick | 200 | `PCT{rats_royal_institution}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#the-magicians-trick) |
| 3 | Ghost in the Network | 300 | `PCT{mit_sendmail_fingerd}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#ghost-in-the-network) |
| 4 | The Lost Boarding Pass | 400 | `PCT{islamabad_international_airport_2018}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#the-lost-boarding-pass) |
| 5 | Silent Minaret | 450 | `PCT{muratkhan_1968}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#silent-minaret) |
| 6 | Garden Walk | 500 | `PCT{shalimar_1981}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#garden-walk) |
| 7 | First Words | 550 | `PCT{login_stanford_research_institute}` | [📝](Zero%20Trace%20CTF%202026/OSINT/osint_ctf_writeups.md#first-words) |

---

## 🕌 Ramadan CTF 2026

**Format:** Jeopardy-style | **Total Challenges:** 21

> Wide coverage across Web, Reverse Engineering, Forensics, Binary Exploitation, Cryptography, and Miscellaneous.

📂 [**Browse Full CTF Folder →**](Ramadan%20CTF%202026/)

| # | Challenge | Category | Writeup |
|---|-----------|----------|:-------:|
| 1 | Airbender | PWN / Virtualization | [📝](Ramadan%20CTF%202026/writeups/airbender_writeup.md) |
| 2 | CloudVault | Web | [📝](Ramadan%20CTF%202026/writeups/cloudvault_writeup.md) |
| 3 | Encryption 101 | Reverse Engineering | [📝](Ramadan%20CTF%202026/writeups/encryption101_writeup.md) |
| 4 | ezRSA | Cryptography | [📝](Ramadan%20CTF%202026/writeups/ezrsa_writeup.md) |
| 5 | Feedback | PWN / Linux Kernel | [📝](Ramadan%20CTF%202026/writeups/feedback_writeup.md) |
| 6 | Forest | Misc / Machine Learning | [📝](Ramadan%20CTF%202026/writeups/forest_writeup.md) |
| 7 | GameWatch | Web | [📝](Ramadan%20CTF%202026/writeups/gamewatch_writeup.md) |
| 8 | GiftForge | Web | [📝](Ramadan%20CTF%202026/writeups/giftforge_writeup.md) |
| 9 | Immobilzed | Misc / Car Hacking | [📝](Ramadan%20CTF%202026/writeups/immobilzed_writeup.md) |
| 10 | In-visible | Forensics | [📝](Ramadan%20CTF%202026/writeups/in_visible_writeup.md) |
| 11 | JITstream | PWN | [📝](Ramadan%20CTF%202026/writeups/jitstream_writeup.md) |
| 12 | Mutation World | Web | [📝](Ramadan%20CTF%202026/writeups/mutation_world_writeup.md) |
| 13 | Neurahire | Misc | [📝](Ramadan%20CTF%202026/writeups/neurahire_writeup.md) |
| 14 | Notey | Web | [📝](Ramadan%20CTF%202026/writeups/notey_writeup.md) |
| 15 | QuizApp | Web | [📝](Ramadan%20CTF%202026/writeups/quizapp_writeup.md) |
| 16 | Ruby | Misc / Reverse Engineering | [📝](Ramadan%20CTF%202026/writeups/ruby_writeup.md) |
| 17 | SeeTwo | Memory Forensics / Network Analysis | [📝](Ramadan%20CTF%202026/writeups/seetwo_writeup.md) |
| 18 | SpellHound | Web | [📝](Ramadan%20CTF%202026/writeups/spellhound_writeup.md) |
| 19 | Validator | Reverse Engineering | [📝](Ramadan%20CTF%202026/writeups/validator_writeup.md) |
| 20 | Vaultmind | AI / Prompt Injection | [📝](Ramadan%20CTF%202026/writeups/vaultmind_writeup.md) |
| 21 | Zippy | Forensics | [📝](Ramadan%20CTF%202026/writeups/zippy_writeup.md) |

---

## 🏆 KnightCTF 2026

**Date:** January 2026 | **Format:** Jeopardy-style | **Total Challenges:** 11

> Forensics, Reverse Engineering, Web Security, and Binary Exploitation.

📂 [**Browse Full CTF Folder →**](KnightCTF%202026/)

| # | Challenge | Category | Writeup |
|---|-----------|----------|:-------:|
| 1 | Database Credentials Theft | Forensics | [📝](KnightCTF%202026/writeups/FORENSICS_Database_Credentials_Theft.md) |
| 2 | Exploitation | Forensics / Exploitation | [📝](KnightCTF%202026/writeups/FORENSICS_Exploitation.md) |
| 3 | Vulnerability Exploitation | Forensics | [📝](KnightCTF%202026/writeups/FORENSICS_Vulnerability_Exploitation.md) |
| 4 | KnightCTF Admin Panel | Web / SQLi | [📝](KnightCTF%202026/writeups/KnightCTF-Admin-Panel.md) |
| 5 | Knight Shop Again | Web / API | [📝](KnightCTF%202026/writeups/Knight_Shop_Again.md) |
| 6 | Knight Squad Academy Jail 2 | PWN / Jail | [📝](KnightCTF%202026/writeups/PWN_Jail2.md) |
| 7 | Knight Squad Academy | PWN | [📝](KnightCTF%202026/writeups/PWN_KnightSquadAcademy.md) |
| 8 | ReM3 | Reverse Engineering | [📝](KnightCTF%202026/writeups/RE_ReM3.md) |
| 9 | ReM3 Again | Reverse Engineering | [📝](KnightCTF%202026/writeups/RE_ReM3_Again.md) |
| 10 | kWAPTA Giveaway | Web / IDOR | [📝](KnightCTF%202026/writeups/WEB_kWAPTA_Giveaway.md) |
| 11 | WaF | Web | [📝](KnightCTF%202026/writeups/WEB_WaF.md) |

---

## 🏙️ UMass CTF 2026

**Format:** Jeopardy-style | **Total Challenges:** 7

> Web/Logic, Reverse Engineering, and Miscellaneous challenges.

📂 [**Browse Full CTF Folder →**](UMass%20CTF%202026/)

| # | Challenge | Category | Writeup |
|---|-----------|----------|:-------:|
| 1 | The Block City Times | Web / Logic | [📝](UMass%20CTF%202026/writeups/The%20Block%20City%20Times.md) |
| 2 | Brick Workshop | Web / Logic | [📝](UMass%20CTF%202026/writeups/Brick%20Workshop.md) |
| 3 | Ninja-Nerds | Web / Logic | [📝](UMass%20CTF%202026/writeups/Ninja-Nerds.md) |
| 4 | ORDER66 | Web / Logic | [📝](UMass%20CTF%202026/writeups/ORDER66.md) |
| 5 | Batcave Bitflips | Misc / Reverse Engineering | [📝](UMass%20CTF%202026/writeups/Batcave%20Bitflips.md) |
| 6 | Hens and Roosters | Misc / Logic | [📝](UMass%20CTF%202026/writeups/Hens%20and%20Roosters.md) |
| 7 | Smart Brick v2 | Reverse Engineering / Logic | [📝](UMass%20CTF%202026/writeups/Smart%20Brick%20v2.md) |

---

## 🗂️ Categories Quick Reference

| Category | Total Solved | CTFs |
|----------|:------------:|------|
| 🌐 Web Exploitation | 22+ | Zero Trace, Ramadan, KnightCTF, UMass |
| 💻 Reverse Engineering | 15+ | Zero Trace, Ramadan, KnightCTF, UMass |
| 🕵️ Forensics | 12+ | Zero Trace, Ramadan, KnightCTF |
| 💥 Binary Exploitation (PWN) | 5+ | Ramadan, KnightCTF |
| 🔐 Cryptography | 10+ | Zero Trace, Ramadan |
| 🔍 OSINT | 7 | Zero Trace |
| 🧩 Miscellaneous | 12+ | Zero Trace, Ramadan, UMass |

---

## 🛠️ Tools & Techniques

| Domain | Tools |
|--------|-------|
| **Binary Analysis** | Ghidra, GDB, radare2, IDA Pro, objdump |
| **Web Security** | Burp Suite, curl, Python requests, jwt_tool |
| **Forensics** | Wireshark, exiftool, binwalk, sqlite3, Volatility |
| **Cryptography** | SageMath, pycryptodome, z3-solver, gmpy2 |
| **Steganography** | zsteg, stegsolve, PIL/Pillow, custom LSB scripts |
| **OSINT** | Google Maps, exiftool, open-source research |
| **Scripting** | Python 3, Bash, PowerShell |

---

## ⚠️ Disclaimer

All writeups are for **educational purposes only**. Every technique documented here was performed in authorized CTF competition environments. These methods should never be applied against systems without explicit permission.

---

⭐ **Star this repo** if you find it useful!
🔔 **Watch** to stay updated with new CTF writeups
🍴 **Fork** to build your own collection
