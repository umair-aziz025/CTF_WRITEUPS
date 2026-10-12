# 🏴 Zero Trace CTF 2026 — Writeups

> *"An attacker leaves no trace. A defender reads every bit."*

A full collection of writeups from **Zero Trace CTF 2026**, a jeopardy-style competition covering Cryptography, Forensics, Reverse Engineering, Web Exploitation, Miscellaneous, and OSINT.

---

## 📊 Scoreboard Summary

| Category | Challenges Solved | Total Points |
|----------|:-----------------:|:------------:|
| 🔐 [Cryptography](Cryptography/) | 9 | 2,275 |
| 🕵️ [Forensics](Forensics/) | 9 | 1,685 |
| 💻 [Reverse Engineering](Reverse%20Engineering/) | 9 | 3,425 |
| 🌐 [Web](Web/) | 7 | — |
| 🧩 [Miscellaneous](Misc/) | 9 | 1,025 |
| 🔍 [OSINT](OSINT/) | 7 | 2,550 |
| **Total** | **50** | **10,960+** |

---

## 🗂️ Challenge Index

### 🔐 Cryptography
> *RSA attacks, ECDSA nonce reuse, Mersenne Twister, Diffie-Hellman, encoding ciphers*

| Challenge | Points | Flag | Writeup | Challenge File |
|-----------|:------:|------|---------|----------------|
| Ephemeral Reuse | 350 | `PCT{ecdsa_nonce_reuse_kills_private_key}` | [📝](Cryptography/Ephemeral_Reuse_Writeup.md) | [📁](Cryptography/challenges/Ephemeral_Reuse.txt) |
| Glitch Pair | 325 | `PCT{fault_attack_rsa_crt_gcd}` | [📝](Cryptography/Glitch_Pair_Writeup.md) | [📁](Cryptography/challenges/Glitch_Pair.txt) |
| Needle in Six Keys | 300 | `PCT{hastad_broadcast_cube_root_attack}` | [📝](Cryptography/Needle_In_Six_Keys_Writeup.md) | [📁](Cryptography/challenges/Needle_In_Six_Keys.txt) |
| Twin Keys | 300 | `PCT{shared_primes_break_rsa}` | [📝](Cryptography/Twin_Keys_Writeup.md) | [📁](Cryptography/challenges/Twin_Keys.txt) |
| Small Diffie-Hellman | 275 | `PCT{discrete_log_baby_step_giant_step}` | [📝](Cryptography/Small_Diffie_Hellman_Writeup.md) | [📁](Cryptography/challenges/Small_Diffie_Hellman.txt) |
| Twister | 250 | `PCT{mersenne_twister_state_recovered}` | [📝](Cryptography/Twister_Writeup.md) | [📁](Cryptography/challenges/twister_solve.txt) |
| Weighted Checksum | 200 | `PCT{linear_congruence_system_solved}` | [📝](Cryptography/Weighted_Checksum_Writeup.md) | [📁](Cryptography/challenges/Weighted_Checksum.txt) |
| Plus One | 150 | `PCT{stream_cipher_keystream_reuse}` | [📝](Cryptography/Plus_One_Writeup.md) | [📁](Cryptography/challenges/Plus_One.txt) |
| Related Messages II | 125 | `PCT{franklin_reiter_related_message}` | [📝](Cryptography/Related_Messages_II_Writeup.md) | [📁](Cryptography/challenges/Related_Messages_II.txt) |

[→ View all Cryptography writeups](Cryptography/)

---

### 🕵️ Forensics
> *Steganography, PCAP analysis, file carving, SQLite, audio metadata, encoding chains*

| Challenge | Points | Flag | Writeup | Challenge File |
|-----------|:------:|------|---------|----------------|
| Ghost in the Pixel | 300 | `PCT{gh0st_1n_th3_p1x3l_z3r0_tr4c3}` | [📝](Forensics/Ghost_in_the_Pixel_Writeup.md) | [📁](Forensics/challenges/ghost.png) |
| Audio Notes | 275 | `PCT{1d3_t4g_h1dd3n_m3ss4g3}` | [📝](Forensics/Audio_Notes_Writeup.md) | [📁](Forensics/challenges/recording.wav) |
| Blue Moon | 250 | `PCT{r3v3rs3d_b1t_lsb_st3g0}` | [📝](Forensics/Blue_Moon_Writeup.md) | [📁](Forensics/challenges/skyline_b.png) |
| Double Trouble | 230 | `PCT{p33l_3v3ry_l4y3r}` | [📝](Forensics/Double_Trouble_Writeup.md) | [📁](Forensics/challenges/README_DECRYPT.txt) |
| Russian Dolls | 180 | `PCT{4rch1v3_1ns1d3_4rch1v3}` | [📝](Forensics/Russian_Dolls_Writeup.md) | [📁](Forensics/challenges/dolls.zip) |
| Trailing Spaces | 160 | `PCT{wh1t3sp4c3_enc0d3d_m3ss4g3}` | [📝](Forensics/Trailing_Spaces_Writeup.md) | [📁](Forensics/challenges/memo.txt) |
| Hidden Table | 90 | `PCT{sq1ite_h1dd3n_t4bl3_d4t4}` | [📝](Forensics/Hidden_Table_Writeup.md) | [📁](Forensics/challenges/app.db) |
| Admin Panel | 200 | `PCT{http_cr3d3nt14ls_1n_pl41n_s1ght}` | [📝](Forensics/Admin_Panel_Writeup.md) | [📁](Forensics/challenges/capture.pcap) |
| Squashed | 250 | `PCT{c0mpr3ss3d_m3t4d4t4_1n_png}` | [📝](Forensics/Squashed_Writeup.md) | [📁](Forensics/challenges/serverroom.png) |

[→ View all Forensics writeups](Forensics/)

---

### 💻 Reverse Engineering
> *ELF binary analysis, custom VM, hash cracking, anti-debug, SMT solving*

| Challenge | Points | Flag | Writeup | Binary |
|-----------|:------:|------|---------|--------|
| Broken Matrix | 500 | `PCT{m4tr1x_0p3r4t10ns_r3v3rs3d}` | [📝](Reverse%20Engineering/Broken_Matrix_Writeup.md) | [📁](Reverse%20Engineering/challenges/broken-matrix) |
| Brute Bastion | 450 | `PCT{h4sh_brut3_f0rc3d}` | [📝](Reverse%20Engineering/Brute_Bastion_Writeup.md) | [📁](Reverse%20Engineering/challenges/brute-bastion) |
| Chunk Norris | 425 | `PCT{png_chunk_byp4ss}` | [📝](Reverse%20Engineering/Chunk_Norris_Writeup.md) | [📁](Reverse%20Engineering/challenges/chunk-norris) |
| Triple Gate | 400 | `PCT{thr33_l4y3r_k3y_ch3ck}` | [📝](Reverse%20Engineering/Triple_Gate_Writeup.md) | [📁](Reverse%20Engineering/challenges/triple-gate) |
| Rotate & Add | 400 | `PCT{r3v3rs3_l1k3_4_pr0}` | [📝](Reverse%20Engineering/Rotate_And_Add_Writeup.md) | [📁](Reverse%20Engineering/challenges/crackme) |
| Link by Link | 350 | `PCT{l1nk3d_l1st_trav3rs4l}` | [📝](Reverse%20Engineering/Link_by_Link_Writeup.md) | [📁](Reverse%20Engineering/challenges/link-by-link) |
| Lookup Lane | 325 | `PCT{lookup_t4bl3_xor_k3y}` | [📝](Reverse%20Engineering/Lookup_Lane_Writeup.md) | [📁](Reverse%20Engineering/challenges/lookup-lane) |
| Spin Cycle | 300 | `PCT{r0t4t3_4nd_xor_r3v3rs3d}` | [📝](Reverse%20Engineering/Spin_Cycle_Writeup.md) | [📁](Reverse%20Engineering/challenges/spin-cycle) |
| Paper Tiger | 275 | `PCT{d3bug_byp4ss_f4k3_ch3ck}` | [📝](Reverse%20Engineering/Paper_Tiger_Writeup.md) | [📁](Reverse%20Engineering/challenges/paper-tiger) |

[→ View all Reverse Engineering writeups](Reverse%20Engineering/)

---

### 🌐 Web Exploitation
> *Path traversal, SSRF, SSTI, JWT attacks, SQL injection, XSS*

| Challenge | Vulnerability | Flag | Writeup |
|-----------|--------------|------|---------|
| Lost in the Hallways | Path Traversal | `PCT{d1r3ct0ry_tr4v3rs4l_r34d_4ny_f1l3}` | [📝](Web/Web_Writeups.md#1-lost-in-the-hallways) |
| Ask the Server Nicely | SSRF | `PCT{ssrf_t0_1nt3rn4l_s3rv1c3}` | [📝](Web/Web_Writeups.md#2-ask-the-server-nicely) |
| Template of Doom | SSTI (Jinja2 RCE) | `PCT{ssti_j1nj4_t3mpl4t3_rc3}` | [📝](Web/Web_Writeups.md#3-template-of-doom) |
| Token of Trust | Weak JWT Secret | `PCT{w34k_jwt_s3cr3t_brut3_f0rc3d}` | [📝](Web/Web_Writeups.md#4-token-of-trust) |
| Query the Vault | SQL Injection | `PCT{sql1_1nj3ct10n_byp4ss_4uth}` | [📝](Web/Web_Writeups.md#5-query-the-vault) |
| Echo Chamber | Reflected XSS | `PCT{r3fl3ct3d_xss_st34l_c00k13}` | [📝](Web/Web_Writeups.md#6-echo-chamber) |
| Trusted Webhook | SSRF + JWT Alg Confusion | `PCT{ssrf_plus_jwt_alg_confusion_m@00m}` | [📝](Web/Web_Writeups.md#7-trusted-webhook) |

[→ View all Web writeups](Web/)

---

### 🧩 Miscellaneous
> *Brainfuck, file repair, Morse code, ZigZag cipher, onion encoding, steganography*

| Challenge | Points | Flag | Writeup | Challenge File |
|-----------|:------:|------|---------|----------------|
| Khunjerab Zigzag | 200 | `PCT{z1gz4g_d3c0d3d}` | [📝](Misc/Khunjerab_Zigzag_Writeup.md) | [📁](Misc/challenges/zigzag.txt) |
| Onion | 175 | `PCT{p33l1ng_l4y3rs_0f_enc0d1ng}` | [📝](Misc/Onion_Writeup.md) | [📁](Misc/challenges/onion.txt) |
| Tap Tap Tap | 150 | `PCT{m0rs3_c0d3_t4pp3d_0ut}` | [📝](Misc/Tap_Tap_Tap_Writeup.md) | [📁](Misc/challenges/Tap_Tap_Tap.txt) |
| Operator Asleep | 140 | `PCT{c4ll_s1gn_d3c0d3d}` | [📝](Misc/Operator_Asleep_Writeup.md) | [📁](Misc/challenges/Operator_Asleep.txt) |
| Broken Header | 130 | `PCT{h34d3r_r3p41r3d_png_c4rv3d}` | [📝](Misc/Broken_Header_Writeup.md) | [📁](Misc/challenges/corrupted.dat) |
| Dynamic Code | 120 | `PCT{br41nfuck_3x3cut3d}` | [📝](Misc/Dynamic_Code_Writeup.md) | [📁](Misc/challenges/program.bf) |
| Every Last Bit | 110 | `PCT{lsb_st3g_1n_png}` | [📝](Misc/Every_Last_Bit_Writeup.md) | [📁](Misc/challenges/cover.png) |
| Lock Inside Lock | 100 | `PCT{n3st3d_z1p_w1th_p4ssw0rd}` | [📝](Misc/Lock_Inside_Lock_Writeup.md) | [📁](Misc/challenges/outer.zip) |
| Noisy Brain | 90 | `PCT{w0rdl1st_d3crypt3d}` | [📝](Misc/Noisy_Brain_Writeup.md) | [📁](Misc/challenges/loader.py) |

[→ View all Miscellaneous writeups](Misc/)

---

### 🔍 OSINT
> *Historical research, geolocation, image metadata, airport codes, landmark identification*

| Challenge | Points | Flag | Writeup |
|-----------|:------:|------|---------|
| Cat and Mouse | 150 | `PCT{thomas_tenex_bbn}` | [📝](OSINT/osint_ctf_writeups.md#cat-and-mouse) |
| The Magician's Trick | 200 | `PCT{rats_royal_institution}` | [📝](OSINT/osint_ctf_writeups.md#the-magicians-trick) |
| Ghost in the Network | 300 | `PCT{mit_sendmail_fingerd}` | [📝](OSINT/osint_ctf_writeups.md#ghost-in-the-network) |
| The Lost Boarding Pass | 400 | `PCT{islamabad_international_airport_2018}` | [📝](OSINT/osint_ctf_writeups.md#the-lost-boarding-pass) |
| Silent Minaret | 450 | `PCT{muratkhan_1968}` | [📝](OSINT/osint_ctf_writeups.md#silent-minaret) |
| Garden Walk | 500 | `PCT{shalimar_1981}` | [📝](OSINT/osint_ctf_writeups.md#garden-walk) |
| First Words | 550 | `PCT{login_stanford_research_institute}` | [📝](OSINT/osint_ctf_writeups.md#first-words) |

[→ View all OSINT writeups](OSINT/)

---

## 🛠️ Tools Used

| Category | Tools |
|----------|-------|
| **Reverse Engineering** | Ghidra, GDB, radare2, Python (capstone, z3-solver, pwntools) |
| **Cryptography** | Python (gmpy2, pycryptodome, sympy), SageMath |
| **Forensics** | Wireshark, exiftool, sqlite3, binwalk, Python (PIL, scapy) |
| **Web** | curl, Burp Suite, Python (requests, jwt) |
| **Steganography** | zsteg, stegsolve, Python LSB scripts |
| **OSINT** | Google Maps, exiftool, open-source research |
