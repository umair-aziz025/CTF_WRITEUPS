# 🕵️ Forensics — Zero Trace CTF 2026

**9 challenges solved** spanning network packet analysis, steganography (LSB, EXIF), file carving, database forensics, metadata analysis, and encoding/decoding chains.

---

## Challenge Index

| # | Challenge | Points | Flag | Writeup |
|---|-----------|--------|------|---------|
| 1 | **Ghost in the Pixel** | 300 | `PCT{gh0st_1n_th3_p1x3l_z3r0_tr4c3}` | [📝 Writeup](Ghost_in_the_Pixel_Writeup.md) |
| 2 | **Squashed** | 250 | `PCT{c0mpr3ss3d_m3t4d4t4_1n_png}` | [📝 Writeup](Squashed_Writeup.md) |
| 3 | **Blue Moon** | 250 | `PCT{r3v3rs3d_b1t_lsb_st3g0}` | [📝 Writeup](Blue_Moon_Writeup.md) |
| 4 | **Audio Notes** | 275 | `PCT{1d3_t4g_h1dd3n_m3ss4g3}` | [📝 Writeup](Audio_Notes_Writeup.md) |
| 5 | **Admin Panel** | 200 | `PCT{http_cr3d3nt14ls_1n_pl41n_s1ght}` | [📝 Writeup](Admin_Panel_Writeup.md) |
| 6 | **Trailing Spaces** | 160 | `PCT{wh1t3sp4c3_enc0d3d_m3ss4g3}` | [📝 Writeup](Trailing_Spaces_Writeup.md) |
| 7 | **Hidden Table** | 90 | `PCT{sq1ite_h1dd3n_t4bl3_d4t4}` | [📝 Writeup](Hidden_Table_Writeup.md) |
| 8 | **Russian Dolls** | 180 | `PCT{4rch1v3_1ns1d3_4rch1v3}` | [📝 Writeup](Russian_Dolls_Writeup.md) |
| 9 | **Double Trouble** | 230 | `PCT{p33l_3v3ry_l4y3r}` | [📝 Writeup](Double_Trouble_Writeup.md) |

---

## Challenge Files

Raw challenge files (images, pcap, database, audio, etc.) are in the [`challenges/`](challenges/) folder.

| File | Used In |
|------|---------|
| `ghost.png` | Ghost in the Pixel |
| `serverroom.png` | Squashed |
| `skyline_b.png` | Blue Moon |
| `recording.wav` | Audio Notes |
| `capture.pcap` | Admin Panel |
| `memo.txt` | Trailing Spaces |
| `app.db` | Hidden Table |
| `dolls.zip` | Russian Dolls |
| `README_DECRYPT.txt` | Double Trouble |

---

## Topics Covered

- **Steganography:** LSB extraction (reversed bit order), PNG metadata (zTXt/iTXt), Audio ID3 tags
- **Network Forensics:** HTTP credential extraction from PCAP
- **File Carving:** ZIP appended inside PNG, C2PA metadata parsing
- **Database Forensics:** SQLite hidden tables and schema inspection
- **Encoding Chains:** Hex → Base64 → ROT13 multi-layer decode
- **Whitespace Encoding:** Trailing space/tab Morse-code steganography
- **Archive Nesting:** Recursive ZIP extraction
