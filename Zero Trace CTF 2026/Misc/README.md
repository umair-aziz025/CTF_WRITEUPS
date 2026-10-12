# 🧩 Miscellaneous — Zero Trace CTF 2026

**9 challenges solved** covering brainfuck execution, file header repair, steganography, Morse code, cipher decoding, and encoding puzzles.

---

## Challenge Index

| # | Challenge | Points | Flag | Writeup |
|---|-----------|--------|------|---------|
| 1 | **Khunjerab Zigzag** | 200 | `PCT{z1gz4g_d3c0d3d}` | [📝 Writeup](Khunjerab_Zigzag_Writeup.md) |
| 2 | **Onion** | 175 | `PCT{p33l1ng_l4y3rs_0f_enc0d1ng}` | [📝 Writeup](Onion_Writeup.md) |
| 3 | **Tap Tap Tap** | 150 | `PCT{m0rs3_c0d3_t4pp3d_0ut}` | [📝 Writeup](Tap_Tap_Tap_Writeup.md) |
| 4 | **Operator Asleep** | 140 | `PCT{c4ll_s1gn_d3c0d3d}` | [📝 Writeup](Operator_Asleep_Writeup.md) |
| 5 | **Broken Header** | 130 | `PCT{h34d3r_r3p41r3d_png_c4rv3d}` | [📝 Writeup](Broken_Header_Writeup.md) |
| 6 | **Dynamic Code** | 120 | `PCT{br41nfuck_3x3cut3d}` | [📝 Writeup](Dynamic_Code_Writeup.md) |
| 7 | **Every Last Bit** | 110 | `PCT{lsb_st3g_1n_png}` | [📝 Writeup](Every_Last_Bit_Writeup.md) |
| 8 | **Lock Inside Lock** | 100 | `PCT{n3st3d_z1p_w1th_p4ssw0rd}` | [📝 Writeup](Lock_Inside_Lock_Writeup.md) |
| 9 | **Noisy Brain** | 90 | `PCT{w0rdl1st_d3crypt3d}` | [📝 Writeup](Noisy_Brain_Writeup.md) |

---

## Challenge Files

Raw challenge files are in the [`challenges/`](challenges/) folder.

| File | Used In |
|------|---------|
| `zigzag.txt` | Khunjerab Zigzag |
| `onion.txt` | Onion |
| `Tap_Tap_Tap.txt` | Tap Tap Tap |
| `Operator_Asleep.txt` | Operator Asleep |
| `corrupted.dat` / `repaired.png` | Broken Header |
| `program.bf` | Dynamic Code |
| `cover.png` | Every Last Bit |
| `outer.zip` | Lock Inside Lock |
| `loader.py` / `wordlist.txt` | Noisy Brain |

---

## Topics Covered

- **Encoding:** ZigZag transposition, multi-layer onion decoding
- **Morse Code:** Audio/text-based Morse decoding
- **Esoteric Languages:** Brainfuck execution and analysis
- **File Repair:** PNG header reconstruction from corrupted binary
- **Steganography:** LSB extraction from images
- **Archive Cracking:** Nested password-protected ZIPs with wordlist
- **PRNG Cracking:** Python `random` module seed recovery
