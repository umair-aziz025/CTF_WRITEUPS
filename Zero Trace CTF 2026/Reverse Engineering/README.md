# 💻 Reverse Engineering — Zero Trace CTF 2026

**9 challenges solved** involving x86-64 binary analysis, custom VM reverse engineering, hash cracking, bytecode analysis, and anti-debug bypass techniques.

---

## Challenge Index

| # | Challenge | Points | Flag | Writeup |
|---|-----------|--------|------|---------|
| 1 | **Broken Matrix** | 500 | `PCT{m4tr1x_0p3r4t10ns_r3v3rs3d}` | [📝 Writeup](Broken_Matrix_Writeup.md) |
| 2 | **Brute Bastion** | 450 | `PCT{h4sh_brut3_f0rc3d}` | [📝 Writeup](Brute_Bastion_Writeup.md) |
| 3 | **Chunk Norris** | 425 | `PCT{png_chunk_byp4ss}` | [📝 Writeup](Chunk_Norris_Writeup.md) |
| 4 | **Triple Gate** | 400 | `PCT{thr33_l4y3r_k3y_ch3ck}` | [📝 Writeup](Triple_Gate_Writeup.md) |
| 5 | **Link by Link** | 350 | `PCT{l1nk3d_l1st_trav3rs4l}` | [📝 Writeup](Link_by_Link_Writeup.md) |
| 6 | **Lookup Lane** | 325 | `PCT{lookup_t4bl3_xor_k3y}` | [📝 Writeup](Lookup_Lane_Writeup.md) |
| 7 | **Spin Cycle** | 300 | `PCT{r0t4t3_4nd_xor_r3v3rs3d}` | [📝 Writeup](Spin_Cycle_Writeup.md) |
| 8 | **Rotate & Add** | 400 | `PCT{r3v3rs3_l1k3_4_pr0}` | [📝 Writeup](Rotate_And_Add_Writeup.md) |
| 9 | **Paper Tiger** | 275 | `PCT{d3bug_byp4ss_f4k3_ch3ck}` | [📝 Writeup](Paper_Tiger_Writeup.md) |

---

## Challenge Files

Binary challenge files are in the [`challenges/`](challenges/) folder.

| File | Used In |
|------|---------|
| `broken-matrix` | Broken Matrix |
| `brute-bastion` | Brute Bastion |
| `chunk-norris` | Chunk Norris |
| `triple-gate` | Triple Gate |
| `link-by-link` | Link by Link |
| `lookup-lane` | Lookup Lane |
| `spin-cycle` | Spin Cycle |
| `crackme` | Rotate & Add |
| `paper-tiger` | Paper Tiger |

> ⚠️ All binaries are Linux x86-64 ELF executables. Run in a Linux/WSL environment.

---

## Topics Covered

- **Static Analysis:** Ghidra / radare2 disassembly, function graph analysis
- **Dynamic Analysis:** GDB tracing, strace, ltrace
- **Custom VM:** Bytecode disassembly, opcode mapping, Z3 SMT solving
- **Anti-Debug:** ptrace bypass, fake check circumvention
- **Hash Cracking:** CRC32/MD5 brute force with custom wordlists
- **Cryptographic Operations:** XOR with rotation, AES-like substitution boxes, matrix operations
- **Data Structures:** Linked list traversal in binary
