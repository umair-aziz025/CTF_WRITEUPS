# 🔐 Cryptography — Zero Trace CTF 2026

**9 challenges solved** across classical and modern cryptography topics including RSA factorization, ECDSA vulnerabilities, Mersenne Twister state recovery, and custom cipher analysis.

---

## Challenge Index

| # | Challenge | Points | Flag | Writeup |
|---|-----------|--------|------|---------|
| 1 | **Ephemeral Reuse** | 350 | `PCT{ecdsa_nonce_reuse_kills_private_key}` | [📝 Writeup](Ephemeral_Reuse_Writeup.md) |
| 2 | **Glitch Pair** | 325 | `PCT{fault_attack_rsa_crt_gcd}` | [📝 Writeup](Glitch_Pair_Writeup.md) |
| 3 | **Needle in Six Keys** | 300 | `PCT{hastad_broadcast_cube_root_attack}` | [📝 Writeup](Needle_In_Six_Keys_Writeup.md) |
| 4 | **Twin Keys** | 300 | `PCT{shared_primes_break_rsa}` | [📝 Writeup](Twin_Keys_Writeup.md) |
| 5 | **Small Diffie-Hellman** | 275 | `PCT{discrete_log_baby_step_giant_step}` | [📝 Writeup](Small_Diffie_Hellman_Writeup.md) |
| 6 | **Twister** | 250 | `PCT{mersenne_twister_state_recovered}` | [📝 Writeup](Twister_Writeup.md) |
| 7 | **Weighted Checksum** | 200 | `PCT{linear_congruence_system_solved}` | [📝 Writeup](Weighted_Checksum_Writeup.md) |
| 8 | **Plus One** | 150 | `PCT{stream_cipher_keystream_reuse}` | [📝 Writeup](Plus_One_Writeup.md) |
| 9 | **Related Messages II** | 125 | `PCT{franklin_reiter_related_message}` | [📝 Writeup](Related_Messages_II_Writeup.md) |

---

## Challenge Files

Raw challenge input files are in the [`challenges/`](challenges/) folder.

---

## Topics Covered

- **RSA Attacks:** Shared prime factor (GCD), CRT fault injection, Hastad broadcast, Franklin-Reiter
- **ECDSA:** Nonce reuse → private key recovery
- **Diffie-Hellman:** Baby-step giant-step discrete log
- **PRNG:** Mersenne Twister full state recovery
- **Symmetric:** Stream cipher keystream reuse, weighted checksum linear systems
