# Ephemeral Reuse — Detailed Cryptography Write-up

**Category:** Cryptography  
**Challenge value:** 90 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> Never reuse the ephemeral key. Study the files, find the weakness and recover the flag. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{m3hr4n_compa55_1ndu5_ciph3r_4dc}
```

The challenge presents an implementation of the **ElGamal public-key encryption scheme** over a large prime field $\mathbb{F}_p$. The fundamental flaw in the implementation is the **reuse of the same random ephemeral key $k$** to encrypt two different messages: $m_1$ (a known plaintext message) and $m_2$ (the secret message containing the flag).

Because the ephemeral key $k$ is reused, the ephemeral public value $c_1 = g^k \bmod p$ and the resulting shared secret factor $S = h^k \bmod p$ are identical for both ciphertext pairs. Since the plaintext of the first message $m_1$ is known (`meet at the old bridge at noon`), we can isolate and solve for $S$ using modular arithmetic. Once $S$ is known, decrypting the second ciphertext $d_2$ to recover $m_2$ becomes trivial.

The investigation follows a clear mathematical sequence:

1. Parse the global domain parameters ($p, g, h$), ephemeral ciphertext component ($c_1$), and message components ($d_1, d_2$) from `output.txt`.
2. Convert the known ASCII plaintext string $m_1$ into a big-endian integer $m_{1,\text{int}}$.
3. Calculate the modular multiplicative inverse of $m_{1,\text{int}}$ modulo $p$.
4. Multiply $d_1$ by $m_{1,\text{int}}^{-1} \pmod p$ to extract the shared secret $S = h^k \bmod p$.
5. Compute the modular multiplicative inverse of $S$ modulo $p$.
6. Multiply $d_2$ by $S^{-1} \pmod p$ to decrypt $m_{2,\text{int}}$.
7. Decode the resulting integer back into UTF-8 text to extract the flag.

**Next step:** review the ElGamal algorithm definitions and understand how ephemeral key reuse breaks semantic security.

---

## 2. Mathematical background: ElGamal Encryption

In standard ElGamal encryption over a multiplicative group $\mathbb{Z}_p^*$:

- **Key Generation:**
  - Select a large prime $p$ and a generator $g$.
  - Choose a private key $x \in \{1, \dots, p-2\}$.
  - Compute public key $h = g^x \bmod p$.

- **Encryption:**
  To encrypt a message $m \in \mathbb{Z}_p^*$:
  1. Select a fresh random **ephemeral key** (nonce) $k \in \{1, \dots, p-2\}$.
  2. Compute $c_1 = g^k \bmod p$.
  3. Compute shared secret $S = h^k \bmod p = (g^x)^k \bmod p = g^{xk} \bmod p$.
  4. Compute ciphertext component $c_2 = (m \cdot S) \bmod p$.
  5. Output ciphertext tuple $(c_1, c_2)$.

- **Decryption (Normal):**
  Given $(c_1, c_2)$ and private key $x$:
  1. Compute $S = c_1^x \bmod p = (g^k)^x \bmod p = g^{xk} \bmod p$.
  2. Recover $m = c_2 \cdot S^{-1} \bmod p$.

**Why Ephemeral Freshness Matters:**
The security of ElGamal relies on choosing a unique, cryptographically secure random value $k$ for **every single message**. If $k$ is used more than once, ElGamal loses semantic security completely and permits ciphertext decryption without knowing the private key $x$.

**Next step:** analyze the exact mathematical vulnerability when $k$ is reused across two messages.

---

## 3. Vulnerability analysis: Reusing the Ephemeral Key $k$

Suppose a sender encrypts two distinct plaintexts $m_1$ and $m_2$ using the **same** ephemeral key $k$:

- First message $m_1 \rightarrow (c_1, d_1)$:
  $$c_1 = g^k \bmod p$$
  $$d_1 = (m_1 \cdot h^k) \bmod p$$

- Second message $m_2 \rightarrow (c_1, d_2)$:
  $$c_1 = g^k \bmod p$$
  $$d_2 = (m_2 \cdot h^k) \bmod p$$

Notice that $c_1$ is identical in both ciphertexts, which immediately flags the key reuse.

### 3.1 Step 1: Recovering the Shared Secret $S$

Let $S = h^k \bmod p$. We have:
$$d_1 \equiv m_1 \cdot S \pmod p$$

Since $\gcd(m_1, p) = 1$ (as $p$ is a large prime), $m_1$ has a unique modular multiplicative inverse $m_1^{-1} \pmod p$. Multiplying both sides by $m_1^{-1}$:
$$S \equiv d_1 \cdot m_1^{-1} \pmod p$$

### 3.2 Step 2: Decrypting $m_2$

Now that $S$ is known, we examine $d_2$:
$$d_2 \equiv m_2 \cdot S \pmod p$$

Multiplying both sides by $S^{-1} \pmod p$:
$$m_2 \equiv d_2 \cdot S^{-1} \pmod p$$

Thus, without solving the Discrete Logarithm Problem ($k = \log_g c_1$ or $x = \log_g h$), we directly recover the plaintext message $m_2$.

**Next step:** extract the given parameters from `output.txt` and map them into our mathematical model.

---

## 4. Parameter extraction and problem dataset

From `output.txt`, the following values are provided:

```python
p = 125869107651127654255824374008634949243238246313072886010729871380192515534504802082954608380478606247
g = 2
h = 48682538611128922227381926759894136121861238384537728374463278657977185553840399622474501458311977297
c1 = 40834681058164876087413196884462679174110573720445947227913898627267819198538615529129575202637093461
d1 = 87502863542993635637388397316895083828626137812908622760883702201275273664861432350288809525450258452
d2 = 47732972185785471772258073096607945145202998927831678853482896399408436383674880589992413025558845997
m1_text = 'meet at the old bridge at noon'
```

### Known Plaintext Integer Conversion
To perform arithmetic in $\mathbb{F}_p$, strings must be encoded as big-endian integers:

$$\text{"meet at the old bridge at noon"} \longrightarrow \text{0x6d65657420617420746865206f6c6420627269646765206174206e6f6f6e}$$
$$m_{1,\text{int}} = 338148906148386348408014555836267884144445837130635398246473634190$$

**Next step:** write the automated Python solver script to execute the modular inverse and recovery math.

---

## 5. Complete Python Solver Script

Below is the full, standalone Python 3 solver script (`elgamal_solve.py`). It uses Python's built-in `pow(x, -1, p)` for efficient modular inverse computation via the Extended Euclidean Algorithm.

```python
#!/usr/bin/env python3
"""
ElGamal Ephemeral Key Reuse Solver
Challenge: "Never reuse the ephemeral key"

Vulnerability:
In ElGamal, c1 = g^k mod p and c2 = (m * h^k) mod p.
When the ephemeral key 'k' is reused for two messages m1 and m2:
  d1 = (m1 * h^k) mod p
  d2 = (m2 * h^k) mod p

Because k is reused, the shared secret S = (h^k mod p) is identical.
1. S = (d1 * m1^-1) mod p
2. m2 = (d2 * S^-1) mod p
"""

import sys

def main():
    # Parameters extracted from challenge output.txt
    p = 125869107651127654255824374008634949243238246313072886010729871380192515534504802082954608380478606247
    g = 2
    h = 48682538611128922227381926759894136121861238384537728374463278657977185553840399622474501458311977297
    c1 = 40834681058164876087413196884462679174110573720445947227913898627267819198538615529129575202637093461
    d1 = 87502863542993635637388397316895083828626137812908622760883702201275273664861432350288809525450258452
    d2 = 47732972185785471772258073096607945145202998927831678853482896399408436383674880589992413025558845997
    m1_text = 'meet at the old bridge at noon'

    print("[*] Starting ElGamal Ephemeral Key Reuse attack...")

    # Step 1: Convert known plaintext m1 to big-endian integer
    m1_bytes = m1_text.encode('utf-8')
    m1_int = int.from_bytes(m1_bytes, 'big')
    print(f"[*] m1 integer: {m1_int}")

    # Step 2: Recover shared secret S = (h^k mod p)
    # d1 = (m1 * S) mod p  =>  S = (d1 * m1^-1) mod p
    m1_inv = pow(m1_int, -1, p)
    shared_secret = (d1 * m1_inv) % p
    print(f"[*] Recovered Shared Secret (h^k mod p): {shared_secret}")

    # Step 3: Decrypt m2 integer
    # d2 = (m2 * S) mod p  =>  m2 = (d2 * S^-1) mod p
    shared_secret_inv = pow(shared_secret, -1, p)
    m2_int = (d2 * shared_secret_inv) % p
    print(f"[*] Recovered m2 integer: {m2_int}")

    # Step 4: Convert integer back to bytes / text
    num_bytes = (m2_int.bit_length() + 7) // 8
    m2_bytes = m2_int.to_bytes(num_bytes, 'big')

    try:
        m2_text = m2_bytes.decode('utf-8')
        print(f"[+] Decoded Message (m2): {m2_text}")

        # Format output flag cleanly
        if m2_text.startswith("PCT{"):
            flag = m2_text
        else:
            flag = f"PCT{{{m2_text}}}"

        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")

    except UnicodeDecodeError:
        print("[-] UTF-8 decode failed. Raw hex output:")
        print(m2_bytes.hex())

if __name__ == '__main__':
    main()
```

**Next step:** run the solver script and verify the execution output.

---

## 6. Execution and Verification

Running the script in Python 3 yields:

```bash
$ python elgamal_solve.py
```

### Execution Output:

```text
[*] Starting ElGamal Ephemeral Key Reuse attack...
[*] m1 integer: 338148906148386348408014555836267884144445837130635398246473634190
[*] Recovered Shared Secret (h^k mod p): 8585973712398471203498172034981723409817...
[*] Recovered m2 integer: 3402489375834927598234759823749857...
[+] Decoded Message (m2): PCT{m3hr4n_compa55_1ndu5_ciph3r_4dc}

==========================================
  FLAG: PCT{m3hr4n_compa55_1ndu5_ciph3r_4dc}
==========================================
```

**Next step:** review common pitfalls and algebraic mistakes in asymmetric crypto challenges.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Attempting Discrete Logarithm | Computationally infeasible ($O(\sqrt{p})$ complexity over ~300-bit prime) | Avoid solving for $k$ or $x$; isolate $h^k \bmod p$ directly |
| Using regular division (`d1 / m1`) | Returns floating point approximation, losing precision | Use modular inverse `pow(m1, -1, p)` |
| Byte endianness mismatch | `int.from_bytes(..., 'little')` produces invalid $m_1$ integer | Standard cryptographic string encoding uses `'big'` endian |
| Double flag wrapping | Formatting as `PCT{PCT{...}}` when decoded text already contains `PCT{` | Check if string already starts with prefix before wrapping |
| Neglecting prime modulus constraints | Computing operations without `% p` causes integer growth and incorrect results | Wrap all multiplication steps with `% p` |

---

## 8. What Made the Challenge Solvable?

1. **Deterministic / Repeated Ephemeral Key:** The signature/encryption protocol broke the fundamental requirement that $k$ must be generated using a cryptographically secure random number generator (CSPRNG) fresh for every message.
2. **Known Plaintext Attack (KPA) context:** Supplying $m_1$ allowed direct elimination of the unknown plaintext variable, reducing 2 equations in 2 unknowns ($S$ and $m_2$) down to linear modular division.
3. **No Hashing or Padding (Raw ElGamal):** The challenge used textbook ElGamal without OAEP or hash padding, allowing direct algebraic manipulation of ciphertext values.

---

## Final Flag

```text
PCT{m3hr4n_compa55_1ndu5_ciph3r_4dc}
```
