# Twin Keys — Detailed Cryptography Write-up

**Category:** Cryptography / RSA Factorization  
**Category Value:** 300 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> A careless admin generated two RSA keys but tried to save time on randomness, and something ended up shared between them. You're given both public keys and a ciphertext. Recover the message.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{shared_primes_break_rsa}
```

The challenge provides two RSA public keys ($n_1, e$ and $n_2, e$) alongside two ciphertexts ($c_1$ and $c_2$) in `output.txt`.

The title **"Twin Keys"** and description hint **"tried to save time on randomness, and something ended up shared between them"** point directly to a **Shared Prime Factor Vulnerability**.

When an RNG failure or state reuse occurs during key generation, two independent RSA moduli $n_1$ and $n_2$ may share a single prime factor $p$:

$$n_1 = p \times q_1, \quad n_2 = p \times q_2$$

Because $p$ divides both $n_1$ and $n_2$, computing the Greatest Common Divisor $\gcd(n_1, n_2)$ isolates $p$ in sub-millisecond time without requiring general integer factorization.

The investigation workflow follows a logical sequence:

1. Parse $e = 65537$, $n_1$, $c_1$, $n_2$, $c_2$ from `output.txt`.
2. Compute $p = \gcd(n_1, n_2)$.
3. Verify that $1 < p < n_1$, confirming $p$ is a non-trivial shared prime factor.
4. Calculate $q_1 = n_1 / p$ and $q_2 = n_2 / p$.
5. Derive Euler's totient $\phi(n_1) = (p - 1)(q_1 - 1)$ and private exponent $d_1 = e^{-1} \pmod{\phi(n_1)}$.
6. Decrypt ciphertext $m_1 = c_1^{d_1} \bmod n_1$ to recover the flag.

**Next step:** analyze the input parameters and mathematical properties.

---

## 2. Initial inspection & Parameter analysis

`output.txt` supplies the following parameters:

- **Public Exponent ($e$):** $65537$
- **Modulus 1 ($n_1$):** 1024-bit integer
- **Ciphertext 1 ($c_1$):** 1024-bit integer
- **Modulus 2 ($n_2$):** 1024-bit integer
- **Ciphertext 2 ($c_2$):** 1024-bit integer

Because $n_1$ and $n_2$ are 1024-bit numbers, standard factorization methods (like GNFS or ECM) would take decades. However, if $\gcd(n_1, n_2) > 1$, Euclid's algorithm factors both numbers instantly in $O(\log N)$ steps.

**Next step:** formulate the shared prime mathematical model.

---

## 3. Vulnerability analysis: Shared Prime Factorization via Euclidean Algorithm

In secure RSA implementations, primes $p$ and $q$ must be generated independently using cryptographically secure random number generators (CSPRNGs).

If the same prime $p$ is selected during key generation for two different users or endpoints:

$$\gcd(n_1, n_2) = \gcd(p q_1, p q_2) = p \cdot \gcd(q_1, q_2)$$

Since $q_1$ and $q_2$ are distinct random 512-bit primes, $\gcd(q_1, q_2) = 1$. Thus:

$$p = \gcd(n_1, n_2)$$

### Shared Prime Recovery
Running Euclid's algorithm yields:

$$p = 12934779835116010428958684527514172952421978209492298945776688426282480192293020088761725224991962084197680889631872069259745742972145308162056118839984501$$

### Private Key Construction
Once $p$ is known:

$$q_1 = \frac{n_1}{p}$$
$$\phi(n_1) = (p - 1)(q_1 - 1)$$
$$d_1 \equiv e^{-1} \pmod{\phi(n_1)}$$

### Decryption
$$m_1 = c_1^{d_1} \bmod n_1$$

Converting $m_1$ to ASCII bytes yields `PCT{shared_primes_break_rsa}`.

Decrypting $c_2$ with $d_2$ yields the decoy message: `nothing to see here, check the other one`.

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Factoring & Decryption Procedure

$$\begin{array}{|c|l|l|}
\hline
\text{Step} & \text{Mathematical Operation} & \text{Result / Value} \\
\hline
1 & p = \gcd(n_1, n_2) & \text{512-bit shared prime } p \\
2 & q_1 = n_1 / p & \text{512-bit second prime } q_1 \\
3 & \phi(n_1) = (p - 1)(q_1 - 1) & \text{1024-bit totient value} \\
4 & d_1 = \text{pow}(e, -1, \phi(n_1)) & \text{Private exponent } d_1 \\
5 & m_1 = \text{pow}(c_1, d_1, n_1) & \text{Plaintext integer } m_1 \\
6 & m_1.\text{to\_bytes}(\dots) & \mathbf{\text{PCT\{shared\_primes\_break\_rsa\}}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`twin_keys_solve.py`):

```python
#!/usr/bin/env python3
"""
Twin Keys Solver
Challenge: "A careless admin generated two RSA keys but tried to save time on randomness, and something ended up shared between them."

Vulnerability / Analysis:
1. `output.txt` provides two RSA public moduli `n1` and `n2`, exponent `e = 65537`, and ciphertexts `c1` and `c2`.
2. The description hints at shared randomness between keys.
3. Calculating `p = gcd(n1, n2)` reveals a non-trivial shared prime factor:
   p = 12934779835116010428958684527514172952421978209492298945776688426282480192293020088761725224991962084197680889631872069259745742972145308162056118839984501
4. Factoring `n1 = p * q1` and computing `phi1 = (p - 1) * (q1 - 1)` allows computing private key `d1 = e^(-1) mod phi1`.
5. Decrypting `c1^d1 mod n1` yields:
   PCT{shared_primes_break_rsa}
"""

import os
from math import gcd

def solve():
    base_dir = os.path.dirname(__file__)
    output_path = os.path.join(base_dir, "output.txt")

    if not os.path.exists(output_path):
        print(f"[-] Input file not found: {output_path}")
        return None

    # Load variables from output.txt
    env = {}
    with open(output_path, "r", encoding="utf-8") as f:
        exec(f.read(), env)

    e = env["e"]
    n1 = env["n1"]
    c1 = env["c1"]
    n2 = env["n2"]
    c2 = env["c2"]

    print(f"[*] Loaded n1 ({n1.bit_length()} bits), n2 ({n2.bit_length()} bits)")
    print(f"[*] Step 1: Computing gcd(n1, n2)...")
    
    p = gcd(n1, n2)
    if p == 1:
        print("[-] Moduli n1 and n2 do not share a prime factor.")
        return None

    print(f"[+] Shared prime factor p found! ({p.bit_length()} bits)")

    # Factoring n1
    q1 = n1 // p
    phi1 = (p - 1) * (q1 - 1)
    d1 = pow(e, -1, phi1)

    m1 = pow(c1, d1, n1)
    flag_bytes1 = m1.to_bytes((m1.bit_length() + 7) // 8, "big")
    flag1 = flag_bytes1.decode("utf-8", errors="ignore")

    print(f"[+] Decrypted Ciphertext 1: {flag1}")

    # Factoring n2
    q2 = n2 // p
    phi2 = (p - 1) * (q2 - 1)
    d2 = pow(e, -1, phi2)
    m2 = pow(c2, d2, n2)
    flag_bytes2 = m2.to_bytes((m2.bit_length() + 7) // 8, "big")
    flag2 = flag_bytes2.decode("utf-8", errors="ignore")

    print(f"[+] Decrypted Ciphertext 2: {flag2}")

    flag = flag1 if flag1.startswith("PCT{") else flag2

    print(f"\n==========================================")
    print(f"  FLAG: {flag}")
    print(f"==========================================")
    return flag

if __name__ == "__main__":
    solve()
```

**Next step:** verify execution output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python twin_keys_solve.py
```

### Execution Output:

```text
[*] Loaded n1 (1024 bits), n2 (1024 bits)
[*] Step 1: Computing gcd(n1, n2)...
[+] Shared prime factor p found! (512 bits)
[+] Decrypted Ciphertext 1: PCT{shared_primes_break_rsa}
[+] Decrypted Ciphertext 2: nothing to see here, check the other one

==========================================
  FLAG: PCT{shared_primes_break_rsa}
==========================================
```

**Next step:** review common mistakes when analyzing multi-key RSA deployments.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Attempting general factoring algorithms (Pollard $p-1$, ECM) | Script hangs indefinitely or fails | Run `gcd(n1, n2)` first whenever multiple RSA moduli are available |
| Decrypting only $c_2$ | Receiving the decoy string `nothing to see here...` | Check all available ciphertexts ($c_1$ and $c_2$) |
| Calculating $\phi(n) = n_1 - 1$ | Incorrect totient calculation | Ensure factors $p$ and $q_1$ are used: $\phi(n_1) = (p-1)(q_1-1)$ |

---

## 8. What Made the Challenge Solvable?

1. **Weak RNG Design:** Reusing a single prime across multiple keys reduced RSA security to a simple GCD computation.
2. **Fast Euclidean Algorithm:** Computing $\gcd(n_1, n_2)$ requires less than 0.1 milliseconds.
3. **Multiple Public Moduli:** Providing both $n_1$ and $n_2$ allowed direct pairwise factor extraction.

---

## Final Flag

```text
PCT{shared_primes_break_rsa}
```
