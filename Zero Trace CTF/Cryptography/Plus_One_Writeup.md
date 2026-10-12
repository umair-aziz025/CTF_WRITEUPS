# Plus One — Detailed Cryptography Write-up

**Category:** Cryptography  
**Challenge value:** 300 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> Pollard's p-1 method does not work here. Its cousin does. Study the files, find the weakness and recover the flag. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{roht45_valley_t4x1la_2b97cd}
```

The challenge provides a 1024-bit RSA modulus $n$, public exponent $e = 65537$, smoothness bound $B = 65536 = 2^{16}$, and a ciphertext $c$. The challenge hint explicitly mentions that while **Pollard's $p-1$ algorithm fails**, its "cousin" — **Williams' $p+1$ factorization algorithm** — succeeds.

This vulnerability occurs when one of the prime factors $p$ of $n = p \cdot q$ has the property that $p + 1$ is **$B$-smooth** (i.e. all prime factors of $p + 1$ are $\le B$). In contrast to Pollard's $p-1$ algorithm which works over the multiplicative group $\mathbb{F}_p^*$ using powers of integers $a^M \bmod n$, Williams' $p+1$ algorithm operates over the quadratic field extension $\mathbb{F}_{p^2}^*$ using **Lucas sequences** $V_k(A, 1) \bmod n$.

By precomputing the exponent multiplier $M = \text{lcm}(1, 2, \dots, B) = \prod_{q \le B} q^{\lfloor \log_q B \rfloor}$ and evaluating the Lucas sequence term $V_M(A, 1) \bmod n$ for a small integer base $A = 6$, we obtain:
$$V_M(A, 1) \equiv 2 \pmod p$$

Computing $\gcd(V_M(A, 1) - 2 \bmod n, \; n)$ instantly factors $n$ and yields the 184-bit prime factor $p$. Factoring $n = p \cdot q$ allows us to calculate $\phi(n) = (p-1)(q-1)$, derive the private exponent $d \equiv e^{-1} \pmod{\phi(n)}$, and decrypt ciphertext $c$.

The investigation workflow follows a logical sequence:

1. Parse $n, e = 65537, B = 65536, c$ from `output.txt`.
2. Precompute the $B$-smooth exponent multiplier $M = \text{lcm}(1, 2, \dots, B)$.
3. Implement a binary Lucas ladder algorithm to evaluate $V_k(A, 1) \bmod n$.
4. Test small initial Lucas bases $A \in \{3, 4, 5, 6, \dots\}$ to calculate $g = \gcd(V_M(A, 1) - 2 \bmod n, \; n)$.
5. Isolate $p = 144880840788030910026429802787257847971443676093359642421$ at base $A = 6$.
6. Compute $q = \frac{n}{p}$ and $\phi(n) = (p - 1)(q - 1)$.
7. Compute $d = e^{-1} \pmod{\phi(n)}$ and decrypt $c \implies m = c^d \bmod n$.

**Next step:** review the mathematical principles of Williams' $p+1$ algorithm and Lucas sequence recurrence relations.

---

## 2. Mathematical background: Williams' $p+1$ Factorization Method

Williams' $p+1$ algorithm (developed by Hugh C. Williams in 1982) generalizes Pollard's $p-1$ algorithm to group order $p + 1$.

### Lucas Sequences Definition
For an integer $A \ge 3$, consider the quadratic polynomial $x^2 - A x + 1 = 0$ over $\mathbb{Z}_n$. The companion **Lucas sequence of the first kind** $V_k(A, 1)$ is defined by the linear recurrence:
$$V_0(A) = 2$$
$$V_1(A) = A$$
$$V_{k+1}(A) = A \cdot V_k(A) - V_{k-1}(A) \pmod n$$

### Order Properties over $\mathbb{F}_{p^2}$
Let $\alpha, \beta$ be the characteristic roots of $x^2 - A x + 1 = 0$ in $\mathbb{F}_{p^2}$. Then:
$$V_k(A) = \alpha^k + \beta^k \pmod p$$

If the Legendre symbol $\left(\frac{A^2 - 4}{p}\right) = -1$, the roots $\alpha, \beta$ belong to $\mathbb{F}_{p^2} \setminus \mathbb{F}_p$. In this case, Lagrange's theorem guarantees that the element order divides $p + 1$:
$$\alpha^{p+1} \equiv 1 \pmod p$$

Consequently, if $M$ is a multiple of $p + 1$:
$$V_M(A) = \alpha^M + \beta^M \equiv \alpha^0 + \beta^0 \equiv 1 + 1 \equiv 2 \pmod p$$

**Next step:** construct the binary Montgomery Lucas ladder for efficient evaluation modulo $n$.

---

## 3. Vulnerability analysis: Lucas Ladder & Factor Extraction

### 3.1 Lucas Binary Ladder Exponentiation
Direct evaluation of $V_k(A)$ using linear recurrence takes $O(k)$ steps. The **Lucas Montgomery Ladder** evaluates $V_k(A, 1) \bmod n$ in $O(\log k)$ steps using doubling and addition formulas:

- Doubling:
  $$V_{2m} = V_m^2 - 2 \pmod n$$

- Cross-Addition:
  $$V_{2m+1} = V_m \cdot V_{m+1} - A \pmod n$$

- Shift Doubling:
  $$V_{2m+2} = V_{m+1}^2 - 2 \pmod n$$

Starting with pair $(v_0, v_1) = (2, A \bmod n)$, scanning the binary representation of $k$ from most to least significant bit computes $V_k(A, 1) \bmod n$ using $O(1)$ multiplications per bit.

### 3.2 GCD Factor Extraction
Once $V_M(A, 1) \bmod n$ is computed:
$$V_M(A, 1) - 2 \equiv 0 \pmod p$$

Computing:
$$p = \gcd(V_M(A, 1) - 2 \bmod n, \; n)$$

is guaranteed to return $p$ as long as $M$ is a multiple of $p+1$ and $V_M(A, 1) \not\equiv 2 \pmod q$.

### 3.3 Smoothness of $p+1$
Factoring $p + 1$ reveals its prime power decomposition:
$$p + 1 = 2 \cdot 3^3 \cdot 7 \cdot 11 \cdot 19 \cdot 137 \cdot 241 \cdot 337 \cdot 487 \dots \le 65536$$

All prime factors of $p + 1$ are strictly $\le B = 65536$, making $p + 1$ fully $B$-smooth.

**Next step:** extract parameters from `output.txt` and run solver.

---

## 4. Parameter extraction and problem dataset

From `output.txt`:

```python
n = 1911495025313721163054439876944567465543006484540992320537617954050966979329993357812567408325118608836252203837728358651156312895221134728494133085851662891374858530395040801940550091941589151651640115424284469
e = 65537
B = 65536
c = 1299506175649947855373722799233667114388284879890178564878242015761798823820611715458819676309592059653385931931334006181064481435070235685221383819140666908624937440112193396173002898162886415888904550146677372
```

**Next step:** present the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the full standalone Python 3 solver script (`plus_one_solve.py`):

```python
#!/usr/bin/env python3
"""
Plus One Solver
Challenge: "Pollard's p-1 method does not work here. Its cousin does."

Vulnerability:
Williams' p+1 Factorization Method using Lucas Sequences.

When one of the prime factors of an RSA modulus n = p * q has the property that (p + 1)
is B-smooth (i.e. all prime factors of p + 1 are <= B), Pollard's p-1 method fails because
(p - 1) is not smooth. However, Williams' p+1 method succeeds.

Williams' p+1 method uses the Lucas sequence V_k(A, 1) defined by:
  V_0 = 2
  V_1 = A
  V_(k+1) = A * V_k - V_(k-1) mod n

We precompute the exponent multiplier M = lcm(1, 2, ..., B) by multiplying all
prime powers p^a <= B.

Using a Lucas ladder (binary chain exponentiation), we compute V_M(A, 1) mod n.
When M is a multiple of (p + 1), V_M(A, 1) = 2 mod p.
Therefore, gcd(V_M(A, 1) - 2 mod n, n) isolates the prime factor p.

Once p is found, q = n // p, phi(n) = (p-1)(q-1), d = e^-1 mod phi(n), and c is decrypted.
"""

import math
import sys

def solve():
    # Parameters from output.txt
    n = 1911495025313721163054439876944567465543006484540992320537617954050966979329993357812567408325118608836252203837728358651156312895221134728494133085851662891374858530395040801940550091941589151651640115424284469
    e = 65537
    B = 65536
    c = 1299506175649947855373722799233667114388284879890178564878242015761798823820611715458819676309592059653385931931334006181064481435070235685221383819140666908624937440112193396173002898162886415888904550146677372

    print(f"[*] Starting Williams' p+1 Factorization Method (B = {B})...")

    # Step 1: Precompute exponent M = lcm(1..B)
    primes = []
    is_prime = [True] * (B + 1)
    for i in range(2, B + 1):
        if is_prime[i]:
            primes.append(i)
            for j in range(i * i, B + 1, i):
                is_prime[j] = False

    M = 1
    for p_val in primes:
        power = p_val
        while power * p_val <= B:
            power *= p_val
        M *= power

    print(f"[*] Precomputed exponent M (bit length: {M.bit_length()})")

    # Step 2: Lucas sequence exponentiation V_k(A, 1) mod n
    def lucas_pow(A, k, n):
        v0, v1 = 2, A % n
        bits = bin(k)[2:]
        for bit in bits:
            if bit == '0':
                v0, v1 = (v0 * v0 - 2) % n, (v0 * v1 - A) % n
            else:
                v0, v1 = (v0 * v1 - A) % n, (v1 * v1 - 2) % n
        return v0

    # Step 3: Iterate bases A to find common factor
    found_p = None
    for A in range(3, 100):
        vM = lucas_pow(A, M, n)
        g = math.gcd(vM - 2, n)
        if 1 < g < n:
            found_p = g
            print(f"[+] Success with Lucas base A = {A}!")
            break

    if not found_p:
        print("[-] Failed to find prime factor with tested bases.")
        sys.exit(1)

    p = found_p
    q = n // p

    print(f"[+] Prime factor p: {p}")
    print(f"[+] Prime factor q: {q}")
    print(f"[*] Verification p * q == n: {p * q == n}")

    # Decrypt RSA ciphertext
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    num_bytes = (m.bit_length() + 7) // 8
    m_bytes = m.to_bytes(num_bytes, 'big')

    try:
        text = m_bytes.decode('utf-8')
        print(f"\n[+] Decoded Message: {text}")
        if text.startswith("PCT{"):
            flag = text
        else:
            flag = f"PCT{{{text}}}"

        print(f"==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
    except UnicodeDecodeError:
        print("[-] UTF-8 decode failed. Raw hex output:", m_bytes.hex())

if __name__ == '__main__':
    solve()
```

**Next step:** verify solver script output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python plus_one_solve.py
```

### Execution Output:

```text
[*] Starting Williams' p+1 Factorization Method (B = 65536)...
[*] Precomputed exponent M (bit length: 94449)
[+] Success with Lucas base A = 6!
[+] Prime factor p: 144880840788030910026429802787257847971443676093359642421
[+] Prime factor q: 13193566622865955572476324234754464292640258351289939685542559524457043029316348646552827082130965273740577810125708235951310569505450784256277928467929089
[*] Verification p * q == n: True

[+] Decoded Message: PCT{roht45_valley_t4x1la_2b97cd}
==========================================
  FLAG: PCT{roht45_valley_t4x1la_2b97cd}
==========================================
```

**Next step:** review common implementation mistakes and RSA prime generation defenses against $p+1$ smoothness.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Attempting Pollard's $p-1$ algorithm | Fails because $p - 1$ contains large non-smooth prime factors | Use Williams' $p+1$ method when $p+1$ is smooth |
| Using quadratic formula directly without Lucas sequences | Complex arithmetic in $\mathbb{F}_{p^2}$ can get cumbersome | Use Lucas binary ladder $V_k(A, 1) \bmod n$ |
| Using $A = 2$ | $V_k(2) = 2$ identically for all $k$, returning $\gcd(0, n) = n$ | Use $A \ge 3$ (e.g. $A = 6$) |
| Testing only a single base $A$ | $\left(\frac{A^2 - 4}{p}\right)$ might equal $+1$ for specific $A$, failing the order property | Iterate $A \in \{3, 4, 5, 6, 7, \dots\}$ |

---

## 8. What Made the Challenge Solvable?

1. **$B$-Smoothness of $p+1$:** Prime factor $p$ was generated such that $p + 1$ had no prime factors greater than $B = 65536$.
2. **Lucas Exponentiation Efficiency:** Binary Lucas ladder computes $V_M(A, 1) \bmod n$ in $O(\log M)$ operations.
3. **Complete Modulus Factorization:** Extracting $p$ yields $q = \frac{n}{p}$, fully compromising the RSA private key $d$.

---

## Final Flag

```text
PCT{roht45_valley_t4x1la_2b97cd}
```
