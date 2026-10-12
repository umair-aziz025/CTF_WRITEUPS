# Weighted Checksum — Detailed Cryptography Write-up

**Category:** Cryptography  
**Challenge value:** 135 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> A weighted checksum of the two primes. Study the files, find the weakness and recover the flag. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{p4rb4t_lah0re_s1gn4l_ae9}
```

The challenge provides a standard RSA cryptosystem setup with modulus $n$, public exponent $e = 65537$, and ciphertext $c$. In addition to these standard parameters, an extra integer $t$ is provided, described as a "weighted checksum of the two primes".

Mathematically, $t$ represents a linear combination of the unknown prime factors $p$ and $q$:
$$t = a \cdot p + b \cdot q$$

where $a$ and $b$ are small positive integer weights. Since $n = p \cdot q$, substituting $q = \frac{n}{p}$ yields a quadratic equation in $p$:
$$a \cdot p^2 - t \cdot p + b \cdot n = 0$$

By searching over small positive integer pairs $(a, b)$, we can test when the quadratic discriminant $\Delta = t^2 - 4abn$ is a non-negative perfect square. When a matching integer pair $(a, b)$ is found, the quadratic formula yields the exact prime factor $p$. Factoring $n$ reveals $q$, allowing us to compute $\phi(n) = (p-1)(q-1)$, derive the private decryption exponent $d = e^{-1} \pmod{\phi(n)}$, and decrypt the ciphertext $c$.

The investigation workflow follows a logical sequence:

1. Parse $n, e, c, t$ from `output.txt` and compare bit lengths ($\text{bit\_length}(n) = 1024$, $\text{bit\_length}(t) = 516$).
2. Formulate the quadratic equation $a \cdot p^2 - t \cdot p + b \cdot n = 0$ for small integer weights $(a, b)$.
3. Iterate small values of $(a, b)$ to check if $\Delta = t^2 - 4abn$ is a perfect square.
4. Solve for $p = \frac{t \pm \sqrt{\Delta}}{2a}$ and verify $n \pmod p == 0$.
5. Calculate $q = \frac{n}{p}$ and verify $a \cdot p + b \cdot q == t$.
6. Derive RSA private exponent $d = e^{-1} \pmod{(p-1)(q-1)}$ and compute plaintext integer $m = c^d \bmod n$.
7. Convert $m$ to UTF-8 text to recover the flag.

**Next step:** review the underlying mathematical relationship between RSA prime factors and linear checksum leakage.

---

## 2. Mathematical background: RSA & Side-Channel Information Leakage

In standard RSA key generation:
- Two distinct large primes $p$ and $q$ are chosen.
- Modulus $n = p \cdot q$.
- Euler's totient $\phi(n) = (p - 1)(q - 1) = n - (p + q) + 1$.
- Public exponent $e$ satisfies $\gcd(e, \phi(n)) = 1$.
- Private exponent $d \equiv e^{-1} \pmod{\phi(n)}$.

Security relies on the hardness of factoring $n$ into $p$ and $q$. However, if an attacker learns any non-trivial algebraic relation between $p$ and $q$, factoring $n$ reduces from exponential time to simple polynomial-time arithmetic.

For instance:
- Knowing $p + q$ immediately factors $n$ because $p$ and $q$ are roots of $x^2 - (p+q)x + n = 0$.
- Knowing $p - q$ factors $n$ using Fermat's factorization method.
- Knowing a weighted sum $a \cdot p + b \cdot q$ allows setting up a quadratic equation whose roots are $p$ and $q$.

**Next step:** analyze the exact quadratic derivation when the weights $a$ and $b$ are unknown.

---

## 3. Vulnerability analysis: Solving $t = a \cdot p + b \cdot q$

Given:
1. $n = p \cdot q$
2. $t = a \cdot p + b \cdot q$ for small unknown integers $a, b \in \mathbb{Z}^+$

### 3.1 Quadratic Derivation
Since $q = \frac{n}{p}$, substitute $q$ into the expression for $t$:
$$t = a \cdot p + b \left(\frac{n}{p}\right)$$

Multiply both sides by $p$:
$$t \cdot p = a \cdot p^2 + b \cdot n$$

Rearranging into standard quadratic form $A x^2 + B x + C = 0$:
$$a \cdot p^2 - t \cdot p + b \cdot n = 0$$

Here, the quadratic coefficients are:
- $A = a$
- $B = -t$
- $C = b \cdot n$

### 3.2 Discriminant and Root Analysis
Applying the quadratic formula gives the roots for $p$:
$$p = \frac{-B \pm \sqrt{B^2 - 4AC}}{2A} = \frac{t \pm \sqrt{t^2 - 4abn}}{2a}$$

For $p$ to be a valid integer, two conditions must hold:
1. The discriminant $\Delta = t^2 - 4abn$ must be a **perfect square** ($\Delta = k^2$ for some integer $k \ge 0$).
2. $2a$ must divide $(t \pm \sqrt{\Delta})$ evenly.

### 3.3 Estimating Weight Coefficients $a$ and $b$
Since $p \approx \sqrt{n}$ and $q \approx \sqrt{n}$:
$$t = a \cdot p + b \cdot q \approx (a + b) \sqrt{n}$$

Using the given parameters:
$$\sqrt{n} \approx 1.12066 \times 10^{154}$$
$$t \approx 1.37476 \times 10^{155}$$
$$\frac{t}{\sqrt{n}} \approx 12.2678$$

This ratio indicates that $a + b \approx 12$. Since $a$ and $b$ are small positive integers, searching $1 \le a, b \le 100$ takes less than a fraction of a millisecond.

Testing weights reveals:
$$a = 5, \quad b = 7$$
$$5p + 7q = t$$

**Next step:** extract parameters from `output.txt` and map them into the solver.

---

## 4. Parameter extraction and problem dataset

From `output.txt`:

```python
n = 125581313763115046447663056564379735549197550870463661272881474895731887042525927160227287843690326167340225199087253113418441266503321946679140521318396483398280389104498663861361648547866771164870606846865258104193298560520682428259551650097923968849393715905102632078183342320467593729170008465069020899861
e = 65537
c = 84526313325352511748841081292033028356081159333088094069980938042819650405815922183450581194388639969527443045873565387302034832661480524794041689604008582888328627744210821252019776009544407700689041174772623435325103698557524981238324695649137115274405321111649047234796018557099512469354284873964220913173
t = 137476643083642462545051059966165483869356866287707136585327117967082303605558505393707875645506428967656985795103336029172432420306381850101393623956995752
```

**Next step:** implement the automated Python solver script.

---

## 5. Complete Python Solver Script

Below is the full standalone Python 3 solver script (`weighted_checksum_solve.py`):

```python
#!/usr/bin/env python3
"""
Weighted Checksum Solver
Challenge: "A weighted checksum of the two primes"

Vulnerability:
Given RSA parameters n = p * q, e, ciphertext c, and a weighted sum of primes:
  t = a * p + b * q

Since n = p * q, we can substitute q = n / p:
  t = a * p + b * (n / p)
  a * p^2 - t * p + b * n = 0

This forms a quadratic equation in terms of p:
  p = (t ± sqrt(t^2 - 4 * a * b * n)) / (2 * a)

By iterating small integer weights (a, b), we check if the discriminant
  Δ = t^2 - 4 * a * b * n
is a non-negative perfect square. When Δ is a perfect square, we obtain the prime factor p,
compute q = n / p, calculate phi(n) = (p-1)(q-1), derive d = e^-1 mod phi(n), and decrypt c.
"""

import math
import sys

def solve():
    # Parameters from output.txt
    n = 125581313763115046447663056564379735549197550870463661272881474895731887042525927160227287843690326167340225199087253113418441266503321946679140521318396483398280389104498663861361648547866771164870606846865258104193298560520682428259551650097923968849393715905102632078183342320467593729170008465069020899861
    e = 65537
    c = 84526313325352511748841081292033028356081159333088094069980938042819650405815922183450581194388639969527443045873565387302034832661480524794041689604008582888328627744210821252019776009544407700689041174772623435325103698557524981238324695649137115274405321111649047234796018557099512469354284873964220913173
    t = 137476643083642462545051059966165483869356866287707136585327117967082303605558505393707875645506428967656985795103336029172432420306381850101393623956995752

    print("[*] Searching for integer weights (a, b) such that t = a*p + b*q...")

    found_p = None
    found_q = None
    found_a = None
    found_b = None

    # Search space for small integer coefficients
    for a in range(1, 100):
        for b in range(1, 100):
            disc = t * t - 4 * a * b * n
            if disc >= 0:
                sq = math.isqrt(disc)
                if sq * sq == disc:
                    # Check roots
                    for root in (t + sq, t - sq):
                        if root % (2 * a) == 0:
                            p_candidate = root // (2 * a)
                            if p_candidate > 1 and n % p_candidate == 0:
                                q_candidate = n // p_candidate
                                found_p = p_candidate
                                found_q = q_candidate
                                found_a = a
                                found_b = b
                                break
            if found_p:
                break
        if found_p:
            break

    if not found_p:
        print("[-] Failed to find matching weights and prime factors.")
        sys.exit(1)

    print(f"[+] Found weight coefficients: a = {found_a}, b = {found_b}")
    print(f"[+] Prime p: {found_p}")
    print(f"[+] Prime q: {found_q}")
    print(f"[*] Verification p * q == n: {found_p * found_q == n}")
    print(f"[*] Verification a*p + b*q == t: {found_a * found_p + found_b * found_q == t}")

    # Decrypt RSA ciphertext
    phi = (found_p - 1) * (found_q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    num_bytes = (m.bit_length() + 7) // 8
    m_bytes = m.to_bytes(num_bytes, 'big')

    try:
        flag_text = m_bytes.decode('utf-8')
        print(f"\n[+] Decoded Message: {flag_text}")
        if flag_text.startswith("PCT{"):
            flag = flag_text
        else:
            flag = f"PCT{{{flag_text}}}"

        print(f"==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
    except UnicodeDecodeError:
        print("[-] Decoding failed. Hex output:", m_bytes.hex())

if __name__ == '__main__':
    solve()
```

**Next step:** run the solver script and verify the execution output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python weighted_checksum_solve.py
```

### Execution Output:

```text
[*] Searching for integer weights (a, b) such that t = a*p + b*q...
[+] Found weight coefficients: a = 5, b = 7
[+] Prime p: 10116626623746924040315112856553461815517469971071490112296411268693660982723778069562576823870104360861130652096944903611400680164000253316144921973124841
[+] Prime q: 12413358566415406049067927954771167827395645204621383717692151660516285527419945006556427360879415309050190362088373073016489859926625797645809859155910221
[*] Verification p * q == n: True
[*] Verification a*p + b*q == t: True

[+] Decoded Message: PCT{p4rb4t_lah0re_s1gn4l_ae9}
==========================================
  FLAG: PCT{p4rb4t_lah0re_s1gn4l_ae9}
==========================================
```

**Next step:** review common pitfalls and error conditions when solving linear combinations of primes.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Using floating-point square root (`math.sqrt`) | Loss of precision on 1024-bit integers leads to inaccurate integer checks | Use integer square root `math.isqrt(disc)` |
| Assuming $a = 1$ and $b = 1$ | Search fails if weights are not equal to 1 | Loop over small integer weight combinations $(a, b)$ |
| Neglecting $2a$ division condition | May select non-integer candidate values for $p$ | Check `root % (2 * a) == 0` |
| Attempting general RSA factorization (e.g. CADO-NFS) | Wasteful computation on 1024-bit modulus | Exploit the linear relation leakage $t = a \cdot p + b \cdot q$ |

---

## 8. What Made the Challenge Solvable?

1. **Linear Combination Leakage:** Releasing any linear relation $t = a \cdot p + b \cdot q$ reduces RSA factorization to solving a quadratic equation over the integers.
2. **Small Integer Weights:** Because $a=5$ and $b=7$ are small positive integers, brute-forcing $(a, b)$ takes $O(1)$ time.
3. **Exact Modulus Factorization:** Computing $p$ and $q$ allows exact calculation of $\phi(n)$ and $d$, completely compromising the RSA cryptosystem.

---

## Final Flag

```text
PCT{p4rb4t_lah0re_s1gn4l_ae9}
```
