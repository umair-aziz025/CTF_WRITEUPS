# Related Messages II — Detailed Cryptography Write-up

**Category:** Cryptography  
**Challenge value:** 250 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> Retransmission with a linear tweak, and a bigger exponent. Study the files, find the weakness and recover the flag. Flag format: PCT{...}.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{5ign4l_5t4ck_anchor_17e00e54}
```

The challenge presents two RSA ciphertexts $c_1$ and $c_2$ generated under the same public key $(n, e = 5)$, where the underlying plaintexts are related by a known linear relation:
$$m_1 = m$$
$$m_2 = a \cdot m + b = 7 \cdot m + 1337$$

This configuration is vulnerable to the **Franklin-Reiter Related Message Attack**. When two plaintexts share a known polynomial relationship $m_2 = f(m_1)$ and are encrypted under the same RSA key with small public exponent $e$, we construct two polynomials in $\mathbb{Z}_n[x]$:
$$g_1(x) = x^e - c_1 \pmod n$$
$$g_2(x) = (a \cdot x + b)^e - c_2 \pmod n$$

Since $x = m$ is a root of both $g_1(x)$ and $g_2(x)$ modulo $n$, the linear term $(x - m)$ divides both polynomials. Computing the **Greatest Common Divisor (GCD)** of $g_1(x)$ and $g_2(x)$ over the ring $\mathbb{Z}_n[x]$ using the Euclidean Algorithm produces a monic degree-1 polynomial:
$$\gcd(g_1(x), g_2(x)) = x - m \pmod n$$

Extracting the constant term directly yields the secret message $m = - \text{constant\_term} \pmod n$.

The investigation workflow follows a logical sequence:

1. Parse $n, e = 5, a = 7, b = 1337, c_1, c_2$ from `output.txt`.
2. Construct polynomial $g_1(x) = x^5 - c_1 \in \mathbb{Z}_n[x]$.
3. Expand and construct polynomial $g_2(x) = (7x + 1337)^5 - c_2 \in \mathbb{Z}_n[x]$.
4. Perform polynomial Euclidean division in $\mathbb{Z}_n[x]$ to calculate $\gcd(g_1(x), g_2(x))$.
5. Obtain the monic degree-1 GCD polynomial $x + c_0 \pmod n$.
6. Recover $m = (-c_0) \bmod n$.
7. Convert $m$ to UTF-8 bytes to reveal the flag.

**Next step:** review the theoretical foundation of the Franklin-Reiter attack and polynomial ring arithmetic.

---

## 2. Mathematical background: Franklin-Reiter Related Message Attack

The **Franklin-Reiter theorem** states that if two plaintexts $m_1$ and $m_2$ satisfy an affine relation $m_2 = a \cdot m_1 + b$ (with $b \ne 0$) and are encrypted under the same RSA modulus $n$ and public exponent $e$:
$$c_1 = m_1^e \bmod n$$
$$c_2 = (a \cdot m_1 + b)^e \bmod n$$

then $m_1$ can be recovered in $O(e \log^2 e)$ time complexity using polynomial GCD operations over $\mathbb{Z}_n[x]$.

### Algebraic Formulation
Consider the two polynomials $g_1(x), g_2(x) \in \mathbb{Z}_n[x]$:
$$g_1(x) = x^e - c_1 \pmod n$$
$$g_2(x) = (a \cdot x + b)^e - c_2 \pmod n$$

Notice that at $x = m_1$:
$$g_1(m_1) = m_1^e - c_1 \equiv 0 \pmod n$$
$$g_2(m_1) = (a \cdot m_1 + b)^e - c_2 \equiv 0 \pmod n$$

Thus, $(x - m_1)$ is a common linear factor of $g_1(x)$ and $g_2(x)$ in $\mathbb{Z}_n[x]$. Provided $\gcd(m_1, n) = 1$ and $e$ is sufficiently small (e.g. $e = 5$), $(x - m_1)$ is the **unique common factor** of degree 1. Therefore:
$$\gcd(g_1(x), g_2(x)) = x - m_1 \pmod n$$

**Next step:** perform the expansion of $(ax + b)^5 - c_2$ and detail the polynomial division algorithm over $\mathbb{Z}_n[x]$.

---

## 3. Vulnerability analysis: Polynomial GCD over $\mathbb{Z}_n[x]$

Given $e = 5, a = 7, b = 1337$:

### 3.1 Expanding $g_2(x)$
Using the Binomial Theorem:
$$(7x + 1337)^5 = \sum_{k=0}^5 \binom{5}{k} 7^k \cdot 1337^{5-k} \cdot x^k$$

The coefficient array $[c_0, c_1, c_2, c_3, c_4, c_5]$ for $g_2(x)$ is:
- $c_5 = 7^5 = 16807$
- $c_4 = 5 \cdot 7^4 \cdot 1337 = 16050635$
- $c_3 = 10 \cdot 7^3 \cdot 1337^2 = 613042430$
- $c_2 = 10 \cdot 7^2 \cdot 1337^3 = 11709110410$
- $c_1 = 5 \cdot 7^1 \cdot 1337^4 = 111822004415$
- $c_0 = (1337^5 - c_2) \bmod n$

### 3.2 Polynomial Division in $\mathbb{Z}_n[x]$
Standard polynomial Euclidean algorithm relies on field division. Although $\mathbb{Z}_n$ is a composite ring (not a field), at each step of polynomial reduction:
$$A(x) = Q(x) B(x) + R(x)$$

we multiply $B(x)$ by the modular multiplicative inverse of its leading coefficient $b_{\text{lead}}^{-1} \pmod n$. Since $\gcd(b_{\text{lead}}, n) = 1$ in practice, division succeeds without factoring $n$.

Repeatedly applying $A, B \leftarrow B, A \bmod B$ terminates when $B(x) = 0$, producing the monic degree-1 polynomial:
$$P(x) = x + c_0 \pmod n$$

Setting $x + c_0 \equiv 0 \implies m = (-c_0) \bmod n$.

**Next step:** extract parameters from `output.txt` and run solver.

---

## 4. Parameter extraction and problem dataset

From `output.txt`:

```python
n = 116422957224533227501190744058552721464218041914055599990348544310411299188711792043192045031368874233578453694768210583127335756101599178154449029295627871714750559970987694573779585918503712104606118110717256560776497992282399425744661888312153014453770072915598084123896871036534024936068154153088936368953
e = 5
a = 7
b = 1337
c1 = 64686688699135016655392051899314653249236975323086374607459945986359780637653903191100067908969128340777154795091445267728717981691664100762996002884027331740778884890641535948905353421816458532440172096398791670813747736268759479938545966681881762996373854823303581914869306624254280303493394501822154217081
c2 = 43026156523727440078623801948816287723260599564646633182173582449927859935991118741713600283619609740121979748977536373868798846237945603374535682764056553583129138038132028578521735852172152016604897343688880161523533672647894629040372852149051648616436566577525860473477149048658653261400515627924226146418
```

**Next step:** present complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 solver script (`related_messages_solve.py`):

```python
#!/usr/bin/env python3
"""
Related Messages II Solver
Challenge: "Retransmission with a linear tweak, and a bigger exponent."

Vulnerability:
Franklin-Reiter Related Message Attack.
We are given two ciphertexts c1 and c2 of two linearly related plaintexts m1 and m2
encrypted under the same RSA public key (n, e = 5):
  m1 = m
  m2 = a * m + b = 7 * m + 1337
  c1 = m^5 mod n
  c2 = (7*m + 1337)^5 mod n

We define two polynomials in Z_n[x]:
  g1(x) = x^5 - c1 mod n
  g2(x) = (7*x + 1337)^5 - c2 mod n

Since x = m is a root of both polynomials modulo n, (x - m) divides both g1(x) and g2(x).
We compute the polynomial Greatest Common Divisor gcd(g1(x), g2(x)) over Z_n[x] using
the Euclidean Algorithm. The result is a monic linear polynomial:
  gcd(g1(x), g2(x)) = x - m mod n

Extracting the constant term gives m = -constant_term mod n.
"""

import sys

def solve():
    # Parameters extracted from output.txt
    n = 116422957224533227501190744058552721464218041914055599990348544310411299188711792043192045031368874233578453694768210583127335756101599178154449029295627871714750559970987694573779585918503712104606118110717256560776497992282399425744661888312153014453770072915598084123896871036534024936068154153088936368953
    e = 5
    a = 7
    b = 1337
    c1 = 64686688699135016655392051899314653249236975323086374607459945986359780637653903191100067908969128340777154795091445267728717981691664100762996002884027331740778884890641535948905353421816458532440172096398791670813747736268759479938545966681881762996373854823303581914869306624254280303493394501822154217081
    c2 = 43026156523727440078623801948816287723260599564646633182173582449927859935991118741713600283619609740121979748977536373868798846237945603374535682764056553583129138038132028578521735852172152016604897343688880161523533672647894629040372852149051648616436566577525860473477149048658653261400515627924226146418

    print("[*] Starting Franklin-Reiter Related Message Attack...")
    print(f"[*] Parameters: e={e}, a={a}, b={b}")

    def poly_clean(p):
        while len(p) > 1 and p[-1] == 0:
            p.pop()
        return [c % n for c in p]

    def poly_monic(p):
        p = poly_clean(p)
        if not p or p == [0]:
            return [0]
        lead = p[-1]
        inv = pow(lead, -1, n)
        return [(c * inv) % n for c in p]

    def poly_rem(A, B):
        A = poly_clean(A)
        B = poly_monic(B)
        while len(A) >= len(B) and A != [0]:
            deg_diff = len(A) - len(B)
            factor = A[-1]
            for i in range(len(B)):
                idx = deg_diff + i
                A[idx] = (A[idx] - factor * B[i]) % n
            A = poly_clean(A)
        return A

    def poly_gcd(A, B):
        while B != [0] and B != []:
            A, B = B, poly_rem(A, B)
        return poly_monic(A)

    # g1(x) = x^5 - c1
    g1 = [(-c1) % n, 0, 0, 0, 0, 1]

    # g2(x) = (7x + 1337)^5 - c2
    coeffs_g2 = [
        (pow(b, 5, n) - c2) % n,
        (5 * pow(a, 1) * pow(b, 4)) % n,
        (10 * pow(a, 2) * pow(b, 3)) % n,
        (10 * pow(a, 3) * pow(b, 2)) % n,
        (5 * pow(a, 4) * pow(b, 1)) % n,
        (pow(a, 5)) % n
    ]

    print("[*] Computing Polynomial GCD modulo n...")
    gcd_poly = poly_gcd(g1, coeffs_g2)

    degree = len(gcd_poly) - 1
    print(f"[+] Polynomial GCD Degree: {degree}")

    if degree != 1:
        print(f"[-] Expected degree 1 GCD polynomial, got degree {degree}.")
        sys.exit(1)

    # gcd_poly = [c0, 1] => x + c0 = 0 => m = -c0 mod n
    m = (-gcd_poly[0]) % n
    print(f"[+] Recovered Plaintext Integer m: {m}")

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

**Next step:** verify execution output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python related_messages_solve.py
```

### Execution Output:

```text
[*] Starting Franklin-Reiter Related Message Attack...
[*] Parameters: e=5, a=7, b=1337
[*] Computing Polynomial GCD modulo n...
[+] Polynomial GCD Degree: 1
[+] Recovered Plaintext Integer m: 9293821365348594034248507235884442661230843498665515461708332926353809507431549

[+] Decoded Message: PCT{5ign4l_5t4ck_anchor_17e00e54}
==========================================
  FLAG: PCT{5ign4l_5t4ck_anchor_17e00e54}
==========================================
```

**Next step:** review common implementation mistakes in related message attacks.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Forgetting to make polynomials monic before reduction | Remainder division algorithm diverges or produces invalid remainder | Scale coefficients by $b_{\text{lead}}^{-1} \pmod n$ |
| Using standard float/symbolic computer algebra | Overflow and floating-point errors on 1024-bit integer coefficients | Perform all coefficient reductions modulo $n$ |
| Attempting Coppersmith's small root method for large $m$ | Coppersmith requires $|m| < n^{1/e^2}$, which fails for full-length messages | Use Franklin-Reiter polynomial GCD when two related ciphertexts exist |
| Incorrect binomial coefficient expansion | Constructing wrong $g_2(x)$ leads to $\gcd(g_1, g_2) = 1$ | Expand $(ax + b)^e$ accurately using $\binom{e}{k} a^k b^{e-k}$ |

---

## 8. What Made the Challenge Solvable?

1. **Known Linear Relation:** The relationship $m_2 = 7m_1 + 1337$ allowed constructing $g_2(x)$ explicitly in terms of $x = m_1$.
2. **Small Public Exponent ($e = 5$):** Small degree polynomials enable fast $O(e^2)$ polynomial Euclidean GCD operations.
3. **No Random Padding (OAEP):** Plain textbook RSA without randomized padding permits direct algebraic relation across retransmitted ciphertexts.

---

## Final Flag

```text
PCT{5ign4l_5t4ck_anchor_17e00e54}
```
