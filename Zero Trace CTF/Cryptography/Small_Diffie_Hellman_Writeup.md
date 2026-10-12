# Small Diffie-Hellman — Detailed Cryptography Write-up

**Category:** Cryptography  
**Challenge value:** 480 points  
**Provided file:** `output.txt`  
**Flag format:** `PCT{...}`

> Diffie-Hellman with a modulus that fits in a phone number. Study the files, find the weakness and recover the flag.

## 1. Result and approach

```text
PCT{p4ra7h4_ciph3r_chi7ral_gwad4r_10}
```

The modulus is only **38 bits**, making the discrete logarithm small enough to solve with baby-step giant-step (BSGS). Recovering an exponent for one public value allows us to compute the shared secret. We then infer the ciphertext's keystream construction and decrypt the flag.

The complete chain is:

1. Read the public parameters and ciphertext.
2. Identify the small discrete-log search space.
3. Recover an exponent `a` satisfying `g^a mod p = A`.
4. Compute the shared secret `B^a mod p`.
5. Use the known flag prefix to test candidate keystream constructions.
6. Extend the matching construction with a counter to decrypt all bytes.
7. Verify the exponent and reproduce the supplied ciphertext.

Only `output.txt` was supplied; there was no encryption source code. The Diffie-Hellman attack follows directly from the public parameters. The precise keystream format was inferred experimentally, not read from a missing source file.

## 2. Inspect the supplied data

```bash
cat output.txt
```

Contents:

```text
p = 255793885307
g = 4
A = 98480505109
B = 55250906666
enc = 'a470284f492b2e62ac44c492e84dc9f01c7ac58ef15de9063196534c6868378737946a33f5'
```

| Field | Meaning |
|---|---|
| `p` | Modulus |
| `g` | Public group element used as the base |
| `A` | Public value corresponding to an unknown exponent `a` |
| `B` | Public value corresponding to an unknown exponent `b` |
| `enc` | Hexadecimal encoding of 37 ciphertext bytes |

For Diffie-Hellman:

```text
A = g^a mod p
B = g^b mod p
shared = B^a mod p = A^b mod p = g^(ab) mod p
```

The public values are not themselves the secret. The missing quantity is an exponent or an equivalent way to compute the shared group element.

**Next step:** measure the modulus and choose an attack whose cost fits its size.

## 3. Identify the weakness

The modulus is:

```text
p = 255793885307
p.bit_length() = 38
```

A direct search over exponents can require far too many iterations. BSGS reduces the work from roughly the size of the exponent range to its square root, at the expense of storing a lookup table.

Using `N = p - 1` as an upper bound:

```text
m = ceil(sqrt(N)) = 505761
```

This requires roughly half a million stored baby steps and at most a comparable number of giant steps. That is practical for a Python script on a desktop, although a Python dictionary has substantially more overhead than the raw integer data it stores.

Additional arithmetic checks on this sample establish:

```text
p is prime
p - 1 = 2 * 127896942653
ord_p(4) = 127896942653
```

The factor `127896942653` is prime. The base `4` generates a subgroup of that order, not the entire multiplicative group of order `p - 1`. BSGS still works with the larger bound `p - 1`; knowing the exact subgroup order is not necessary for our solver.

The weakness exploited here is the tiny group size. It is not necessary to exploit a smooth group order or solve either participant's original random-number-generation process.

**Next step:** derive BSGS so that the implementation follows directly from the equation we need to solve.

## 4. Derive baby-step giant-step

We want an exponent `a` such that:

```text
g^a = A  (mod p)
```

Write a candidate exponent as:

```text
a = i*m + j
```

where `0 <= j < m`. Substitute and rearrange:

```text
g^(i*m + j) = A                  (mod p)
g^j = A * (g^(-m))^i             (mod p)
```

This creates two collections that can be matched.

### Baby steps

Store:

```text
g^j mod p -> j
```

for `j = 0, 1, ..., m-1`. Calculate successive values by multiplying by `g` modulo `p`, rather than performing a fresh exponentiation each time.

### Giant steps

Start from `A` and repeatedly multiply by:

```text
factor = inverse(g^m mod p) mod p
```

At giant-step index `i`, the current value is:

```text
A * (g^(-m))^i mod p
```

If it appears in the baby-step table at index `j`, then:

```text
a = i*m + j
```

Always verify the recovered exponent with modular exponentiation before using it.

### Match for this sample

```text
m = 505761
i = 38391
j = 126060

a = 38391 * 505761 + 126060
  = 19416796611
```

Verification:

```text
pow(4, 19416796611, 255793885307) == 98480505109
```

This is a valid exponent representing `A`. Exponents are equivalent modulo the order of `g`, so we do not need to claim that it is the exact original integer sampled by the challenge generator.

**Next step:** use this exponent with the other public value to obtain the shared secret.

## 5. Compute the shared secret

```python
shared = pow(B, a, p)
```

Result:

```text
109775021590
```

Only one exponent needs to be recovered. Assuming the advertised Diffie-Hellman construction, `B = g^b`; therefore exponents equivalent modulo the order of `g` also produce the same `B^a` shared secret.

At this point the group problem is solved, but the file does not specify how the shared integer becomes encryption bytes. We must investigate the keystream format separately.

## 6. Infer the keystream construction

### 6.1 Separate known facts from hypotheses

We know the ciphertext and expected flag prefix `PCT{`. We do not know the encryption implementation from the attachment alone. A short ciphertext without an accompanying IV or nonce makes a deterministic XOR stream a reasonable hypothesis, but it does not prove that hypothesis.

Initial tests of a repeated digest of the secret and common pseudorandom-byte constructions did not yield the flag. The useful next hypothesis was a counter-based hash stream, which can provide more bytes than one digest.

### 6.2 Use the known prefix

Under the XOR-stream hypothesis:

```text
ciphertext = plaintext XOR keystream
keystream = ciphertext XOR plaintext
```

The first four ciphertext bytes and expected plaintext give:

```text
Ciphertext prefix: a4 70 28 4f
Plaintext PCT{:    50 43 54 7b
Required stream:  f4 33 7c 34
```

We can test candidate secret encodings, separators, counter encodings, and hash functions against this four-byte value without guessing the remaining flag.

The matching construction was:

```python
hashlib.sha256(b"109775021590|0").digest()
```

That means the decimal ASCII secret, a literal pipe character, and a decimal ASCII counter starting at zero. The full digest gives a readable first 32-byte plaintext block:

```text
PCT{p4ra7h4_ciph3r_chi7ral_gwad4
```

A four-byte prefix match alone would be limited evidence. The readable continuation and complete flag obtained with the next counter strongly support this inferred construction.

### 6.3 Extend to the second block

The ciphertext contains 37 bytes, while SHA-256 produces 32 bytes. Repeating the first digest incorrectly decrypts the last five bytes. Instead, concatenate fresh counter blocks:

```text
K0 = SHA256(ASCII("109775021590|0"))
K1 = SHA256(ASCII("109775021590|1"))
keystream = K0 || K1
```

Take only the first 37 keystream bytes and XOR with the ciphertext. The first 32 bytes end at `...gwad4`, and the second block supplies the final five bytes, `r_10}`. This boundary follows the byte count, not the visual word boundaries in the flag.

The recovered flag is:

```text
PCT{p4ra7h4_ciph3r_chi7ral_gwad4r_10}
```

**Next step:** make both the discrete-log recovery and the inferred key schedule reproducible in complete scripts.

## 7. Complete script 1: solve and decrypt

Save as `solve_small_dh.py`. Requires Python 3.8+ and only the standard library. It parses the attachment with `ast.literal_eval` rather than executing its contents, solves the discrete log, checks the public value, builds the inferred stream, and verifies byte-for-byte re-encryption.

```python
#!/usr/bin/env python3
"""Solve the supplied Small Diffie-Hellman challenge."""
import argparse
import ast
import hashlib
import math
from pathlib import Path


def read_parameters(path):
    fields = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        name, value = line.split("=", 1)
        fields[name.strip()] = ast.literal_eval(value.strip())
    for name in ("p", "g", "A", "B"):
        if type(fields.get(name)) is not int:
            raise ValueError(f"Missing or invalid integer: {name}")
    ciphertext = bytes.fromhex(fields["enc"])
    return fields["p"], fields["g"], fields["A"], fields["B"], ciphertext


def bsgs(g, target, p):
    # p - 1 is a sufficient exponent bound for this prime-modulus sample.
    bound = p - 1
    m = math.isqrt(bound) + 1
    baby = {}
    value = 1
    for j in range(m):
        baby.setdefault(value, j)
        value = value * g % p
    factor = pow(pow(g, m, p), -1, p)
    value = target % p
    for i in range(m + 1):
        if value in baby:
            j = baby[value]
            exponent = i * m + j
            if exponent < bound and pow(g, exponent, p) == target % p:
                return exponent, m, i, j
        value = value * factor % p
    raise ValueError("No discrete logarithm found within the bound")


def make_stream(shared, length):
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        message = f"{shared}|{counter}".encode("ascii")
        stream.extend(hashlib.sha256(message).digest())
        counter += 1
    return bytes(stream[:length])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    p, g, A, B, ciphertext = read_parameters(args.input)
    a, m, i, j = bsgs(g, A, p)
    print("Modulus bits:", p.bit_length())
    print("Ciphertext bytes:", len(ciphertext))
    print("BSGS step size:", m)
    print(f"BSGS match: i={i}, j={j}")
    print("Recovered exponent:", a)
    if pow(g, a, p) != A:
        raise SystemExit("Public-value verification failed")
    print("Public-value verification: passed")
    shared = pow(B, a, p)
    print("Shared secret:", shared)
    stream = make_stream(shared, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, stream))
    if not (plaintext.startswith(b"PCT{") and plaintext.endswith(b"}")):
        raise SystemExit(f"Unexpected plaintext: {plaintext!r}")
    print("Flag:", plaintext.decode("ascii"))
    rebuilt = bytes(x ^ k for x, k in zip(plaintext, stream))
    if rebuilt != ciphertext:
        raise SystemExit("Re-encryption mismatch")
    print("Re-encryption matches: True")


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve_small_dh.py output.txt
```

Output:

```text
Modulus bits: 38
Ciphertext bytes: 37
BSGS step size: 505761
BSGS match: i=38391, j=126060
Recovered exponent: 19416796611
Public-value verification: passed
Shared secret: 109775021590
Flag: PCT{p4ra7h4_ciph3r_chi7ral_gwad4r_10}
Re-encryption matches: True
```

## 8. Complete script 2: reproduce the keystream inference

Save as `probe_small_dh_stream.py`. This standalone script takes the recovered shared secret and checks a bounded collection of candidate hash-stream formats against the known `PCT{` prefix. It then prints the full plaintext for matching candidates.

This is a reproducible diagnostic search, not a claim that the attachment specifies any of these constructions. It tests decimal/hexadecimal/binary secret encodings, several hashes and separators, ASCII or binary counters starting at zero or one, and both orders of secret and counter.

```python
#!/usr/bin/env python3
"""Probe counter-hash XOR streams using the known PCT{ prefix."""
import argparse
import ast
import hashlib
from pathlib import Path


def encode_counter(value, style):
    if style == "ascii":
        return str(value).encode("ascii")
    width, byteorder = style
    return value.to_bytes(width, byteorder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("shared", type=int)
    args = parser.parse_args()
    fields = {}
    for line in args.input.read_text().splitlines():
        if line.strip():
            name, value = line.split("=", 1)
            fields[name.strip()] = ast.literal_eval(value.strip())
    ciphertext = bytes.fromhex(fields["enc"])
    known = b"PCT{"
    wanted = bytes(c ^ p for c, p in zip(ciphertext[:4], known))
    print("Required stream prefix:", wanted.hex())
    shared = args.shared
    width = max(1, (shared.bit_length() + 7) // 8)
    sources = [str(shared).encode(), hex(shared).encode(),
               format(shared, "x").encode()]
    sources += [shared.to_bytes(n, order)
                for n in sorted({width, max(width, 8), max(width, 16)})
                for order in ("big", "little")]
    styles = ["ascii"] + [(n, order) for n in (1, 2, 4, 8)
                           for order in ("big", "little")]
    for source in dict.fromkeys(sources):
        for algorithm in ("sha256", "sha512", "sha1", "md5"):
            for separator in (b"", b"|", b":", b"-", b"_", b",", b" "):
                for style in styles:
                    for start in (0, 1):
                        for reverse in (False, True):
                            def block(counter):
                                c = encode_counter(counter, style)
                                message = (c + separator + source if reverse
                                           else source + separator + c)
                                return hashlib.new(algorithm, message).digest()
                            first = block(start)
                            if first[:4] != wanted:
                                continue
                            stream = bytearray(first)
                            counter = start + 1
                            while len(stream) < len(ciphertext):
                                stream.extend(block(counter))
                                counter += 1
                            plaintext = bytes(c ^ k for c, k
                                              in zip(ciphertext, stream))
                            print("Match:", algorithm, repr(source),
                                  repr(separator), style, start, reverse)
                            print("Plaintext:", repr(plaintext))


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 probe_small_dh_stream.py output.txt 109775021590
```

The matching candidate uses SHA-256, secret bytes `b'109775021590'`, separator `b'|'`, ASCII counters starting at `0`, and secret-before-counter order. The full recovered plaintext is the flag above.

## 9. Verification and its limits

The result is supported by distinct checks:

- **Discrete-log check:** the recovered exponent exactly reproduces `A` under the supplied `g` and `p`.
- **Plaintext check:** the inferred stream produces a complete readable flag in the required format across both hash blocks.
- **Round-trip check:** applying the inferred stream to that plaintext exactly reproduces the supplied ciphertext.

The XOR round-trip is an implementation consistency check. It is not authentication and does not independently prove a guessed key schedule, because any XOR stream round-trips its own decrypted output. The meaningful evidence for the schedule is the known-prefix match followed by a coherent full flag using consecutive counters. No challenge-server submission or encryption-source inspection was performed.

## 10. Common mistakes

| Mistake | Consequence | Correction |
|---|---|---|
| Treating a 12-digit decimal modulus as large | Overestimates the search difficulty | Measure its bit length and square-root cost |
| Brute-forcing both exponents | Adds unnecessary work | Recover one exponent, then compute the shared secret |
| Assuming `g` generates the full group | Misstates the group structure | A subgroup is sufficient; use a valid exponent bound |
| Computing `B*a` or `B XOR a` | Does not implement Diffie-Hellman | Use `pow(B, a, p)` |
| Claiming the exact original private integer | Discrete logs are defined modulo group order | Report a verified representative exponent |
| Hashing the wrong secret encoding | Produces a different stream | Use decimal ASCII in the inferred format |
| Using a hex digest as keystream | ASCII hex differs from digest bytes | Use `.digest()` |
| Repeating the first SHA-256 digest | Corrupts bytes after the first block | Hash the next counter |
| Starting the counter at one | Shifts the entire stream | Start at zero |
| Treating re-encryption as an authentication tag | Overstates the evidence | Separate consistency from authenticity |

## 11. What made the challenge solvable?

The public Diffie-Hellman parameters expose a discrete-log problem in a tiny group. BSGS makes that problem practical with a table of about half a million entries. Once a valid exponent is recovered, the shared secret follows immediately.

The remaining task is format discovery: determine how the shared integer becomes bytes. The known flag prefix provides a short keystream fingerprint, and testing a counter-hash construction reveals the complete message. The solution therefore combines a mathematical attack with careful handling of serialization, counters, and XOR.

**Final flag:**

```text
PCT{p4ra7h4_ciph3r_chi7ral_gwad4r_10}
```
