# Batcave Bitflips - Writeup

**Points:** 100
**Difficulty:** rev medium
**Author:** gregt114 (Greg)

## Challenge Description
Batman's new state-of-the-art AI agent has deleted all of the source code to the Batcave license verification program! There's an old debug version lying around, but that thing has been hit by more cosmic rays than Superman!

**Hints:**
1. BatAI estimates there are 3 bugs
2. Rotation rotation rotation!
3. Something about that SBOX seems off...

## Analysis

We are given an ELF 64-bit executable `batcave_license_checker`. Running or statically analyzing the binary reveals the following control flow:
1. It reads a `LICENSE KEY` from standard input.
2. It expands this key into a 64-byte state and runs a heavy hashing algorithm for over 12 million rounds (`12513007` rounds).
3. The hash algorithm incorporates:
   - A byte substitution layer using a 256-byte `SBOX`.
   - A mixing layer XORing adjacent elements.
   - A bitwise rotation layer.
4. The resulting hash is compared against a 32-byte `EXPECTED` buffer stored in the binary.
5. If the hash matches the `EXPECTED` buffer, it calls a `decrypt_flag` function to decrypt and print the `FLAG` buffer.

### The Three Bugs (Cosmic Rays)
The challenge hints refer to three "bitflips" or bugs due to cosmic rays:
1. **SBOX Bitflip:** An entry in the `SBOX` array was altered slightly from its intended mathematical property.
2. **Rotation Bitflip:** Standard bitwise rotation operations typically use shifts of 3 or 5, but the operation here was altered to an incorrect bit shift (e.g., rotating by 6 instead of 5).
3. **In-place Mix Bug:** The mix algorithm applies `st[i] ^= st[(i+1)&63] ^ st[63-i];` in a single pass. Because it operates in-place, updating `st[i]` cascades into the later calculations (specifically when `i > 31` interacting with `63-i`), making the hashing function extremely chaotic and irreversible.

### The Bypass

While one *could* attempt to un-bitflip the executable by identifying the three exact hardware bugs and mathematically reversing the hash algorithm or forging a hash-collision, there is a much cleaner realization.

We know the program uses a successful verification to trigger `decrypt_flag`. The decryption mechanism simply takes a 32-byte key stream and XORs it with the encrypted flag buffer. In the binary, the `EXPECTED` buffer resides at offset `0x3040` completely intact, and the encrypted `FLAG` resides directly after it at `0x3060`. 

Testing the raw `EXPECTED` bytes directly as the XOR key against the `FLAG` bytes effortlessly bypasses the 12 million round hash execution and the three bitflips!

When we pull the 32 bytes of `EXPECTED` and the 32 bytes of `FLAG` and mutually XOR them:
`EXPECTED ^ FLAG` = `UMASS{__p4tche5_0n_p4tche$__#}\x00\xee...`

## Solution Script

```python
#!/usr/bin/env python3
from pathlib import Path

def solve():
    # Load the binary
    p = Path('batcave_license_checker').read_bytes()
    
    # Extract the EXPECTED and FLAG buffers
    # EXPECTED is located at offset 0x3040
    # FLAG is located at offset 0x3060
    expected = p[0x3040:0x3060]
    flag_enc = p[0x3060:0x3080]
    
    # Perform the XOR decryption
    decrypted_flag = bytes(f ^ e for f, e in zip(flag_enc, expected))
    
    # The flag is a null-terminated string, so extract up to the null byte
    flag = decrypted_flag.split(b'\x00')[0].decode()
    
    print(f"Recovered Flag: {flag}")

if __name__ == '__main__':
    solve()
```

## Conclusion

Running the script gives us the flag, completely sidestepping the broken rotational logic, the corrupted SBOX, and the faulty in-place mixing arrays!

**Recovered Flag:** `UMASS{__p4tche5_0n_p4tche$__#}`