# Encryption 101

---
| Field       | Detail                        |
|-------------|-------------------------------|
| **CTF**     | VulnByDefault (VBD) CTF  |
| **Category**| Reversing                     |
| **Points**  | 75                            |
| **Difficulty** | Easy                       |
| **Flag Format** | `VBD{}`                  |

---

## Challenge

We are given a `challenge.jar` file. Running it prints:

```
Startup failed, invalid password.
```

## Analysis

### 1. JAR Contents

```bash
unzip -l challenge.jar
```

| File | Purpose |
|------|---------|
| `com/vulnbydefault/ctf/Main.class` | Entry point (obfuscated) |
| `com/vulnbydefault/ctf/FlagKeeper.class` | Holds encrypted flag array + decryption logic (obfuscated) |
| `META-INF/MANIFEST.MF` | Contains hidden Base64 config |
| `META-INF/.classes/com.vulnbydefault.ctf.FlagKeeper` | Encrypted backup of FlagKeeper |
| `META-INF/.classes/com.vulnbydefault.ctf.Main` | Encrypted backup of Main |
| `META-INF/.classes/org.springframework.config.PassHash` | MD5 hash hint |
| `build-config.properties` | Contains hex-encoded vendor ID |

### 2. Extracting Hints

**MANIFEST.MF** â€” Hidden Base64 value:

```
X-Build-Config: U3VwM3JTM2N1cjNfUjRtNGQ0bjIwMjY=
```

```bash
echo "U3VwM3JTM2N1cjNfUjRtNGQ0bjIwMjY=" | base64 -d
# Sup3rS3cur3_R4m4d4n2026
```

**build-config.properties** â€” Hex-encoded vendor ID:

```
vendor.id=56756e427944656661756c74
```

```python
bytes.fromhex("56756e427944656661756c74").decode()
# "VunByDefault"
```

**PassHash file:**

```
eff263f8cc440753acf1c01d02b3756b
```

(MD5 hash â€” red herring / validator)

### 3. Bytecode Analysis

Using `javap -c -p FlagKeeper.class`, we find the encrypted flag array:

```java
private static final int[] ENC = {
    4, 3, 9, 90, 107, 121, 125, 24, 48, 117,
    117, 20, 54, 115, 44, 66, 48, 118, 126, 24,
    100, 35, 126, 19, 106, 34, 121, 16, 51, 113,
    47, 16, 107, 32, 44, 25, 47
};
```

All methods (`k()`, `assembleFlag()`, `verify()`, `getFlag()`) are obfuscated with NOP sleds and infinite `goto` loops, making jadx and other decompilers fail with "unreachable blocks."

The constant pool references `Math.pow(2.0, 6.0)` = **64**, which equals `0x40`.

### 4. Key Derivation (The Solve)

Since the flag format starts with `VBD{` and ends with `}`, we can derive the XOR key by XORing the known plaintext against the ciphertext:

```python
enc = [4, 3, 9, 90, 107, 121, 125, 24, ...]

# XOR first 4 encrypted bytes with known prefix "VBD{"
key[0] = 4  ^ ord('V') = 4  ^ 86 = 82  = 'R'
key[1] = 3  ^ ord('B') = 3  ^ 66 = 65  = 'A'
key[2] = 9  ^ ord('D') = 9  ^ 68 = 77  = 'M'
key[3] = 90 ^ ord('{') = 90 ^ 123 = 33 = '!'

# Verify with last byte (must be '}'):
enc[36] ^ key[36 % 4] = 47 ^ 82 = 125 = '}'  âœ“
```

**XOR key: `RAM!`** (4 bytes, repeating)

## Solve Script

```python
enc = [4, 3, 9, 90, 107, 121, 125, 24, 48, 117,
       117, 20, 54, 115, 44, 66, 48, 118, 126, 24,
       100, 35, 126, 19, 106, 34, 121, 16, 51, 113,
       47, 16, 107, 32, 44, 25, 47]

key = [ord(c) for c in "RAM!"]

flag = "".join(chr(enc[i] ^ key[i % 4]) for i in range(len(enc)))
print(flag)
```

## Flag

```
VBD{9809b485d2acb7396b328c41a0b19aa8}
```

## Key Takeaways

- The `.class` files were obfuscated with NOP sleds + goto loops (anti-decompilation)
- The actual crypto was a simple **repeating-key XOR** with a 4-byte key
- Known-plaintext attack using the flag format `VBD{...}` instantly reveals the key
- The hidden files in `META-INF/.classes/` and Base64/hex hints were distractions.

