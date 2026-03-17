# Immobilzed
---
| Field       | Detail                        |
|-------------|-------------------------------|
| **CTF**     | VulnByDefault (VBD) CTF  |
| **Category**| Misc / Car Hacking            |
| **Points**  | 100                           |
| **Difficulty** | Medium                       |
| **Flag Format** | `VBD{}`                     |
| **Author**  | VBD                           |

---

## Challenge

> Immobilzed
> Something doesn't fit.

We are provided with a single file: `can_capture.log`. This appears to be a standard `candump` log file from a Linux SocketCAN interface.

## Analysis

### 1. Log Inspection
Opening `can_capture.log`, we see standard CAN traffic patterns. Frequently appearing IDs include `7DF` and `7E8` (standard OBD-II diagnostic request/response pairs) and high-frequency data IDs like `130`, `1A0`, `309`.

However, scanning for less frequent IDs or those with varying payloads often reveals hidden data in simple CTFs. We filtered the log by ID.

```bash
# Count occurrences of each ID
cat can_capture.log | awk '{print $3}' | cut -d# -f1 | sort | uniq -c
```

Most IDs appeared 25+ times. However, ID **`5EC`** appeared only 4 times.

```
(1710000000.654272) vcan0 5EC#00081D241A57535C
(1710000001.440098) vcan0 5EC#01AC93C5C4959192
(1710000002.136490) vcan0 5EC#027C25227F2F2B7F
(1710000003.029090) vcan0 5EC#03A5A0F1F0E89697
```

In automotive networks, `0x5EC` is sometimes associated with immobilizer or security exchange data, fitting the challenge name.

### 2. Payload Structure
The payloads are 8 bytes long (standard CAN frame size).
Looking at the first byte of each `5EC` frame, we see a clear sequence: `00`, `01`, `02`, `03`. This acts as a sequence counter (ISO-TP style or custom multi-frame transport).

The remaining 7 bytes of each frame likely contain the encrypted flag.

**Data Segments:**
*   Frame 0: `08 1D 24 1A 57 53 5C`
*   Frame 1: `AC 93 C5 C4 95 91 92`
*   Frame 2: `7C 25 22 7F 2F 2B 7F`
*   Frame 3: `A5 A0 F1 F0 E8 96 97`

### 3. Decryption Logic
The challenge hint "Something doesn't fit" usually implies a disjoint pattern.
We know the flag starts with `VBD{`. Let's test a simple XOR against the first frame.

**Frame 0 Analysis:**
*   Cipher: `08 1D 24 1A ...`
*   Known: `V  B  D  {  ...` (ASCII: `56 42 44 7B`)
*   Key calculation:
    *   `08 ^ 56 = 5E`
    *   `1D ^ 42 = 5F`
    *   `24 ^ 44 = 60`
    *   `1A ^ 7B = 61`

The key increments sequentially (`5E`, `5F`, `60`, `61`...).
If we extend this pattern for Frame 0:
*   `57 ^ 62 = 35` ('5')
*   `53 ^ 63 = 30` ('0')
*   `5C ^ 64 = 38` ('8')

Decoded Frame 0: **`VBD{508`**

**Frame 1 & 2 Analysis:**
The key sequence does *not* continue linearly from Frame 0 to Frame 1 (e.g., 65, 66...). Instead, it seems to "reset" or "jump" to a new start value for each frame, but remains sequential *within* the frame.

Through brute-forcing the "Start Key" for Frame 1 and 2 to produce ASCII Hex characters:
*   **Frame 1** (Start Key `0x9F`): `AC 93 ...` ^ `9F A0 ...` -> **`33df657`**
*   **Frame 2** (Start Key `0x45`): `7C 25 ...` ^ `45 46 ...` -> **`9ce7fa4`**

**Frame 3 Analysis:**
Payload: `A5 A0 F1 F0 E8 96 97`
We expect the flag to end with `}`. In standard buffers, strings are often null-terminated.
Hypothesis: The payload ends with `}` followed by `\0\0`.
*   Last byte `97` -> `\0` implies Key `0x97`.
*   2nd last byte `96` -> `\0` implies Key `0x96`.
*   3rd last byte `E8` -> `}` (0x7D) implies Key `0x95` (`E8 ^ 7D = 95`).

The key sequence `... 95 96 97` is sequential!
Extrapolating backwards to the start of the frame (Index 0): Key must be **`0x91`**.

Decoding Frame 3 with Start Key `0x91`:
*   `A5` ^ `91` = `34` ('4')
*   `A0` ^ `92` = `32` ('2')
*   `F1` ^ `93` = `62` ('b')
*   `F0` ^ `94` = `64` ('d')
*   `E8` ^ `95` = `7D` ('}')
*   `96` ^ `96` = `00`
*   `97` ^ `97` = `00`

Decoded Frame 3: **`42bd}`**

### 4. Solve Script

```python
def solve():
    # Extracted payloads (excluding the first byte counter)
    frames = [
        bytes.fromhex("081D241A57535C"),
        bytes.fromhex("AC93C5C4959192"),
        bytes.fromhex("7C25227F2F2B7F"),
        bytes.fromhex("A5A0F1F0E89697")
    ]
    
    # Determined Start Keys for each frame
    # F0: Matches 'VBD{'
    # F1, F2: Brute-forced for Hex characters
    # F3: Back-calculated from closing brace '}' and null bytes
    keys = [0x5E, 0x9F, 0x45, 0x91]
    
    flag = ""
    
    for i, frame in enumerate(frames):
        start_key = keys[i]
        decoded_chunk = ""
        for j, byte in enumerate(frame):
            # Sequential Key Logic: Key[j] = Start_Key + j
            current_key = (start_key + j) % 256
            
            val = byte ^ current_key
            if val != 0: # Ignore null padding
                decoded_chunk += chr(val)
        
        flag += decoded_chunk
        print(f"Frame {i}: {decoded_chunk}")

    print(f"\nFlag: {flag}")

if __name__ == "__main__":
    solve()
```

## Flag

`VBD{50833df6579ce7fa442bd}`
