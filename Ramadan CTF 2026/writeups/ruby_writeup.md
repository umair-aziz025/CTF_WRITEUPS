# Ruby
---
**CTF:** VulnByDefault CTF  
**Challenge:** Ruby  
**Category:** Misc / Reverse Engineering  
**Difficulty:** Medium  
**Flag:** `VBD{82776878}`

---

## 1. Challenge Overview

The challenge prompt was essentially:

> Play the game and get the flag.

At first glance, the challenge name `Ruby` suggested a programming-language challenge or maybe a scripting puzzle. That turned out to be a misdirection.

The provided files were inside:

```text
1. ctf/new/dist/dist/
â”œâ”€â”€ challenge.schem
â””â”€â”€ MyWorld/
```

That immediately changed the direction of the solve. A `.schem` file plus a full Minecraft world save strongly suggested that the real target was not source code, but a Minecraft-based logic or redstone system.

---

## 2. Initial Recon

### 2.1 Provided Artifacts

The two important artifacts were:

- `challenge.schem`
- `MyWorld/`

Inside `MyWorld`, the key file was `level.dat`, which identified the world as:

```text
LevelName: Computer v2 by mattbatwings
```

That was the first major clue.

### 2.2 What This Meant

This was not a normal Minecraft map challenge where you explore, click buttons, and read signs. It was a challenge built on top of a **redstone computer**.

So the real task became:

1. Identify the computer architecture
2. Recover the program stored in the schematic
3. Reverse the program logic
4. Derive the numeric flag

---

## 3. Identifying the Architecture

The `level.dat` string `Computer v2 by mattbatwings` pointed directly to Mattbatwings' public redstone CPU project.

Using that clue, the architecture was identified as:

```text
BatPU-2
```

From the public project materials, the following details were recovered:

- 16-bit instructions
- 1024 instruction memory slots
- Separate data memory
- An assembler with mnemonics like:
  - `nop`, `hlt`, `add`, `sub`, `nor`, `and`, `xor`, `rsh`
  - `ldi`, `adi`, `jmp`, `brh`, `cal`, `ret`, `lod`, `str`
- I/O ports mapped in the `240-255` range
- The number display is controlled through port `250`

That was enough to start decoding the program stored in `challenge.schem`.

---

## 4. Understanding the Schematic

### 4.1 Why the `.schem` File Matters

The schematic was not just a build file for decoration. It contained the machine's **instruction ROM** encoded as redstone components.

The BatPU-2 schematic generator writes each 16-bit instruction using repeaters and wool blocks:

- repeater = bit `1`
- wool = bit `0`

The program memory layout from the upstream generator made it possible to reconstruct the exact instruction stream.

### 4.2 Decoding Result

After reconstructing the address layout and reading the bit columns from the schematic, the ROM contained:

- 1024 total instruction slots
- only **37 non-zero instructions**

That was a strong sign that this was a small deterministic computation rather than an actual game that needed to be played manually.

---

## 5. Recovered Program Logic

The important non-zero instructions reduced to two stages:

### Stage 1: Initialize Data

The program loads eight constants and stores them in data memory.

Recovered values:

```text
55, 101, 41, 100, 125, 57, 35, 109
```

The relevant instruction pattern looked like this in behavior:

```text
RAM[0] = 55
RAM[1] = 101
RAM[2] = 41
RAM[3] = 100
RAM[4] = 125
RAM[5] = 57
RAM[6] = 35
RAM[7] = 109
```

### Stage 2: Process Pairs and Display Output

The second part of the program loops over those values in pairs:

```text
(RAM[0], RAM[1])
(RAM[2], RAM[3])
(RAM[4], RAM[5])
(RAM[6], RAM[7])
```

For each pair, it:

1. loads the first value
2. loads the second value
3. XORs them
4. writes the result to the number-display port

---

## 6. Important Reversal Detail

The key thing that made the solve click was interpreting the BatPU-2 `STR` instruction correctly.

In this ISA:

```text
STR base src offset
```

means:

```text
memory[base + offset] = src
```

So when the disassembly showed instructions equivalent to:

```text
LDI r1 0
LDI r2 55
STR r1 r2 0
```

that does **not** mean "store into address 55" or "write to register 55".

It means:

```text
RAM[0] = 55
```

Once that operand order was interpreted correctly, the program became straightforward.

---

## 7. Manual Emulation

Now compute the XOR for each adjacent pair.

### Pair 1

```text
55 ^ 101 = 82
```

### Pair 2

```text
41 ^ 100 = 77
```

### Pair 3

```text
125 ^ 57 = 68
```

### Pair 4

```text
35 ^ 109 = 78
```

So the four displayed outputs are:

```text
82 77 68 78
```

Concatenating them gives:

```text
82776878
```

---

## 8. Final Flag

```text
VBD{82776878}
```

---

## 9. Why This Challenge Was Tricky

This challenge was tricky for a few reasons:

- The name `Ruby` pushes you toward the wrong ecosystem.
- The prompt says "Play the game," which suggests manual interaction.
- The actual payload is hidden inside a Minecraft redstone CPU schematic.
- You need to recognize the architecture before any of the files make sense.
- The solve depends on understanding a custom ISA, especially the operand semantics of `LOD` and `STR`.

In reality, this was a compact ROM-reversing challenge disguised as a Minecraft world.

---

## 10. Short Solve Summary

1. Inspect the provided files and notice `challenge.schem` plus `MyWorld/`.
2. Parse `level.dat` and identify `Computer v2 by mattbatwings`.
3. Recognize the machine as **BatPU-2**.
4. Reconstruct the 16-bit ROM from the schematic layout.
5. Disassemble the 37 non-zero instructions.
6. Recover the initialized RAM values: `55, 101, 41, 100, 125, 57, 35, 109`.
7. Observe that the loop XORs adjacent pairs and writes the results to the number display.
8. Compute outputs: `82, 77, 68, 78`.
9. Concatenate them to get `82776878`.
10. Submit `VBD{82776878}`.

---

## 11. Reproduction Snippet

Once the values are known, the flag derivation is just:

```python
vals = [55, 101, 41, 100, 125, 57, 35, 109]
outs = [vals[i] ^ vals[i + 1] for i in range(0, 8, 2)]
print(outs)                       # [82, 77, 68, 78]
print(''.join(map(str, outs)))    # 82776878
```

---

## 12. Takeaway

The challenge was solved without "playing" the Minecraft world at all. The faster route was to treat the world and schematic as a serialized program, recover the BatPU-2 machine code, and emulate the tiny algorithm by hand.

That turned a misleading misc challenge into a clean reverse-engineering problem.

