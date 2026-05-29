# Smart Brick v2 (hardware / PCB)

Category: hardware PCB medium  
CTF: UMass CTF 2026

## Challenge Summary
We were given a KiCad PCB file:
- `ctf/smart-brick-v2.kicad_pcb`

Hints strongly suggested:
1. The file format is KiCad PCB.
2. There are 7 inputs (so likely 7-bit ASCII).
3. Use Python with `kiutils`.

The board is a combinational logic circuit built from 74LS logic ICs. Each output drives a MOSFET/LED channel. The intended solve is to model logic constraints and solve for which 7-bit input lights each LED.

## Recon
Loaded the PCB with `kiutils` and enumerated components.

Relevant ICs present:
- 74LS00 (NAND)
- 74LS02 (NOR)
- 74LS04 (NOT)
- 74LS08 (AND)
- 74LS20 (dual 4-input NAND)
- 74LS21 (dual 4-input AND)
- 74LS27 (triple 3-input NOR)
- 74LS32 (OR)
- 74LS86 (XOR)

Also:
- 19x 2N7002 MOSFETs (`Q1..Q19`) used as LED drivers
- 19x LEDs (`D1..D19`)

Inputs are nets `/IN0.. /IN6`.

## Solve Strategy
For each gate package, map pinout to boolean equations over KiCad nets.

Then for each MOSFET gate net (pad 1 of each `Qn`), solve SAT with constraint:
- gate net = True

Read model values of `/IN0.. /IN6` as a 7-bit ASCII character.

Because each `Qn` solved to exactly one input character, concatenating Q1..Q19 gives the full flag.

## Solver Script
```python
import re
from kiutils.board import Board
from z3 import *

p = r"C:\Users\stxrdust\Desktop\Internships\Deltaware_Solution\ctf\smart-brick-v2.kicad_pcb"
b = Board().from_file(p)

netv = {n.name: Bool(n.name) for n in b.nets if n.name}
for i in range(7):
    netv[f"/IN{i}"] = Bool(f"IN{i}")

def pnet(fp, num):
    for pd in fp.pads:
        if pd.number == str(num):
            return pd.net.name if pd.net else None
    return None

constraints = []
for fp in b.footprints:
    val = fp.properties.get("Value")

    if val == "74LS00":
        for o, a, bn in [(3,1,2), (6,4,5), (8,9,10), (11,12,13)]:
            on, an, bnn = pnet(fp,o), pnet(fp,a), pnet(fp,bn)
            if on and an and bnn:
                constraints.append(netv[on] == Not(And(netv[an], netv[bnn])))

    elif val == "74LS02":
        for o, a, bn in [(1,2,3), (4,5,6), (10,8,9), (13,11,12)]:
            on, an, bnn = pnet(fp,o), pnet(fp,a), pnet(fp,bn)
            if on and an and bnn:
                constraints.append(netv[on] == Not(Or(netv[an], netv[bnn])))

    elif val == "74LS32":
        for o, a, bn in [(3,1,2), (6,4,5), (8,9,10), (11,12,13)]:
            on, an, bnn = pnet(fp,o), pnet(fp,a), pnet(fp,bn)
            if on and an and bnn:
                constraints.append(netv[on] == Or(netv[an], netv[bnn]))

    elif val == "74LS86":
        for o, a, bn in [(3,1,2), (6,4,5), (8,9,10), (11,12,13)]:
            on, an, bnn = pnet(fp,o), pnet(fp,a), pnet(fp,bn)
            if on and an and bnn and "unconnected" not in on and "unconnected" not in an and "unconnected" not in bnn:
                constraints.append(netv[on] == Xor(netv[an], netv[bnn]))

    elif val == "74LS08":
        for o, a, bn in [(3,1,2), (6,4,5), (8,9,10), (11,12,13)]:
            on, an, bnn = pnet(fp,o), pnet(fp,a), pnet(fp,bn)
            if on and an and bnn:
                constraints.append(netv[on] == And(netv[an], netv[bnn]))

    elif val == "74LS04":
        for o, a in [(2,1), (4,3), (6,5), (8,9), (10,11), (12,13)]:
            on, an = pnet(fp,o), pnet(fp,a)
            if on and an and "unconnected" not in on and "unconnected" not in an:
                constraints.append(netv[on] == Not(netv[an]))

    elif val == "74LS20":
        on = pnet(fp,6)
        ins = [pnet(fp,x) for x in [1,2,4,5]]
        if on and all(ins):
            constraints.append(netv[on] == Not(And(*[netv[x] for x in ins])))

        on = pnet(fp,8)
        ins = [pnet(fp,x) for x in [9,10,12,13]]
        if on and all(ins):
            constraints.append(netv[on] == Not(And(*[netv[x] for x in ins])))

    elif val == "74LS21":
        on = pnet(fp,6)
        ins = [pnet(fp,x) for x in [1,2,4,5]]
        if on and all(ins):
            constraints.append(netv[on] == And(*[netv[x] for x in ins]))

        on = pnet(fp,8)
        ins = [pnet(fp,x) for x in [9,10,12,13]]
        if on and all(ins):
            constraints.append(netv[on] == And(*[netv[x] for x in ins]))

    elif val == "74LS27":
        # triple 3-input NOR
        for o, ins in [(12,[1,2,13]), (6,[3,4,5]), (8,[9,10,11])]:
            on = pnet(fp,o)
            iv = [pnet(fp,x) for x in ins]
            if on and all(iv):
                constraints.append(netv[on] == Not(Or(*[netv[x] for x in iv])))

qs = []
for fp in b.footprints:
    if fp.properties.get("Value") == "2N7002":
        ref = fp.properties.get("Reference")
        m = re.match(r"Q(\d+)$", ref or "")
        if m:
            qs.append((int(m.group(1)), pnet(fp,1), ref))
qs.sort()

out = ""
for idx, g, ref in qs:
    s = Solver()
    s.add(*constraints)
    s.add(netv[g] == True)

    if s.check() != sat:
        out += "?"
        continue

    m = s.model()
    bits = [1 if is_true(m[netv[f"/IN{i}"]]) else 0 for i in range(7)]
    v = sum(bits[i] << i for i in range(7))
    out += chr(v) if 32 <= v < 127 else "?"

print(out)
```

## Output
The solver returns:

`UMASS{In_Th3_G4t3s}`

## Final Flag
`UMASS{In_Th3_G4t3s}`
