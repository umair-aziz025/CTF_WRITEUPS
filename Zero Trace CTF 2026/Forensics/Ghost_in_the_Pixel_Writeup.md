# Ghost in the Pixel — 300

The challenge provides a file `ghost.png` which appears to be a standard PNG image, but contains hidden data appended to it. Analyzing the image structure reveals C2PA metadata and an appended ZIP archive.

## Flag

```text
PCT{gh0st_1n_th3_p1x3l_z3r0_tr4c3}
```

## Step-by-step writeup

### 1. Analyze the PNG Chunks

By inspecting the PNG chunks, we find a large `caBX` (C2PA metadata) chunk along with custom `tEXt` chunks. The text chunks include:

- **Author**: `ghost`
- **Software**: `pct-wiper v0.3`
- **Comment**: `cGFzc3dvcmQ6bjBfdHI0YzNfbDNmdA==`

Decoding the Base64 comment yields the password:

```text
password:n0_tr4c3_l3ft
```

### 2. Extract the Hidden Archive

Continuing past the `IEND` chunk of the PNG, we encounter standard ZIP archive magic bytes (`PK\x03\x04`). 
Extracting the appended bytes yields a hidden ZIP file (`ghost_data.zip`), which contains an encrypted file named `server.log`.

### 3. Decrypt and Recover the Flag

Using the password recovered from the metadata (`n0_tr4c3_l3ft`), we extract `server.log`. The contents show the attacker's activities:

```text
[2026-10-07 23:41:02] sshd[2210]: Accepted publickey for ghost from 10.13.37.5
[2026-10-07 23:41:19] sudo: ghost : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow
[2026-10-07 23:42:07] cron[881]: (ghost) CMD (/opt/wipe_logs.sh)
[2026-10-07 23:42:31] audit: exfil_token=UENUe2doMHN0XzFuX3RoM19wMXgzbF96M3IwX3RyNGMzfQ==
[2026-10-07 23:43:55] sshd[2210]: session closed for user ghost
```

The `exfil_token` is Base64 encoded. Decoding it gives us the flag:

```text
PCT{gh0st_1n_th3_p1x3l_z3r0_tr4c3}
```
