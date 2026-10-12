# Hidden Table — Detailed Forensics Write-up

**Category:** Forensics / Mobile Database Analysis  
**Category Value:** 90 points  
**Provided file:** `app.db`  
**Flag format:** `PCT{...}`

> A mobile app's local database. Look carefully at everything it stores.

---

## 1. Result and overall approach

The recovered flag is:

```text
PCT{ch3ck_3v3ry_t4bl3}
```

The challenge provides an SQLite 3 database file named `app.db` (12,288 bytes) representing local data storage for a mobile application.

The investigation workflow follows a logical sequence:

1. Open `app.db` using `sqlite3` and query `sqlite_master` to enumerate all stored tables.
2. Identify three tables: `contacts`, `notes`, and internal cache table `_sync_cache`.
3. Inspect `_sync_cache` to find the key `session_token` with value `UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ==`.
4. Perform Base64 decoding on `UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ==`.
5. Recover the flag: `PCT{ch3ck_3v3ry_t4bl3}`.

**Next step:** analyze the database schema and tables.

---

## 2. Initial inspection & SQLite schema enumeration

Querying `sqlite_master` returns the schema definitions:

```sql
SELECT type, name, sql FROM sqlite_master;
```

### Table Definitions:

1. **`contacts`**:
   `CREATE TABLE contacts(id INTEGER PRIMARY KEY, name TEXT, email TEXT)`
2. **`notes`**:
   `CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)`
3. **`_sync_cache`**:
   `CREATE TABLE _sync_cache(k TEXT, v TEXT)`

**Next step:** inspect data contents across all tables.

---

## 3. Vulnerability analysis: Insecure Local Data Storage

Mobile applications frequently store sensitive session tokens, API keys, or cached credentials in local SQLite databases without encryption at rest (SQLCipher).

### Data Inspection Summary:

- **`contacts`**: `[(1, 'alice', 'alice@corp.local'), (2, 'bob', 'bob@corp.local'), (3, 'carol', 'carol@corp.local')]`
- **`notes`**: `[(1, 'remember to rotate keys')]`
- **`_sync_cache`**: `[('session_token', 'UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ==')]`

### Base64 Token Decoding

$$\text{Base64}^{-1}(\text{"UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ=="}) \longrightarrow \text{"PCT\{ch3ck\_3v3ry\_t4bl3\}"}$$

**Next step:** present the complete Python solver script.

---

## 4. Step-by-Step Table Inspection Procedure

$$\begin{array}{|c|l|l|l|}
\hline
\text{Table Name} & \text{Key / Column} & \text{Stored Value} & \text{Analysis} \\
\hline
\text{contacts} & \text{email} & \text{alice@corp.local, bob@corp.local} & \text{Standard application user data} \\
\text{notes} & \text{body} & \text{"remember to rotate keys"} & \text{Internal text note} \\
\text{\_sync\_cache} & \text{session\_token} & \texttt{UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ==} & \mathbf{\text{Base64 Encoded Flag Payload}} \\
\hline
\end{array}$$

**Next step:** write and execute the complete Python solver script.

---

## 5. Complete Python Solver Script

Below is the complete standalone Python 3 script (`hidden_table_solve.py`):

```python
#!/usr/bin/env python3
"""
Hidden Table Solver
Challenge: "A mobile app's local database. Look carefully at everything it stores."

Vulnerability / Analysis:
1. `app.db` is an SQLite 3 database file.
2. Enumerating tables via `sqlite_master` reveals three tables: `contacts`, `notes`, and `_sync_cache`.
3. Querying table `_sync_cache` reveals a key-value entry:
     k = 'session_token'
     v = 'UENUe2NoM2NrXzN2M3J5X3Q0YmwzfQ=='
4. Base64 decoding the cached value yields:
   PCT{ch3ck_3v3ry_t4bl3}
"""

import os
import sqlite3
import base64

def solve():
    base_dir = os.path.dirname(__file__)
    db_path = os.path.join(base_dir, "app.db")

    if not os.path.exists(db_path):
        print(f"[-] Database file not found: {db_path}")
        return None

    print(f"[*] Opening SQLite database {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Enumerate all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"[*] Discovered SQLite Tables: {tables}")

    flag = None
    for table_name in tables:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        print(f"    Table '{table_name}' ({len(rows)} rows)")
        for row in rows:
            for item in row:
                if isinstance(item, str) and item.startswith("UENUe"):
                    decoded = base64.b64decode(item).decode("utf-8", errors="ignore")
                    if decoded.startswith("PCT{"):
                        flag = decoded
                        print(f"[+] Found flag in table '{table_name}': {flag}")

    conn.close()

    if flag:
        print(f"\n==========================================")
        print(f"  FLAG: {flag}")
        print(f"==========================================")
        return flag
    else:
        print("[-] Flag not found in database.")
        return None

if __name__ == "__main__":
    solve()
```

**Next step:** verify solver output.

---

## 6. Execution and Verification

Running the script:

```bash
$ python hidden_table_solve.py
```

### Execution Output:

```text
[*] Opening SQLite database 1. ctf/TODAY\app.db...
[*] Discovered SQLite Tables: ['contacts', 'notes', '_sync_cache']
    Table 'contacts' (3 rows)
    Table 'notes' (1 rows)
    Table '_sync_cache' (1 rows)
[+] Found flag in table '_sync_cache': PCT{ch3ck_3v3ry_t4bl3}

==========================================
  FLAG: PCT{ch3ck_3v3ry_t4bl3}
==========================================
```

**Next step:** review common mistakes when auditing local SQLite databases.

---

## 7. Common Mistakes & Pitfalls

| Mistake | Consequence | Correction |
|---|---|---|
| Querying only primary user tables (`contacts`) | Overlooking hidden/internal system tables (`_sync_cache`) | Inspect `sqlite_master` to list all tables and views |
| Assuming database tokens are encrypted | Treating Base64 strings as hashes | Recognize `UENUe...` Base64 prefix for `PCT{` and decode |

---

## 8. What Made the Challenge Solvable?

1. **Standard Unencrypted SQLite Format:** Accessible using standard `sqlite3` tools.
2. **Accessible Master Schema:** All table names were listed in `sqlite_master`.
3. **Reversible Token Encoding:** Base64 session token stored without cryptographic hashing.

---

## Final Flag

```text
PCT{ch3ck_3v3ry_t4bl3}
```
