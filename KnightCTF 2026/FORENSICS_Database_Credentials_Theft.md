# KnightCTF 2026 - Forensics: Database Credentials Theft

## Challenge Information
- **Category:** Forensics
- **Points:** 100
- **File:** pcap3.pcapng
- **Author:** TareqAhamed (0xt4req)

## Challenge Description
The attacker's ultimate goal was to access our database. During the post-exploitation phase, they managed to extract database credentials from the compromised system. Find the database username and password that were exposed.

**Flag Format:** `KCTF{username_password}`

---

## Solution

### Step 1: Context from Previous Challenges
From the previous pcap analysis:
- Target: WordPress 6.9 on 192.168.1.102
- Vulnerable plugin: Social Warfare 3.5.2 (CVE-2019-9978)
- The attacker exploited RCE to gain access to the system

### Step 2: Search for Database Credentials
After exploiting the RCE vulnerability, attackers typically read `wp-config.php` to extract database credentials.

```bash
strings pcap3.pcapng | grep -iE 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST'
```

### Step 3: Results
Found WordPress database configuration:

```php
// Default template values
define( 'DB_NAME', 'database_name_here' );
define( 'DB_USER', 'username_here' );
define( 'DB_PASSWORD', 'password_here' );
define( 'DB_HOST', 'localhost' );

// Actual credentials exposed
define( 'DB_NAME', 'wordpress_db' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'wp@user123' );
define( 'DB_HOST', 'localhost' );
```

### Extracted Credentials

| Field | Value |
|-------|-------|
| Database Name | wordpress_db |
| Username | wpuser |
| Password | wp@user123 |
| Host | localhost |

---

## Flag
```
KCTF{wpuser_wp@user123}
```

---

## Attack Chain Summary
1. **Reconnaissance** - Attacker scanned WordPress for vulnerable plugins
2. **Exploitation** - Used Social Warfare 3.5.2 RCE (CVE-2019-9978)
3. **Post-Exploitation** - Read wp-config.php to extract DB credentials
4. **Goal Achieved** - Database credentials stolen

---

## Tools Used
- strings
- grep
