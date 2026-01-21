# WaF - Web Challenge Writeup

**CTF:** KnightCTF 2026  
**Challenge:** WaF  
**Category:** Web  
**Points:** 100  
**Author:** badhacker0x1  

---

## Challenge Description

> You can't get the /flag.txt ever.
>
> Link: http://45.56.66.96:7789/

**Hint from Discord:**
- Author: "no need for any parameters"

---

## Initial Reconnaissance

### Accessing the Web Application

When we visit the main page, we see a simple HTML form:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Bee</title>
</head>
<body>
  <p>Input your name:</p>
  <form action="/huraaaaa.html" method="GET">
    <input a="{a}" type="text" required>
    <button type="submit">Submit</button>
  </form>

  <!-- @app.after_request
    def index(filename: str = "index.html"):
    if ".." in filename or "%" in filename:
        return "No no not like that :("
    -->
</body>
</html>
```

### Key Observations

1. **HTML Comment Leak**: The source code reveals a Flask `@app.after_request` function that filters requests
2. **WAF Rules**: The application blocks any filename containing `".."` or `"%"`
3. **Interesting Response**: Direct access to `/flag.txt` returns `"Something wrong!!"`

### Testing Basic Paths

```bash
# Direct flag access
curl http://45.56.66.96:7789/flag.txt
# Returns: Something wrong!!

# Known working endpoints
curl http://45.56.66.96:7789/index.html  # Works
curl http://45.56.66.96:7789/hello.html  # Works
```

---

## Analysis

### WAF Bypass Research

The challenge title "WaF" suggests we need to bypass a Web Application Firewall. The HTML comment reveals:

```python
if ".." in filename or "%" in filename:
    return "No no not like that :("
```

This means:
- Path traversal with `..` is blocked
- URL encoding with `%` is blocked
- The filter checks the literal strings `".."` and `"%"`

### The Hint

The author's Discord hint was crucial: **"no need for any parameters"**

This suggests:
1. We shouldn't use query parameters like `?file=flag.txt`
2. The bypass must be in the URL path itself
3. We need to find a way to traverse directories without using `..` or `%`

---

## The Breakthrough

### Curly Brace Expansion Bypass

In some web servers and frameworks (like Flask with certain configurations), curly braces `{}` can be used for glob pattern matching or path expansion:

- `{.}` can expand to `.` (single dot)
- `{.}{.}` expands to `..` (two dots) **without containing the literal string ".."**

This bypasses the WAF because:
1. The string `"{.}{.}"` doesn't contain `".."`
2. The server processes it AFTER the WAF check
3. The expansion happens at the filesystem level

### Path Traversal Without ".."

To reach the root directory and access `flag.txt`, we can use:

```
/{.}{.}/{.}{.}/flag.txt
```

This expands to:
```
/../../flag.txt
```

But crucially, the WAF only sees `{.}{.}` which doesn't match its filter!

---

## Exploitation

### Final Payload

```bash
curl http://45.56.66.96:7789/{.}{.}/{.}{.}/flag.txt
```

### Response

```
KCTF{7fdbbcd6c3cee0ae65c5ca327c14a25f6e473d1c}
```

---

## Technical Deep Dive

### Why This Works

1. **Flask Static File Handling**: Flask's `send_file()` or similar functions process the path
2. **Glob Pattern Expansion**: The `{.}` pattern is expanded by the underlying filesystem or glob library
3. **Order of Operations**:
   ```
   Request → WAF Check (sees {.}{.}) → Path Expansion (becomes ..) → File Access
   ```

### Alternative Bypass Attempts (Failed)

We tried many other techniques that didn't work:

1. **URL Encoding Variations**:
   - `%2e%2e` (blocked by `%` filter)
   - Double encoding `%252e` (still contains `%`)

2. **Unicode Normalization**:
   - Fullwidth dot `．` (U+FF0E)
   - One dot leader `․` (U+2024)
   - These didn't expand properly

3. **Path Variations**:
   - `/./flag.txt` (no traversal)
   - `//flag.txt` (no traversal)
   - `/proc/self/cwd/flag.txt` (incorrect path)

4. **HTTP Header Tricks**:
   - `X-Original-URL`
   - `X-Rewrite-URL`
   - Different HTTP methods (POST, PUT, HEAD)

5. **Query Parameters**:
   - Author explicitly said "no need for any parameters"
   - All attempts with `?file=`, `?path=`, etc. returned errors

---

## Key Takeaways

1. **Read Error Messages Carefully**: The HTML comment was a huge hint
2. **Listen to Hints**: "no need for any parameters" was the key insight
3. **WAF Bypass Creativity**: Sometimes the bypass is about character expansion/interpretation
4. **Order of Operations**: Understanding when filters apply vs when expansion happens
5. **Glob Patterns**: `{.}` expansion is a lesser-known technique for bypassing string-based filters

---

## Flag

```
KCTF{7fdbbcd6c3cee0ae65c5ca327c14a25f6e473d1c}
```

---

## References

- [Glob Pattern Matching](https://en.wikipedia.org/wiki/Glob_(programming))
- [Flask Path Handling](https://flask.palletsprojects.com/en/2.0.x/api/#flask.send_file)
- [WAF Bypass Techniques](https://owasp.org/www-community/attacks/Path_Traversal)

---

**Author:** MR. Umair  
**Date:** January 21, 2026  
**LinkedIn:** [linkedin.com/in/umairaziz001](https://www.linkedin.com/in/umairaziz001/)
