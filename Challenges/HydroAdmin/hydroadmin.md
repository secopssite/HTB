<div align="center">

# HydroAdmin — HackTheBox

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
| Challenge | HydroAdmin |
| Category | Web |
| Difficulty | Easy |
| Points | 20 |
| Creator | lordrukie |
| Vulnerability | GraphQL Batching Attack |

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

> With reservoirs sealed and cities teetering on thirst, our heroes storm the HydroAdmin control room to reopen valves and restore the flow of water.

---

## Reconnaissance

The target hosts an **HTB Editor** — a web-based code editor that displays the source code of a vulnerable application. The goal is to identify and patch the vulnerability.

### Initial Probe

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/directory | python3 -m json.tool
```

The application is a **Node.js + GraphQL** water management system with:
- Apollo Server with GraphQL endpoint at `/challenge/graphql`
- GraphQL Armor protection (alias limiting, depth limiting)
- Session-based PIN authentication for control room access
- Rate limiting (10 requests/minute)

### Check Vulnerability Status

```bash
curl -s http://<CHALLENGE_IP>:<PORT>/api/verify
```

```json
{"error": "Application vulnerability is not patched."}
```

---

## Source Code Analysis

### Key Files

```bash
# Read the source files
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=index.js"
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=schema/resolvers.js"
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=models/ControlPin.js"
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=utils/middleware.js"
curl -s "http://<CHALLENGE_IP>:<PORT>/api/file?path=exploit/solver.py"
```

### Application Flow

1. A 4-digit PIN (1000-9999) is generated via `generatePin` GraphQL query
2. Users must verify the PIN via `verifyAccessPin` GraphQL mutation
3. Successful PIN verification grants session-based access to `/control-room`
4. The control room page contains the flag

### Rate Limiting (middleware.js)

```javascript
export const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => {
    return req.ip;
  },
});
```

The rate limiter allows only **10 HTTP requests per minute** per IP — seemingly making brute-force impossible for 9000 possible PINs.

### The Vulnerable Configuration (index.js)

```javascript
const server = new ApolloServer({
  ...armor.protect(),
  introspection: false,
  typeDefs,
  allowBatchedHttpRequests: true,  // <-- VULNERABILITY
  resolvers
});
```

---

## Understanding the Vulnerability

### GraphQL Batching Attack

When `allowBatchedHttpRequests` is set to `true`, Apollo Server accepts **arrays of GraphQL operations** in a single HTTP request. Each operation is executed independently, but the rate limiter only counts it as **one request**.

**The math:**
- Rate limit: 10 requests/minute
- PIN space: 9000 values (1000-9999)
- Batch size: 1500 operations per request
- Requests needed: 9000 / 1500 = **6 HTTP requests**
- Time: Well under the 1-minute rate limit window

### Solver Logic (solver.py)

The exploit:

1. **Generate a fresh PIN** via GraphQL query
2. **Build batched mutation arrays** — each batch contains 1500 `verifyAccessPin` mutations with different PINs
3. **Send the batch as a single HTTP POST** — rate limiter sees 1 request, but 1500 PINs are tested
4. **Check for `"authorized": true`** in any response
5. **Access the control room** with the session cookie from the successful verification

```python
def create_batch_query(start_pin, end_pin):
    queries = []
    for pin in range(start_pin, end_pin):
        pin_str = f"{pin:04d}"
        query = {
            "query": f'mutation{{verifyAccessPin(pin:"{pin_str}"){{authorized}}}}'
        }
        queries.append(query)
    return queries

# Send 1500 mutations in ONE HTTP request
batch_queries = create_batch_query(batch_start, batch_end)
response = post(f"{BASE_URL}/graphql", json=batch_queries)
```

The rate limiter at `/challenge/graphql` counts this as a single request, but Apollo processes all 1500 mutations inside it.

---

## Patching the Vulnerability

### The Fix

Change `allowBatchedHttpRequests` from `true` to `false` in `index.js`:

**Before (vulnerable):**

```javascript
const server = new ApolloServer({
  ...armor.protect(),
  introspection: false,
  typeDefs,
  allowBatchedHttpRequests: true,
  resolvers
});
```

**After (patched):**

```javascript
const server = new ApolloServer({
  ...armor.protect(),
  introspection: false,
  typeDefs,
  allowBatchedHttpRequests: false,
  resolvers
});
```

### Apply the Patch

```bash
# Save the patched file
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/save" \
  -H "Content-Type: application/json" \
  -d '{"path":"index.js","content":"<PATCHED_CONTENT>"}'

# Restart the application
curl -s -X POST "http://<CHALLENGE_IP>:<PORT>/api/restart"

# Verify the fix
curl -s "http://<CHALLENGE_IP>:<PORT>/api/verify"
```

```json
{"flag": "HTB{gr4phql_b4tch1n6_4tt4ck_████████████████████████}"}
```

---

## Flag

| Flag | Value |
|------|-------|
| Challenge | `HTB{gr4phql_b4tch1n6_4tt4ck_████████████████████████}` |

---

## Key Takeaways

- **GraphQL batching** allows sending multiple operations in a single HTTP request — rate limiters that count HTTP requests (not operations) are bypassed
- `allowBatchedHttpRequests: true` in Apollo Server is dangerous when combined with rate limiting as the sole brute-force protection
- **Defense in depth**: rate limiting should be applied at the GraphQL operation level, not just the HTTP request level
- GraphQL Armor's `maxAliases` protection prevents **alias-based batching** but does NOT prevent **array-based batching** — they are different attack vectors
- PIN-based authentication with a small keyspace (4 digits = 10,000 combinations) requires additional protections beyond rate limiting: account lockout, CAPTCHA, or exponential backoff per failed attempt

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box — HydroAdmin*

</div>

<!-- HTB HydroAdmin Search Keywords -->
<!-- hydroadmin hackthebox, hydroadmin htb, hydroadmin htb writeup, hydroadmin htb walkthrough -->
<!-- graphql batching attack, graphql batch brute force, allowBatchedHttpRequests, apollo server batching -->
<!-- graphql rate limit bypass, graphql pin brute force, graphql mutation batching -->
<!-- htb easy web challenge, hackthebox easy challenge, htb challenge writeup -->
