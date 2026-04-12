# HTB Writeups & Exploit Kits

**SEO terms:** HackTheBox writeups, HTB walkthroughs, CTF solutions, penetration testing, ethical hacking, cybersecurity training, security research.

Public collection of Hack The Box machine writeups, challenge solutions, and helper scripts for authorized security training and CTF environments.

> **Search keywords:** HackTheBox, HTB, CTF, capture the flag, penetration testing, ethical hacking, security research, vulnerability assessment, exploit development, red team, blue team, purple team, infosec, cybersecurity, OSCP preparation.

---

## Included Machines (12 Total)

| Machine | Type | Difficulty | OS | Writeup |
|---------|------|------------|-----|---------|
| **CCTV** | Linux | Medium | Linux | [cctv.md](./cctv/cctv.md) |
| **DevArea** | Web / API | Medium | Linux | [devarea.md](./DevArea/devarea.md) |
| **Fries** | Windows + Linux / AD | Hard | Windows/Linux | [Fries.md](./Fries/Fries.md) |
| **Garfield** | Active Directory / RODC | Hard | Windows | [garfield.md](./Garfield/garfield.md) |
| **Hercules** | Active Directory | Insane | Windows | [hercules.md](./Hercules/hercules.md) |
| **HiddenPath** | Web / Misc | Easy | N/A | [hidden-path.md](./HiddenPath/hidden-path.md) |
| **Interpreter** | Linux | Medium | Linux | [interpreter.md](./Interpreter/interpreter.md) |
| **Kobold** | Linux | Easy | Linux | [kobold.md](./Kobold/kobold.md) |
| **LockedAway** | Python / Misc | Easy | N/A | [locked-away.md](./LockedAway/locked-away.md) |
| **Pirate** | Active Directory | Medium | Windows | [pirate.md](./Pirate/pirate.md) |
| **Silentium** | Linux / AI Platform | Easy | Linux | [silentium.md](./Silentium/silentium.md) |
| **VariaType (Avatar)** | Linux | Medium | Linux | [VariaType-Writeup.md](./VariaType/VariaType-Writeup.md) |

---

## Challenges (3 Total)

| Challenge | Category | Difficulty | Vulnerability | Writeup |
|-----------|----------|------------|---------------|---------|
| **CommNet** | Web | Easy | IDOR | [commnet.md](./Challenges/CommNet/commnet.md) |
| **AgriWeb** | Web | Easy | Prototype Pollution | [agriweb.md](./Challenges/AgriWeb/agriweb.md) |
| **ResourceHub Core** | Web | Easy | Path Traversal | [resourcehub.md](./Challenges/ResourceHub/resourcehub.md) |

---

## Quick Links to Writeups

### Linux Machines
- [CCTV Writeup](./cctv/cctv.md)
- [DevArea Writeup](./DevArea/devarea.md)
- [Interpreter Writeup](./Interpreter/interpreter.md)
- [Kobold Writeup](./Kobold/kobold.md)
- [Silentium Writeup](./Silentium/silentium.md)
- [VariaType Writeup](./VariaType/VariaType-Writeup.md)

### Windows / Active Directory
- [Fries Writeup](./Fries/Fries.md)
- [Garfield Writeup](./Garfield/garfield.md)
- [Hercules Writeup](./Hercules/hercules.md)
- [Pirate Writeup](./Pirate/pirate.md)

### CTF / Web Challenges
- [Hidden Path Writeup](./HiddenPath/hidden-path.md)
- [Locked Away Writeup](./LockedAway/locked-away.md)

---

## Machine Categories

### Linux Exploitation
- **CCTV** — Linux enumeration, service exploitation
- **DevArea** — Apache CXF, XOP/MTOM file read, Hoverfly middleware RCE
- **Interpreter** — Linux privilege escalation, script abuse
- **Kobold** — Linux kernel exploitation, container escape
- **Silentium** — Flowise AI platform exploitation, CVE-2025-59528, Docker credential harvesting, Gogs symlink RCE, CVE-2025-8110
- **VariaType (Avatar)** — Git extraction, PHP deserialization, RCE, privilege escalation

> **Keywords:** linux privesc, sudo abuse, SUID binaries, kernel exploits, container escape, git extraction, php deserialization, RCE, reverse shell, cron abuse, writable files, path hijacking, LD_PRELOAD, capabilities, SUID, GTFOBins, flowise rce, gogs symlink rce, docker credential harvesting, AI platform exploitation, CVE-2025-59528, CVE-2025-8110

### Windows / Active Directory
- **Fries** — Cross-platform AD exploitation, credential abuse, lateral movement
- **Garfield** — RODC abuse, Golden Ticket, KeyList attack, RBCD, BloodHound ACL analysis
- **Hercules** — LDAP injection, Shadow Credentials, Certipy ESC3, DCOM, DCSync
- **Pirate** — AD enumeration, Kerberoasting, service abuse

> **Keywords:** active directory exploitation, AD pentest, bloodhound, kerberoasting, as-rep roasting, golden ticket, silver ticket, dcsync, mimikatz, evil-winrm, impacket, crackmapexec, certipy, shadow credentials, RBCD, resource based constrained delegation, rodc, read-only domain controller, keylist attack, ldap injection, esc3, dcom exploit

### Web / CTF Challenges
- **HiddenPath** — Unicode homoglyph injection, JavaScript command injection, U+3164
- **LockedAway** — Python sandbox escape, blacklist bypass, chr() construction

> **Keywords:** python sandbox escape, chr bypass, blacklist bypass, python jailbreak, unicode injection, homoglyph attack, U+3164, invisible character, nodejs command injection, express destructuring, javascript prototype pollution

---

## Exploit Kits & Automation

### VariaType (Avatar) Automation
- [Full Exploit Script](./VariaType/exploit_variatype.sh)
- [Phase 1: Git Extract](./VariaType/phase1_git_extract.py)
- [Phase 2: RCE Exploit](./VariaType/phase2_rce_exploit.py)
- [Phase 3: Privesc Steve](./VariaType/phase3_privesc_steve.py)
- [Phase 4: Privesc Root](./VariaType/phase4_privesc_root.py)

---

## Tools & Techniques Reference

### Enumeration
- Nmap, NSE scripts, service detection
- Gobuster, Feroxbuster, directory enumeration
- SMB enumeration: smbclient, smbmap, enum4linux
- LDAP enumeration, Active Directory recon
- BloodHound, SharpHound

### Exploitation
- SQLMap, Commix, XXEinjector
- Burp Suite, OWASP ZAP
- Netcat, Ncat, Socat, Powercat
- Chisel, Ligolo-ng, tunneling
- Impacket suite: psexec, wmiexec, smbexec, atexec, dcomexec

### Post-Exploitation
- LinPEAS, WinPEAS
- PowerUp, PowerView
- Mimikatz, Rubeus
- Evil-WinRM
- CrackMapExec (CME)

### Kerberos & AD
- Rubeus: kerberoast, asreproast, golden ticket, silver ticket
- Certipy: ADCS abuse, ESC1-ESC15
- BloodHound: attack path analysis
- Impacket: GetNPUsers, GetUserSPNs, secretsdump

---

## SEO Keywords by Technique

### Web Security
SQL injection, SQLi, Union Based, Error Based, Blind SQLi, Time-based, XSS, Cross Site Scripting, Stored XSS, Reflected XSS, DOM XSS, CSRF, XSRF, JWT cracking, JWT manipulation, SSTI, Server Side Template Injection, Jinja2, Twig, SSRF, Server Side Request Forgery, LFI, Local File Inclusion, RFI, Remote File Inclusion, XXE, XML External Entity, IDOR, Insecure Direct Object Reference, Path Traversal, Directory Traversal

### Binary Exploitation
Buffer Overflow, BOF, Stack Overflow, Heap Overflow, Format String, ROP, Return Oriented Programming, Shellcode, ASLR bypass, NX bypass, GOT overwrite, Stack Canary, UAF, Use After Free, Integer Overflow

### Cryptography
RSA, AES, DES, Hash cracking, MD5, SHA1, SHA256, bcrypt, Base64, Hex, ROT13, Caesar Cipher, XOR, Padding Oracle, CBC mode

### Forensics
Memory dump analysis, Volatility, PCAP analysis, Wireshark, File carving, Foremost, Steganography, Steghide, EXIF data, Metadata analysis

### Network Security
Port scanning, SMB, RPC, LDAP, Kerberos, AS-REP Roasting, Kerberoasting, SNMP, FTP, SSH bruteforce

### Privilege Escalation
Linux privesc, SUID, SGID, Capabilities, sudoers, Windows privesc, SeImpersonate, Token abuse, UAC bypass, Kernel exploits, Path hijacking, LD_PRELOAD, DLL hijacking, Scheduled tasks, Cron jobs, Service abuse, Unquoted Service Path

---

## Hostname Keywords

`variatype.htb`, `portal.variatype.htb`, `fries.htb`, `cctv.htb`, `interpreter.htb`, `pirate.htb`, `devarea.htb`, `garfield.htb`, `dc01.garfield.htb`, `rodc01.garfield.htb`, `hercules.htb`, `dc.hercules.htb`, `silentium.htb`, `staging.silentium.htb`, `staging-v2-code.dev.silentium.htb`

---

## Note

Content is for authorized CTF/lab environments and security training purposes only. All writeups focus on educational value for defensive understanding and red team methodology.

---

## Repository Stats

- **Machines:** 12
- **Linux:** 6
- **Windows/AD:** 4
- **Web/Misc:** 2
- **Scripts:** 5

---

*Optimized for GitHub global search and security research discoverability.*
