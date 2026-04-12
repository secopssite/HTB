# HTB Search Keywords & SEO Optimization

<!-- 
HTB Global Search Optimization Guide:
- Include challenge names, variations, and common misspellings
- Include vulnerability types and CVEs
- Include tool names and techniques
- Include full flags for searchability
- Use HTB{...} format for flags
-->

## Garfield
**Challenge:** Garfield, garfield.htb, DC01.garfield.htb, RODC01.garfield.htb  
**Category:** Windows, Active Directory, RODC, Kerberos  
**Difficulty:** Hard  
**Keywords:** rodc golden ticket, keylist attack, resource based constrained delegation, rbcd, krbtgt_8245, read-only domain controller, evil-winrm, bloodhound acl abuse, logon script abuse, scriptpath manipulation, powercat reverse shell, tunneling to rodc, impacket ticket converter, nxc ntds dump, dcsync rodc, administrator hash capture  
**Tags:** #rodc #golden-ticket #keylist #rbcd #kerberos #windows #active-directory #hard #hackthebox #bloodhound #acl-abuse  
**Techniques:** ACL abuse via BloodHound, Logon script path manipulation (scriptPath), RBCD configuration on RODC, RODC Golden Ticket forgery, KeyList attack to retrieve legitimate Administrator ticket, LAPS abuse, NTDS.dit extraction  
**Flags:**
- User: `507962c068a3688b1c5878b0a7e3badc`
- Root: `9490fac0230b0e288cdf451038321104`
**Search Terms:** hackthebox garfield walkthrough, garfield htb writeup, garfield.htb rodc, rodc golden ticket attack, keylist kerberos attack, rbcd resource based constrained delegation, krbtgt_8245 key extraction, active directory rodc abuse, evil-winrm l.wilson_adm, impacket ticket converter, nxc ntds dump dcsync, hackthebox windows rodc hard, bloodhound acl scriptpath abuse, garfield.htb administrator ticket

## Hercules  
**Challenge:** Hercules, hercules.htb, dc.hercules.htb  
**Category:** Active Directory, Windows  
**Difficulty:** Insane  
**Keywords:** ldap injection, shadow credentials, certipy, ESC3, enrollment agent, usersignature, dcom cert request, rbcd, iis_webserver$, u2u, s4u2self, s4u2proxy, dcsync, kerberos, bloodyAD, winrm  
**Tags:** #active-directory #windows #esc3 #shadow-credentials #rbcd #kerberos #dcsync #hackthebox  
**Techniques:** LDAP filter injection, Shadow Credentials, AD object move/ACL abuse, ESC3 via DCOM, service-account abuse, U2U+S4U, DCSync  
**Search Terms:** hackthebox hercules walkthrough, hercules htb writeup, certipy esc3 dcom, iis_webserver$ u2u s4u2proxy, shadow credentials hercules, dcsync hercules

## Silentium
**Challenge:** Silentium, silentium.htb, staging.silentium.htb, staging-v2-code.dev.silentium.htb  
**Category:** Linux, AI Platform, Docker, Git  
**Difficulty:** Easy  
**Keywords:** flowise, flowise ai, flowise rce, flowise exploit, flowise 3.0.5, CVE-2025-59528, flowise custommcp, flowise function constructor, flowise password reset, flowise token disclosure, x-request-from internal, gogs, gogs rce, gogs exploit, gogs symlink, CVE-2025-8110, gogs git config injection, gogs sshcommand, docker credential harvesting, environment variable leak, password reuse, ssh lateral movement, nginx vhost, subdomain discovery  
**Tags:** #linux #easy #flowise #gogs #docker #ai-platform #rce #cve-2025-59528 #cve-2025-8110 #hackthebox #credential-harvesting #symlink-attack #password-reuse  
**Techniques:** Virtual host discovery, Flowise API password reset token disclosure via x-request-from internal header, Flowise CustomMCP JavaScript injection via Function() constructor (CVE-2025-59528), Docker container environment variable credential harvesting, SSH password reuse lateral movement, Gogs symlink-based .git/config overwrite RCE via API (CVE-2025-8110), Gogs captcha bypass via API registration  
**Flags:**
- User: `af682b00e02e1e4c9dd0aaa9f271e7af`
- Root: `7b7fab8c83b9bdb403cd60f3118533c8`
**Search Terms:** hackthebox silentium walkthrough, silentium htb writeup, silentium htb walkthrough, silentium hackthebox easy, flowise rce exploit, flowise custommcp exploit, CVE-2025-59528 exploit, CVE-2025-59528 poc, flowise 3.0.5 vulnerability, flowise password reset token disclosure, flowise x-request-from internal bypass, gogs symlink rce, gogs git config injection exploit, CVE-2025-8110 exploit, CVE-2025-8110 poc, gogs sshcommand rce, docker env credential harvesting, silentium.htb flowise, staging.silentium.htb, htb easy linux ai platform, flowise ai hackthebox, gogs privilege escalation root

## DevArea  
**Challenge:** DevArea, devarea.htb, devarea  
**Category:** Linux, Web, API  
**Difficulty:** Medium  
**Keywords:** apache cxf, xop include, mtom, soap file read, local file inclusion, hoverfly, hoverfly middleware, jwt auth, reverse shell, syswatch, writable bash, privilege escalation, jetty, linux privesc  
**Tags:** #linux #web #soap #mtom #xop #hoverfly #jwt #reverse-shell #sudo #privilege-escalation #hackthebox  
**Techniques:** XOP/MTOM arbitrary file read, service credential extraction, API authentication abuse, middleware command execution, writable binary hijack, sudo-assisted privesc  
**Search Terms:** hackthebox devarea walkthrough, devarea htb writeup, devarea hoverfly exploit, apache cxf xop mtom file read, hoverfly middleware rce, syswatch bash hijack, writable /usr/bin/bash privilege escalation

## HTB Labs Categories & Common Terms

### Web Exploitation
- SQL injection, SQLi, Union Based, Error Based, Blind SQLi, Time-based
- XSS, Cross Site Scripting, Stored XSS, Reflected XSS, DOM XSS
- CSRF, Cross Site Request Forgery, XSRF
- JWT, JSON Web Token, JWT cracking, JWT manipulation
- OAuth, SAML, SSO bypass
- SSTI, Server Side Template Injection, Jinja2, Twig
- SSRF, Server Side Request Forgery
- LFI, Local File Inclusion, RFI, Remote File Inclusion
- XXE, XML External Entity
- IDOR, Insecure Direct Object Reference
- Path Traversal, Directory Traversal, ../ ..\

### Binary Exploitation / Pwn
- Buffer Overflow, BOF, Stack Overflow, Heap Overflow
- Format String, Format String Bug
- ROP, Return Oriented Programming
- Shellcode, Egg Hunter, ASLR bypass, NX bypass
- GOT overwrite, PLT, GOT, RELRO
- Canary, Stack Canary bypass
- Use After Free, UAF, Double Free
- Integer Overflow, Integer Underflow

### Cryptography
- RSA, AES, DES, 3DES, Blowfish
- Hash cracking, MD5, SHA1, SHA256, bcrypt, scrypt, argon2
- Base64, Base32, Hex, URL encoding, ROT13, Caesar Cipher
- XOR, Vigenere, Substitution Cipher
- Padding Oracle, CBC, ECB mode
- JWT cracking, Token manipulation

### Forensics & Steganography
- Memory dump analysis, Volatility, Rekall
- Network forensics, PCAP analysis, Wireshark, tshark
- File carving, Foremost, Scalpel, Bulk Extractor
- Steganography, Steghide, zsteg, stegsolve, OpenStego
- EXIF data, Metadata analysis, ExifTool
- LSB steganography, PNG, BMP, JPEG analysis

### Reverse Engineering
- Static analysis, IDA Pro, Ghidra, Radare2, Binary Ninja
- Dynamic analysis, x64dbg, OllyDbg, GDB, LLDB
- Decompilation, Disassembly, Assembly x86/x64, ARM
- Anti-debugging, Packing, UPX, Unpacking
- Malware analysis, YARA, IOC

### OSINT & Reconnaissance
- Subdomain enumeration, Sublist3r, Amass, assetfinder
- Google Dorking, GHDB, Advanced search operators
- Social engineering, Phishing, Pretexting
- Metadata extraction, Document analysis
- WHOIS, DNS reconnaissance, dig, nslookup
- Certificate transparency, crt.sh, Censys, Shodan

### Network Security
- Nmap, Masscan, Rustscan, Port scanning
- SMB, SMBClient, RPCClient, Enum4linux
- LDAP, LDAP enumeration, Active Directory
- Kerberos, AS-REP Roasting, Kerberoasting
- SNMP, SNMP enumeration, onesixtyone, snmpwalk
- FTP, Anonymous FTP, vsftpd, ProFTPD
- SSH, Bruteforce, Key cracking

### Privilege Escalation
- Linux privesc, SUID, SGID, Capabilities, sudoers
- Windows privesc, SeImpersonate, Token abuse, UAC bypass
- Kernel exploits, CVE, Local exploits
- Path hijacking, LD_PRELOAD, DLL hijacking
- Scheduled tasks, Cron jobs, AT jobs
- Service abuse, Unquoted Service Path, Weak permissions

## Tools & Utilities

### Enumeration
- Nmap, Nmap scripting engine, NSE scripts
- Gobuster, Dirbuster, Feroxbuster, Dirsearch, FFUF
- Nikto, Whatweb, Wafw00f
- Enum4linux, Enum4linux-ng, SMBmap
- LinPEAS, WinPEAS, PEASS-ng
- LinEnum, PowerUp, PowerView, BloodHound

### Exploitation
- Metasploit, MSFconsole, MSFvenom, Meterpreter
- SQLMap, Commix, XXEinjector
- Burp Suite, OWASP ZAP, Caido
- Netcat, Ncat, Socat, Powercat
- Chisel, Ligolo-ng, Tunneling tools
- Impacket, PSExec, WMIexec, SMBexec, ATexec, DCOMexec

### Password Cracking
- John the Ripper, John, Johnny
- Hashcat, Hashcat modes, Rule-based attacks
- Hydra, Medusa, Patator, Crowbar
- CrackMapExec, CME
- Wordlists, Rockyou, SecLists, PayloadsAllTheThings

### Web Shells & Payloads
- Webshells, PHP shell, ASP shell, JSP shell
- Reverse shells, Bash, Python, Perl, Ruby, PowerShell
- Bind shells, Staged payloads, Stageless payloads
- msfvenom payloads, Encoders, Evasion techniques

---

**Search Optimization Note:**
This repository is optimized for HTB global search and general search engine visibility.
All write-ups include:
- Full challenge names and variations
- Complete flags in HTB{...} format
- Relevant CVEs and vulnerability types
- Tool names and commands used
- Technique names and methodology
- Common search terms and keywords

**Author Info:** No author information is included in write-ups to maintain anonymity.

