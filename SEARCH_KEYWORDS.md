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

## CCTV
**Challenge:** CCTV, cctv.htb  
**Category:** Linux  
**Difficulty:** Medium  
**Keywords:** zoneminder, zoneminder rce, zoneminder v1.37.63, zoneminder filter rce, csrf bypass, default credentials, motionEye, motionEye api, command injection, snapshot_filename injection, SUID bash, apache 2.4.58, lateral movement, mysql credential extraction, password cracking, port 7999, port 8765  
**Tags:** #linux #medium #zoneminder #motioneye #command-injection #suid #hackthebox #cctv-monitoring #credential-reuse  
**Techniques:** ZoneMinder authenticated RCE via Filter CSRF bypass, default credential access (admin:admin), MySQL credential extraction, SSH lateral movement, motionEye API command injection via snapshot_filename, SUID bash privilege escalation  
**Search Terms:** hackthebox cctv walkthrough, cctv htb writeup, cctv.htb solution, zoneminder rce exploit, zoneminder v1.37.63 vulnerability, zoneminder filter rce csrf, motioneye command injection, motioneye api exploit, snapshot_filename injection, SUID bash privilege escalation, cctv monitoring system exploit, htb linux medium zoneminder

## DevArea  
**Challenge:** DevArea, devarea.htb, devarea  
**Category:** Linux, Web, API  
**Difficulty:** Medium  
**Keywords:** apache cxf, xop include, mtom, soap file read, local file inclusion, hoverfly, hoverfly middleware, jwt auth, reverse shell, syswatch, writable bash, privilege escalation, jetty, linux privesc  
**Tags:** #linux #web #soap #mtom #xop #hoverfly #jwt #reverse-shell #sudo #privilege-escalation #hackthebox  
**Techniques:** XOP/MTOM arbitrary file read, service credential extraction, API authentication abuse, middleware command execution, writable binary hijack, sudo-assisted privesc  
**Flags:**
- User: `b89d674708dc3048b9914a1fdab2c87a`
- Root: `8b726ff797c8e3ef31429da0920ddcb6`
**Search Terms:** hackthebox devarea walkthrough, devarea htb writeup, devarea hoverfly exploit, apache cxf xop mtom file read, hoverfly middleware rce, syswatch bash hijack, writable /usr/bin/bash privilege escalation

## Fries
**Challenge:** Fries, fries.htb, dc01.fries.htb, code.fries.htb, db-mgmt05.fries.htb  
**Category:** Windows, Linux, Active Directory, Hybrid  
**Difficulty:** Hard  
**Keywords:** gitea, gitea env leak, postgresql, pgadmin, CVE-2025-2945, pgadmin authenticated rce, metasploit, COPY FROM PROGRAM, password reuse, hydra, ssh brute force, NFS weak export, no_root_squash, docker tls abuse, sshuttle, pivoting, ldap credential capture, responder, bloodhound, ReadMSAPassword, gMSA, evil-winrm, pass-the-hash, ADCS abuse, ESC7, ESC6, ESC16, certipy-ad, bloodyAD, kerberos, smb, winrm, netexec, impacket, container escape  
**Tags:** #active-directory #windows #linux #hybrid #hard #hackthebox #adcs #esc7 #esc6 #gmsa #docker-tls #nfs #pgadmin #gitea  
**Techniques:** Gitea .env credential leak, PgAdmin authenticated access, PostgreSQL COPY FROM PROGRAM RCE, CVE-2025-2945 PgAdmin RCE, environment variable password reuse, SSH brute force, NFS no_root_squash exploitation, Docker TLS CA key abuse, LDAP redirect credential capture via Responder, BloodHound ReadMSAPassword gMSA dump, ADCS ESC7/ESC6/ESC16 certificate abuse, Domain Admin via certipy-ad  
**Search Terms:** hackthebox fries walkthrough, fries htb writeup, fries.htb solution, CVE-2025-2945 pgadmin rce, ADCS ESC7 ESC6 ESC16 certipy, gMSA ReadMSAPassword bloodhound, docker tls ca abuse, NFS no_root_squash exploit, ldap credential redirect responder, gitea env credential leak, htb hard hybrid active directory, pgadmin postgresql copy from program rce

## HiddenPath
**Challenge:** Hidden Path, HiddenPath, hidden-path  
**Category:** Web, Misc  
**Difficulty:** Easy  
**Keywords:** unicode homoglyph, command injection, U+3164, HANGUL JUNGSEONG FILLER, invisible character, nodejs, express, destructuring bypass, variable reference, array injection, system check endpoint, url encoding, python requests  
**Tags:** #web #misc #easy #hackthebox #unicode #command-injection #nodejs #express #invisible-character #homoglyph  
**Techniques:** Unicode homoglyph injection using U+3164 HANGUL JUNGSEONG FILLER invisible character, Node.js Express destructuring bypass, command injection via system check endpoint, array parameter injection  
**Flags:**
- Flag: `HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_6011a114c82501cf9d38d89d752075cd}`
**Search Terms:** hackthebox hidden path walkthrough, hiddenpath htb writeup, hidden-path htb solution, unicode injection exploit, U+3164 vulnerability, invisible character attack, nodejs command injection, express destructuring bypass, hangul jungseong filler exploit, htb easy web challenge, homoglyph injection ctf

## Interpreter
**Challenge:** Interpreter, interpreter.htb  
**Category:** Linux  
**Difficulty:** Medium  
**Keywords:** mirth connect, mirth connect 4.4.0, java deserialization rce, xstream, xml payload, reverse shell, mysql, credential extraction, PBKDF2, SHA-256, hashcat, password cracking, rockyou, template injection, SSTI, python internal service, localhost service exploitation  
**Tags:** #linux #medium #hackthebox #mirth-connect #java-deserialization #ssti #template-injection #hashcat #mysql  
**Techniques:** Mirth Connect 4.4.0 Java deserialization RCE via XStream XML payload, MySQL credential extraction, PBKDF2-SHA256 hash cracking with hashcat, SSH lateral movement, Python SSTI template injection on internal service for privilege escalation  
**Search Terms:** hackthebox interpreter walkthrough, interpreter htb writeup, interpreter.htb solution, mirth connect rce, mirth connect 4.4.0 exploit, java deserialization mirth xstream, template injection privilege escalation, PBKDF2 hash cracking hashcat, mysql credential dump, localhost service exploitation, htb linux medium mirth connect

## Kobold
**Challenge:** Kobold, kobold.htb, mcp.kobold.htb  
**Category:** Linux  
**Difficulty:** Easy  
**Keywords:** CVE-2026-23520, arcane mcp server, unauthenticated command injection, docker group privilege escalation, container breakout, volume mount, sg command, newgrp, curl api exploitation, ffuf subdomain enumeration, nginx, arcane docker management  
**Tags:** #linux #easy #hackthebox #mcp-server #command-injection #docker #container-breakout #cve-2026-23520  
**Techniques:** Arcane MCP Server unauthenticated command injection (CVE-2026-23520), subdomain enumeration, Docker group membership privilege escalation, container breakout via host filesystem volume mount  
**Flags:**
- User: `10ff89dbd16ef67da5b63f58476f1c9b`
- Root: `cfffff370705c650311f83107de22568`
**Search Terms:** hackthebox kobold walkthrough, kobold htb writeup, kobold.htb solution, CVE-2026-23520 exploit, arcane mcp server rce, unauthenticated command injection, docker group privilege escalation, container breakout volume mount, mcp server exploit, sg docker container escape, htb easy linux mcp

## LockedAway
**Challenge:** Locked Away, LockedAway, locked-away  
**Category:** Misc, Python  
**Difficulty:** Easy  
**Keywords:** python sandbox escape, chr bypass, vars get, blacklist bypass, code injection, restricted shell, exec bypass, python jail, character code construction, open_chest, dictionary methods, introspection bypass  
**Tags:** #misc #easy #hackthebox #python #sandbox-escape #blacklist-bypass #python-jail #chr-bypass  
**Techniques:** Python sandbox escape using chr() character code construction, vars().get() introspection bypass, blacklist filter evasion, restricted Python shell breakout  
**Flags:**
- Flag: `HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_6e18b179e97f616ccb44d71e361278de}`
**Search Terms:** hackthebox locked away walkthrough, lockedaway htb writeup, locked-away htb solution, python sandbox escape chr, python vars get bypass, restricted python shell escape, python exec bypass, python jail escape, blacklist bypass ctf, htb easy misc python, how to bypass python blacklist

## Pirate
**Challenge:** Pirate, pirate.htb, DC01.pirate.htb, MS01.pirate.htb, WEB01.pirate.htb  
**Category:** Windows, Active Directory  
**Difficulty:** Medium  
**Keywords:** active directory, kerberos, pre-windows 2000 compatible access, gMSA dump, gMSADumper, evil-winrm, pass-the-hash, ligolo, network pivoting, NTLM relay, RBCD, resource-based constrained delegation, coercer, ntlmrelayx, impacket, getST.py, psexec.py, wmiexec.py, secretsdump, bloodyAD, password reset, SPN injection, WriteSPN, addspn.py, S4U delegation abuse, altservice, kerberos ticket manipulation  
**Tags:** #active-directory #windows #medium #hackthebox #rbcd #ntlm-relay #kerberos #gmsa #spn-injection #s4u #ligolo #pivoting  
**Techniques:** Pre-Windows 2000 Compatible Access machine account exploitation, gMSA password dump, NTLM relay to RBCD configuration, SPN injection via WriteSPN abuse, S4U delegation abuse with altservice, network pivoting via Ligolo, credential dumping via secretsdump, domain compromise  
**Search Terms:** hackthebox pirate walkthrough, pirate htb writeup, pirate.htb solution, active directory RBCD attack, NTLM relay RBCD, S4U delegation abuse altservice, SPN injection WriteSPN, gMSA dump attack, pre-windows 2000 machine account, ligolo pivot, evil-winrm pass the hash, secretsdump credential dump, kerberos delegation domain admin, htb medium windows active directory

## VariaType
**Challenge:** VariaType, variatype.htb, portal.variatype.htb, Avatar  
**Category:** Linux  
**Difficulty:** Medium  
**Keywords:** git-dumper, exposed git directory, git history credential extraction, LFI, path traversal, CVE-2025-66034, fontTools varLib, arbitrary file write, XML injection, CVE-2024-25082, fontforge, zip filename command injection, PHP webshell, cron job exploitation, SSH key injection, sudo abuse, install_validator.py, url-encoded absolute path bypass, nginx  
**Tags:** #linux #medium #hackthebox #git-dumper #lfi #fonttools #fontforge #cve-2025-66034 #cve-2024-25082 #php-webshell #cron #sudo  
**Techniques:** Exposed .git directory extraction via git-dumper, Git history credential leak, CVE-2025-66034 fontTools varLib arbitrary file write + XML injection, CVE-2024-25082 FontForge ZIP filename command injection, PHP webshell upload, cron job exploitation, sudo path traversal via install_validator.py  
**Search Terms:** hackthebox variatype walkthrough, variatype htb writeup, variatype.htb solution, CVE-2025-66034 fonttools exploit, CVE-2024-25082 fontforge command injection, exposed git directory exploit, git-dumper htb, LFI path traversal, PHP webshell upload, fonttools varlib xml injection, cron job privilege escalation, sudo path traversal exploit, htb linux medium variatype avatar

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

