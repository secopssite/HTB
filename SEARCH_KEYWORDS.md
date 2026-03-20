# HTB Search Keywords & SEO Optimization

<!-- 
HTB Global Search Optimization Guide:
- Include challenge names, variations, and common misspellings
- Include vulnerability types and CVEs
- Include tool names and techniques
- Include full flags for searchability
- Use HTB{...} format for flags
-->

## Locked Away
**Challenge:** Locked Away, locked-away, lockedaway, locked_away  
**Category:** Misc, Python, Sandbox  
**Points:** 975  
**Difficulty:** Easy  
**Keywords:** python sandbox escape, chr() bypass, vars().get(), blacklist bypass, code injection, restricted shell, exec, python jail, character code construction, open_chest, dictionary methods, introspection bypass  
**Tags:** #python #sandbox #blacklist-bypass #chr #vars #exec #jailbreak #misc-easy #hackthebox  
**Techniques:** chr() string construction, vars().get() method, blacklist bypass, python sandbox escape  
**Flag:** `HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_6e18b179e97f616ccb44d71e361278de}`  
**Search Terms:** how to bypass python blacklist, python sandbox escape chr, python vars get bypass, restricted python shell escape, python exec bypass, open_chest function call, hackthebox locked away walkthrough, hackthebox locked away solution

## Hidden Path  
**Challenge:** Hidden Path, hidden-path, hiddenpath, hidden_path  
**Category:** Misc, JavaScript, Node.js, Web  
**Points:** 1000  
**Difficulty:** Easy  
**Keywords:** unicode homoglyph, command injection, U+3164, invisible character, nodejs, express, destructuring, variable reference, hangul jungseong filler, array injection, system check endpoint  
**Tags:** #javascript #nodejs #command-injection #unicode #homoglyph #u3164 #express #invisible-character #misc-easy #hackthebox  
**Techniques:** Unicode homoglyph injection (U+3164), variable reference injection, express body parser abuse, array element pollution  
**Flag:** `HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_6011a114c82501cf9d38d89d752075cd}`  
**Search Terms:** unicode injection exploit, U+3164 vulnerability, invisible character attack, nodejs command injection, express destructuring bypass, hackthebox hidden path walkthrough, hackthebox hidden path solution, hangul jungseong filler exploit

## Hercules  
**Challenge:** Hercules, hercules.htb, dc.hercules.htb  
**Category:** Active Directory, Windows  
**Difficulty:** Insane  
**Keywords:** ldap injection, shadow credentials, certipy, ESC3, enrollment agent, usersignature, dcom cert request, rbcd, iis_webserver$, u2u, s4u2self, s4u2proxy, dcsync, kerberos, bloodyAD, winrm  
**Tags:** #active-directory #windows #esc3 #shadow-credentials #rbcd #kerberos #dcsync #hackthebox  
**Techniques:** LDAP filter injection, Shadow Credentials, AD object move/ACL abuse, ESC3 via DCOM, service-account abuse, U2U+S4U, DCSync  
**Search Terms:** hackthebox hercules walkthrough, hercules htb writeup, certipy esc3 dcom, iis_webserver$ u2u s4u2proxy, shadow credentials hercules, dcsync hercules

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

