#!/usr/bin/env python3
"""pitfall - a tiny low-interaction honeypot (fake Telnet shell + fake router login page).

Pure standard library. It never executes anything an attacker sends:
every command is only logged and answered from a canned table.
Run it in an isolated VM/container, never on a machine you care about.
"""
import argparse
import asyncio
import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qs

LOG_PATH = Path("pitfall.jsonl")
IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff.")  # strip Telnet negotiation bytes

FAKE_OUTPUT = {
    "uname -a": "Linux router 3.10.14 #1 SMP PREEMPT armv7l GNU/Linux",
    "uname": "Linux",
    "whoami": "root",
    "id": "uid=0(root) gid=0(root)",
    "pwd": "/root",
    "ls": "bin  dev  etc  proc  tmp  var",
    "cat /proc/cpuinfo": "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)",
}
DOWNLOADERS = ("wget", "curl", "tftp", "ftpget")

LOGIN_PAGE = b"""<!doctype html><html><head><title>Router Admin</title></head>
<body style="font-family:sans-serif;max-width:320px;margin:80px auto">
<h3>Wireless Router - Admin Login</h3>
<form method="POST" action="/login">
<p><input name="username" placeholder="Username"></p>
<p><input name="password" type="password" placeholder="Password"></p>
<button>Sign in</button></form>
<p style="color:#b00">Invalid credentials.</p></body></html>"""


def log(event, **fields):
    rec = {"ts": round(time.time(), 3), "event": event, **fields}
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    detail = fields.get("cmd") or fields.get("user") or fields.get("path") or ""
    print(f"[{time.strftime('%H:%M:%S')}] {event:8} {fields.get('ip', ''):15} {detail}")


async def ask(reader, writer, prompt, timeout=45):
    writer.write(prompt)
    await writer.drain()
    raw = await asyncio.wait_for(reader.readline(), timeout)
    if not raw:
        raise ConnectionError("closed")
    return IAC.sub(b"", raw).decode("utf-8", "replace").strip()[:256]


async def telnet(reader, writer):
    ip = writer.get_extra_info("peername")[0]
    log("connect", ip=ip, service="telnet")
    try:
        for attempt in (1, 2):  # first try always fails, second always "works"
            user = await ask(reader, writer, b"router login: ")
            pw = await ask(reader, writer, b"Password: ")
            log("auth", ip=ip, service="telnet", user=user, password=pw)
            if attempt == 1:
                writer.write(b"\r\nLogin incorrect\r\n")
        writer.write(b"\r\nBusyBox v1.19.4 built-in shell (ash)\r\n")
        for _ in range(50):
            cmd = await ask(reader, writer, b"# ")
            if not cmd:
                continue
            log("command", ip=ip, service="telnet", cmd=cmd)
            if cmd in ("exit", "quit", "logout"):
                break
            if cmd in FAKE_OUTPUT:
                out = FAKE_OUTPUT[cmd]
            elif cmd.startswith(DOWNLOADERS):
                out = f"{cmd.split()[0]}: bad address"
            else:
                out = f"sh: {cmd.split()[0]}: not found"
            writer.write((out + "\r\n").encode())
    except (asyncio.TimeoutError, ConnectionError, ValueError, OSError):
        pass
    finally:
        writer.close()


async def http(reader, writer):
    ip = writer.get_extra_info("peername")[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin1").split("\r\n")
        method, path = lines[0].split(" ")[:2]
        headers = {k.lower(): v for k, _, v in (l.partition(": ") for l in lines[1:] if l)}
        size = min(int(headers.get("content-length", "0") or 0), 2048)
        body = await asyncio.wait_for(reader.readexactly(size), 10) if size else b""
        form = parse_qs(body.decode("utf-8", "replace"))
        log(
            "http", ip=ip, service="http", method=method, path=path[:200],
            ua=headers.get("user-agent", "")[:200],
            user=form.get("username", [""])[0][:128],
            password=form.get("password", [""])[0][:128],
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
            + f"Content-Length: {len(LOGIN_PAGE)}\r\n\r\n".encode() + LOGIN_PAGE
        )
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            ConnectionError, ValueError, OSError):
        pass
    finally:
        writer.close()


async def main(args):
    global LOG_PATH
    LOG_PATH = Path(args.log)
    servers = [
        await asyncio.start_server(telnet, args.host, args.telnet_port),
        await asyncio.start_server(http, args.host, args.http_port),
    ]
    print(f"pitfall listening: telnet:{args.telnet_port} http:{args.http_port} -> {LOG_PATH}")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="pitfall honeypot")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--telnet-port", type=int, default=2323)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--log", default="pitfall.jsonl")
    try:
        asyncio.run(main(p.parse_args()))
    except KeyboardInterrupt:
        pass
