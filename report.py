#!/usr/bin/env python3
"""Turn pitfall.jsonl into a self-contained HTML threat report."""
import argparse
import html
import json
import re
import time
from collections import Counter
from pathlib import Path

TAGS = {
    "dropper (download & run)": r"\b(wget|curl|tftp|ftpget)\b",
    "recon (system discovery)": r"\b(uname|whoami|id|ifconfig|ps)\b|/proc/",
    "persistence": r"crontab|authorized_keys|rc\.local|systemctl enable",
    "destructive / cleanup": r"rm -rf|dd if=|mkfs|killall|pkill",
}

CSS = """
body{background:#0d1117;color:#c9d1d9;font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:0 auto;padding:24px}
h1{color:#58a6ff;margin-bottom:4px}h2{color:#8b949e;font-size:13px;text-transform:uppercase;letter-spacing:.08em;margin:28px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.card b{display:block;font-size:26px;color:#f0f6fc}
.row{display:grid;grid-template-columns:minmax(90px,40%) 1fr 40px;gap:10px;align-items:center;margin:3px 0}
.k{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,monospace;font-size:13px}
.b{display:block;height:10px;border-radius:5px;background:#3fb950}.v{text-align:right;color:#8b949e}
"""


def bars(title, items):
    if not items:
        return ""
    top = max(c for _, c in items)
    rows = "".join(
        f'<div class="row"><span class="k" title="{html.escape(str(k))}">{html.escape(str(k))}</span>'
        f'<span><span class="b" style="width:{c / top * 100:.0f}%"></span></span><span class="v">{c}</span></div>'
        for k, c in items
    )
    return f"<h2>{html.escape(title)}</h2>{rows}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default="pitfall.jsonl")
    ap.add_argument("-o", "--out", default="report.html")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    events = []
    for line in Path(args.log).read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    auths = [e for e in events if e["event"] in ("auth", "http") and e.get("user")]
    cmds = [e["cmd"] for e in events if e["event"] == "command"]
    ips = Counter(e["ip"] for e in events if "ip" in e)
    users = Counter(e["user"] for e in auths)
    pws = Counter(e["password"] for e in auths)
    pairs = Counter(f'{e["user"]}:{e["password"]}' for e in auths)
    hours = Counter(time.strftime("%m-%d %H:00", time.gmtime(e["ts"])) for e in events)
    tags = Counter()
    for c in cmds:
        for name, rx in TAGS.items():
            if re.search(rx, c):
                tags[name] += 1

    n = args.top
    body = (
        f'<h1>pitfall threat report</h1><div style="color:#8b949e">{len(events)} events, UTC</div>'
        f'<div class="cards"><div class="card"><b>{len(ips)}</b>unique IPs</div>'
        f'<div class="card"><b>{len(auths)}</b>login attempts</div>'
        f'<div class="card"><b>{len(cmds)}</b>commands run</div>'
        f'<div class="card"><b>{sum(tags.values())}</b>flagged commands</div></div>'
        + bars("Top source IPs", ips.most_common(n))
        + bars("Top usernames", users.most_common(n))
        + bars("Top passwords", pws.most_common(n))
        + bars("Top user:password pairs", pairs.most_common(n))
        + bars("Top commands", Counter(cmds).most_common(n))
        + bars("Behaviour tags", tags.most_common())
        + bars("Activity per hour", sorted(hours.items())[-24:])
    )
    Path(args.out).write_text(
        f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>pitfall report</title><style>{CSS}</style>{body}",
        encoding="utf-8",
    )
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
