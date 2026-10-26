# pitfall 🕳️

A tiny **low-interaction honeypot** that pretends to be a vulnerable IoT router, records what attackers try, and turns the logs into a threat report. Pure Python standard library, zero dependencies.

## What it does
- **Fake Telnet shell** (BusyBox-style): first login always fails, second always "works", then it logs every command and answers from a canned table. Nothing is ever executed.
- **Fake router admin page** (HTTP): logs credentials, user-agents and paths from scanners and bots.
- **`report.py`**: builds a self-contained HTML report: top IPs, usernames, passwords, user:password pairs, commands, hourly activity, and behaviour tags (dropper, recon, persistence, destructive).

## Quick start
```bash
python3 honeypot.py                 # telnet :2323, http :8080, logs to pitfall.jsonl
python3 demo_attack.py 127.0.0.1 30 # optional: replay botnet-style traffic locally
python3 report.py                   # writes report.html
```
See `sample-report.html` for example output.

## Safety
- Run it in an isolated VM/container, never on a machine that holds real data.
- Use high ports and forward 23 -> 2323 only if you understand the exposure.
- Only deploy on networks you own or are authorized to monitor; check local law on logging third-party traffic.

## Ideas to extend
GeoIP/ASN enrichment, an SSH listener (asyncssh), exporting IOCs (STIX/CSV), Telegram alerts, rate-limit/tarpit mode, a live dashboard.

## License
MIT
