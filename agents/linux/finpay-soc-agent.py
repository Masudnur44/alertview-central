#!/usr/bin/env python3
"""FINPAY SOC Linux agent.

Ships security-relevant authentication events to the SOC intake endpoint:
  * SSH logins (success / failure / invalid users)       -> auth.login
  * sudo commands (checked for download-and-execute)        -> process.start
  * sudo authentication failures                           -> auth.login
  * new local accounts                                     -> account.created
  * users added to privileged groups (sudo, wheel, admin)  -> group.member_added
  * heartbeat every 5 minutes (so the SOC notices if the agent is stopped)

Standard library only (Python 3.6+). Reads journald when available, otherwise
tails /var/log/auth.log or /var/log/secure. Events are batched, retried with
back-off and spooled to disk while the SOC is unreachable.

Config: /etc/finpay-soc-agent.json  {"url": "https://soc.example.com", "key": "soc_..."}
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

VERSION = "1.0.0"
CONFIG_PATH = os.environ.get("FINPAY_SOC_CONFIG", "/etc/finpay-soc-agent.json")
SPOOL_PATH = "/var/lib/finpay-soc-agent/spool.jsonl"
SPOOL_MAX_BYTES = 50 * 1024 * 1024
BATCH_SIZE = 200
FLUSH_SECONDS = 5
HEARTBEAT_SECONDS = 300

PRIV_GROUPS = re.compile(r"^(sudo|wheel|admin|adm|root|docker)$")
PATTERNS = [
    (re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.login", "failure"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.login", "failure"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.login", "success"),
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*ruser=(?P<user>\S*)"), "auth.login", "failure"),
    (re.compile(r"(?:^|sudo(?:\[\d+\])?:)\s*(?P<user>[\w.$-]+) : .*COMMAND=(?P<cmd>.+)$"), "process.start", "success"),
    (re.compile(r"new user: name=(?P<user>[^,]+),"), "account.created", "success"),
    (re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"), "group.member_added", "success"),
    (re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)"), "group.member_added", "success"),
]
WATCH_IDENTIFIERS = ("sshd", "sudo", "useradd", "usermod", "gpasswd", "groupadd", "su", "login")


def log(msg):
    sys.stderr.write("[finpay-soc-agent] %s\n" % msg)
    sys.stderr.flush()


def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    if not cfg.get("url") or not cfg.get("key"):
        raise SystemExit("config must contain url and key")
    cfg["url"] = cfg["url"].rstrip("/")
    cfg.setdefault("host", socket.gethostname())
    return cfg


def parse_line(line, host, when=None):
    for rx, event_type, outcome in PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        g = m.groupdict()
        if event_type == "group.member_added" and not PRIV_GROUPS.match(g.get("group", "")):
            return None
        event = {
            "event_type": event_type,
            "host": host,
            "username": (g.get("user") or None),
            "outcome": outcome,
            "message": line.strip()[:3900],
            "occurred_at": (when or datetime.now(timezone.utc)).isoformat(),
        }
        if g.get("ip"):
            event["src_ip"] = g["ip"]
        if g.get("cmd"):
            event["raw"] = {"command_line": g["cmd"][:2000], "via": "sudo"}
            event["message"] = "sudo: " + g["cmd"][:3800]
        if event_type == "group.member_added":
            event["message"] = "Added to %s group: %s" % (g.get("group"), line.strip()[:3800])
        return event
    return None


class Shipper:
    def __init__(self, cfg):
        self.cfg = cfg
        self.buf = []
        self.lock = threading.Lock()
        self.backoff = 1
        self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file")) if cfg["url"].startswith("https") else None
        os.makedirs(os.path.dirname(SPOOL_PATH), exist_ok=True)

    def add(self, event):
        with self.lock:
            self.buf.append(event)
            full = len(self.buf) >= BATCH_SIZE
        if full:
            self.flush()

    def _post(self, events):
        body = json.dumps({"events": events}).encode()
        req = urllib.request.Request(
            self.cfg["url"] + "/api/public/ingest", data=body, method="POST",
            headers={"content-type": "application/json", "x-soc-key": self.cfg["key"], "user-agent": "finpay-soc-agent/" + VERSION},
        )
        with urllib.request.urlopen(req, timeout=20, context=self.ctx) as r:
            return r.status

    def _spool(self, events):
        try:
            if os.path.exists(SPOOL_PATH) and os.path.getsize(SPOOL_PATH) > SPOOL_MAX_BYTES:
                log("spool full, dropping %d events" % len(events))
                return
            with open(SPOOL_PATH, "a") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
        except OSError as e:
            log("cannot spool: %s" % e)

    def _drain_spool(self):
        if not os.path.exists(SPOOL_PATH):
            return
        tmp = SPOOL_PATH + ".sending"
        shutil.move(SPOOL_PATH, tmp)
        with open(tmp) as f:
            pending = [json.loads(l) for l in f if l.strip()]
        for i in range(0, len(pending), 500):
            try:
                self._post(pending[i:i + 500])
            except Exception:
                self._spool(pending[i:])
                break
        os.remove(tmp)

    def flush(self):
        with self.lock:
            events, self.buf = self.buf, []
        if not events:
            return
        try:
            self._post(events)
            self.backoff = 1
            self._drain_spool()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log("SOC rejected the key (HTTP %d) - check the key / allowed IPs; events spooled" % e.code)
            elif e.code == 400:
                log("SOC rejected a batch as invalid: %s" % e.read()[:300])
                return
            self._spool(events)
        except Exception as e:  # network down, TLS error...
            log("send failed (%s), spooling %d events" % (e, len(events)))
            self._spool(events)
            time.sleep(min(self.backoff, 60))
            self.backoff *= 2

    def run_timer(self):
        last_hb = 0
        while True:
            time.sleep(FLUSH_SECONDS)
            if time.time() - last_hb >= HEARTBEAT_SECONDS:
                self.add({"event_type": "agent.heartbeat", "host": self.cfg["host"], "outcome": "success",
                          "message": "finpay-soc-agent %s alive" % VERSION, "occurred_at": datetime.now(timezone.utc).isoformat()})
                last_hb = time.time()
            self.flush()


def follow_journal(shipper, host):
    args = ["journalctl", "-f", "-n", "0", "-o", "json"] + sum((["-t", t] for t in WATCH_IDENTIFIERS), [])
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, universal_newlines=True)
    for raw in proc.stdout:
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        msg = entry.get("MESSAGE")
        if not isinstance(msg, str):
            continue
        ts = entry.get("__REALTIME_TIMESTAMP")
        when = datetime.fromtimestamp(int(ts) / 1e6, timezone.utc) if ts else None
        ev = parse_line(msg, host, when)
        if ev:
            shipper.add(ev)
    raise RuntimeError("journalctl exited")


def follow_file(shipper, host, path):
    f = open(path)
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            ev = parse_line(line, host)
            if ev:
                shipper.add(ev)
            continue
        time.sleep(1)
        try:
            if os.stat(path).st_ino != inode:  # log rotated
                f.close()
                f = open(path)
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        cfg = load_config()
        s = Shipper(cfg)
        s._post([{"event_type": "agent.test", "host": cfg["host"], "outcome": "success", "message": "finpay-soc-agent connectivity test"}])
        print("OK: the SOC accepted a test event from %s" % cfg["host"])
        return
    cfg = load_config()
    shipper = Shipper(cfg)
    threading.Thread(target=shipper.run_timer, daemon=True).start()
    log("started %s for host %s -> %s" % (VERSION, cfg["host"], cfg["url"]))
    while True:
        try:
            if shutil.which("journalctl") and not cfg.get("log_file"):
                follow_journal(shipper, cfg["host"])
            else:
                path = cfg.get("log_file") or next((p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p)), None)
                if not path:
                    raise SystemExit("no journald and no auth log found; set log_file in the config")
                follow_file(shipper, cfg["host"], path)
        except Exception as e:
            log("reader stopped (%s); restarting in 5s" % e)
            time.sleep(5)


if __name__ == "__main__":
    main()
