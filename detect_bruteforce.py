#!/usr/bin/env python3
"""
SSH brute-force / password-spray detector for Linux auth.log.

Detections (MITRE ATT&CK T1110 - Brute Force):
  BURST     >= BURST_THRESHOLD failures from one IP within BURST_WINDOW   (T1110.001)
  SPRAY     one IP failing against >= SPRAY_USERS distinct usernames      (T1110.003)
  SLOW      >= SLOW_THRESHOLD failures from one IP across the whole log   (T1110.001)
  COMPROMISE a successful login from an IP that previously failed >= COMPROMISE_MIN times

Usage:
  python3 detect_bruteforce.py auth.log --year 2026 --json alerts.json
"""
import argparse
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

BURST_THRESHOLD = 20
BURST_WINDOW = timedelta(minutes=2)
SPRAY_USERS = 5
SLOW_THRESHOLD = 15
COMPROMISE_MIN = 5

TS = r"(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})"
FAILED = re.compile(TS + r".*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID = re.compile(TS + r".*sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED = re.compile(TS + r".*sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+)")


def parse_ts(s, year):
    return datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S")


def analyze(path, year):
    fails = defaultdict(list)          # ip -> [(ts, user)]
    successes = []                     # (ts, ip, user, method)
    with open(path) as f:
        for line in f:
            if m := FAILED.search(line):
                fails[m["ip"]].append((parse_ts(m["ts"], year), m["user"]))
            elif m := ACCEPTED.search(line):
                successes.append((parse_ts(m["ts"], year), m["ip"], m["user"], m["method"]))
            # INVALID lines duplicate the Failed line for the same attempt; skip to avoid double counting

    alerts = []
    for ip, events in fails.items():
        events.sort()
        users = {u for _, u in events}

        # sliding window burst
        win, peak, peak_start = deque(), 0, None
        for ts, _ in events:
            win.append(ts)
            while ts - win[0] > BURST_WINDOW:
                win.popleft()
            if len(win) > peak:
                peak, peak_start = len(win), win[0]
        if peak >= BURST_THRESHOLD:
            alerts.append(dict(type="BURST", technique="T1110.001", severity="HIGH", ip=ip,
                               detail=f"{peak} failures in {int(BURST_WINDOW.total_seconds()//60)} min (peak starting {peak_start})",
                               total_failures=len(events), users=sorted(users)))
        if len(users) >= SPRAY_USERS:
            alerts.append(dict(type="SPRAY", technique="T1110.003", severity="HIGH", ip=ip,
                               detail=f"failed against {len(users)} distinct usernames",
                               total_failures=len(events), users=sorted(users)))
        if len(events) >= SLOW_THRESHOLD and peak < BURST_THRESHOLD:
            span = events[-1][0] - events[0][0]
            alerts.append(dict(type="SLOW", technique="T1110.001", severity="MEDIUM", ip=ip,
                               detail=f"{len(events)} failures spread over {span} (evades rate-based rules)",
                               total_failures=len(events), users=sorted(users)))

    for ts, ip, user, method in successes:
        prior = [e for e in fails.get(ip, []) if e[0] < ts]
        if len(prior) >= COMPROMISE_MIN:
            alerts.append(dict(type="COMPROMISE", technique="T1110 -> T1078", severity="CRITICAL", ip=ip,
                               detail=f"Accepted {method} for '{user}' at {ts} after {len(prior)} prior failures",
                               total_failures=len(prior), users=[user]))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda a: (order[a["severity"]], -a["total_failures"]))
    stats = dict(total_failed=sum(len(v) for v in fails.values()), unique_source_ips=len(fails),
                 successful_logins=len(successes))
    return alerts, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--year", type=int, default=datetime.now().year)
    ap.add_argument("--json")
    a = ap.parse_args()
    alerts, stats = analyze(a.log, a.year)

    print(f"== SSH Brute-Force Report: {a.log}")
    print(f"   failed attempts: {stats['total_failed']} | source IPs with failures: {stats['unique_source_ips']} | successful logins: {stats['successful_logins']}\n")
    for al in alerts:
        print(f"[{al['severity']:<8}] {al['type']:<10} {al['ip']:<15} {al['technique']:<15} {al['detail']}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(dict(stats=stats, alerts=alerts), f, indent=2, default=str)
        print(f"\nJSON written to {a.json}")


if __name__ == "__main__":
    main()
