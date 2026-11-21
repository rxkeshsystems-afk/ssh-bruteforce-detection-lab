#!/usr/bin/env python3
"""
Generate a synthetic Linux /var/log/auth.log for the lab.

The log mixes normal admin activity with three attack patterns:
  1. Fast brute force against root from one IP
  2. Password spraying (many usernames, one IP)
  3. A "low and slow" brute force that ends in a SUCCESSFUL login (compromise)

All IPs are from documentation ranges (RFC 5737) so nothing here points at a real host.
Deterministic: same seed -> same log.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
HOST = "web-prod-01"
START = datetime(2026, 11, 14, 0, 0, 0)
lines = []


def emit(ts, pid, msg):
    lines.append((ts, f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sshd[{pid}]: {msg}"))


def pid():
    return random.randint(10000, 65000)


# --- Normal traffic: legit admins logging in with keys/passwords all day
admins = [("rakesh", "198.51.100.10"), ("deploy", "198.51.100.22"), ("backup", "198.51.100.35")]
for i in range(60):
    user, ip = random.choice(admins)
    ts = START + timedelta(seconds=random.randint(0, 86399))
    p = pid()
    port = random.randint(40000, 60000)
    method = "publickey" if user != "rakesh" else random.choice(["publickey", "password"])
    # occasional legit typo
    if random.random() < 0.1:
        emit(ts, p, f"Failed password for {user} from {ip} port {port} ssh2")
        ts += timedelta(seconds=4)
    emit(ts, p, f"Accepted {method} for {user} from {ip} port {port} ssh2")
    emit(ts, p, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")

# --- Attack 1: fast brute force on root (≈ 400 attempts in ~6 minutes)
ip = "203.0.113.45"
ts = START + timedelta(hours=3, minutes=12)
for _ in range(400):
    ts += timedelta(seconds=random.uniform(0.4, 1.4))
    emit(ts, pid(), f"Failed password for root from {ip} port {random.randint(30000, 65000)} ssh2")

# --- Attack 2: password spray — many usernames, few tries each
ip = "192.0.2.77"
users = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser", "guest",
         "support", "user", "jenkins", "pi", "mysql", "www-data", "ec2-user", "minecraft"]
ts = START + timedelta(hours=9, minutes=40)
for u in users:
    for _ in range(random.randint(2, 4)):
        ts += timedelta(seconds=random.uniform(2, 6))
        emit(ts, pid(), f"Invalid user {u} from {ip} port {random.randint(30000, 65000)}")
        emit(ts, pid(), f"Failed password for invalid user {u} from {ip} port {random.randint(30000, 65000)} ssh2")

# --- Attack 3: low-and-slow against 'deploy', ending in success  (the one that matters)
ip = "203.0.113.200"
ts = START + timedelta(hours=1)
for _ in range(38):
    ts += timedelta(minutes=random.uniform(18, 26))  # stays under per-minute thresholds
    emit(ts, pid(), f"Failed password for deploy from {ip} port {random.randint(30000, 65000)} ssh2")
ts += timedelta(minutes=21)
p = pid()
emit(ts, p, f"Accepted password for deploy from {ip} port 51515 ssh2")
emit(ts, p, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)")

lines.sort(key=lambda x: x[0])
out = Path(__file__).resolve().parent / "auth.log"
out.write_text("\n".join(l for _, l in lines) + "\n")
print(f"wrote {len(lines)} lines -> {out}")
