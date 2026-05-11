#!/usr/bin/env python3
"""Active Firewall Blocker - Reads blacklist.acl and enforces iptables rules."""

import ipaddress
import os
import re
import subprocess
import time
from typing import Optional, Set

BLACKLIST_FILE = os.environ.get("BLACKLIST_FILE", "/tmp/blacklist.acl")
POLL_INTERVAL = float(os.environ.get("BLOCKER_POLL_INTERVAL", "5"))
BLOCK_CHAIN = os.environ.get("BLOCK_CHAIN", "ACTIVE_BLOCK")
BLOCKER_MODE = os.environ.get("BLOCKER_MODE", "enforce").strip().lower()
EFFECTIVE_MODE = BLOCKER_MODE if BLOCKER_MODE in {"enforce", "monitor"} else "enforce"

BLOCKED_IP_RE = re.compile(r"BLOCKED IP: (\d+\.\d+\.\d+\.\d+)")
BLOCKED_IPS: Set[str] = set()
LAST_MTIME: Optional[float] = None


def run_iptables(args, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["iptables", *args], check=check, capture_output=True, text=True)


def ensure_chain() -> None:
    """Create dedicated chain and hook INPUT/FORWARD once."""
    if EFFECTIVE_MODE != "enforce":
        return

    run_iptables(["-N", BLOCK_CHAIN], check=False)

    if run_iptables(["-C", "INPUT", "-j", BLOCK_CHAIN], check=False).returncode != 0:
        run_iptables(["-I", "INPUT", "1", "-j", BLOCK_CHAIN], check=True)

    if run_iptables(["-C", "FORWARD", "-j", BLOCK_CHAIN], check=False).returncode != 0:
        run_iptables(["-I", "FORWARD", "1", "-j", BLOCK_CHAIN], check=True)


def validate_ip(raw_ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return None


def read_blacklist() -> Set[str]:
    """Extract and validate blocked IPv4 addresses from blacklist.acl."""
    current_ips: Set[str] = set()
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as handle:
            for line in handle:
                match = BLOCKED_IP_RE.search(line)
                if not match:
                    continue
                ip = validate_ip(match.group(1))
                if ip:
                    current_ips.add(ip)
    except FileNotFoundError:
        pass
    return current_ips


def get_blacklist_mtime() -> Optional[float]:
    try:
        return os.path.getmtime(BLACKLIST_FILE)
    except FileNotFoundError:
        return None


def block_ip(ip: str) -> None:
    """Add an idempotent drop rule for one IP in dedicated chain."""
    if EFFECTIVE_MODE != "enforce":
        print(f"[BLOCKER] Monitor mode: would block IP {ip}")
        return

    if run_iptables(["-C", BLOCK_CHAIN, "-s", ip, "-j", "DROP"], check=False).returncode == 0:
        return

    run_iptables(["-A", BLOCK_CHAIN, "-s", ip, "-j", "LOG",
                  "--log-prefix", f"[ACTIVE_BLOCK:{ip}] "], check=False)
    run_iptables(["-A", BLOCK_CHAIN, "-s", ip, "-j", "DROP"], check=True)
    print(f"[BLOCKER] Blocked IP: {ip}")


def unblock_ip(ip: str) -> None:
    """Remove all matching drop rules for one IP from dedicated chain."""
    if EFFECTIVE_MODE != "enforce":
        print(f"[BLOCKER] Monitor mode: would unblock IP {ip}")
        return

    removed = False
    while run_iptables(["-C", BLOCK_CHAIN, "-s", ip, "-j", "DROP"], check=False).returncode == 0:
        run_iptables(["-D", BLOCK_CHAIN, "-s", ip, "-j", "DROP"], check=True)
        removed = True

    while run_iptables(["-C", BLOCK_CHAIN, "-s", ip, "-j", "LOG",
                        "--log-prefix", f"[ACTIVE_BLOCK:{ip}] "], check=False).returncode == 0:
        run_iptables(["-D", BLOCK_CHAIN, "-s", ip, "-j", "LOG",
                      "--log-prefix", f"[ACTIVE_BLOCK:{ip}] "], check=False)

    if removed:
        print(f"[BLOCKER] Unblocked IP: {ip}")


def main() -> None:
    """Main daemon loop."""
    global BLOCKED_IPS, LAST_MTIME

    if BLOCKER_MODE not in {"enforce", "monitor"}:
        print(f"[BLOCKER] Invalid BLOCKER_MODE={BLOCKER_MODE!r}, fallback to 'enforce'")
    print(f"[BLOCKER] Starting Active Firewall Blocking Daemon (mode={EFFECTIVE_MODE})...")
    ensure_chain()

    while True:
        try:
            current_mtime = get_blacklist_mtime()
            if LAST_MTIME is not None and current_mtime == LAST_MTIME:
                time.sleep(POLL_INTERVAL)
                continue

            new_ips = read_blacklist()

            for ip in sorted(new_ips - BLOCKED_IPS):
                block_ip(ip)

            for ip in sorted(BLOCKED_IPS - new_ips):
                unblock_ip(ip)

            BLOCKED_IPS = new_ips
            LAST_MTIME = current_mtime
            print(f"[BLOCKER] Sync complete | blocked={len(BLOCKED_IPS)}")
        except Exception as exc:
            print(f"[BLOCKER] Error: {exc}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
