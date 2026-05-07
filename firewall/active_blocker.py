#!/usr/bin/env python3
"""
Active Firewall Blocker - Reads blacklist.acl and enforces iptables rules
"""
import subprocess
import time
import re

BLACKLIST_FILE = "/tmp/blacklist.acl"  # Path to blacklist.acl
BLOCKED_IPS = set()

def read_blacklist():
    """Extract IPs from blacklist.acl"""
    current_ips = set()
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            for line in f:
                # Format: "2026-04-24 03:58:03 - BLOCKED IP: 172.20.30.131 - ..."
                match = re.search(r'BLOCKED IP: (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_ips.add(match.group(1))
    except FileNotFoundError:
        pass
    return current_ips

def block_ip(ip):
    """Add iptables rule to block an IP"""
    try:
        # Block all traffic from this IP
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                      check=True, capture_output=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], 
                      check=True, capture_output=True)
        print(f"[BLOCKER] Blocked IP: {ip}")
    except Exception as e:
        print(f"[BLOCKER] Error blocking {ip}: {e}")

def unblock_ip(ip):
    """Remove iptables rule (in case IP is removed from blacklist)"""
    try:
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                      check=True, capture_output=True)
        subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], 
                      check=True, capture_output=True)
        print(f"[BLOCKER] Unblocked IP: {ip}")
    except Exception as e:
        print(f"[BLOCKER] Error unblocking {ip}: {e}")

def main():
    """Main daemon loop"""
    global BLOCKED_IPS
    print("[BLOCKER] Starting Active Firewall Blocking Daemon...")
    
    while True:
        try:
            new_ips = read_blacklist()
            
            # Block new IPs
            for ip in new_ips - BLOCKED_IPS:
                block_ip(ip)
            
            # Unblock removed IPs (optional)
            for ip in BLOCKED_IPS - new_ips:
                unblock_ip(ip)
            
            BLOCKED_IPS = new_ips
            time.sleep(5)  # Check every 5 seconds
            
        except Exception as e:
            print(f"[BLOCKER] Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
