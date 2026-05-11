#!/usr/bin/env python3
"""
Industrial Firewall Monitor - ACL Enforcement via VLAN Isolation
Queries InfluxDB for attacker blocked/allowed metrics and pushes
aggregated firewall statistics: block rate, MTTD, false positive rate.
"""

import os
import re
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUXDB_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUXDB_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUXDB_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")
BLACKLIST_FILE = os.environ.get("BLACKLIST_FILE", "/tmp/blacklist.acl")
FIREWALL_TOPOLOGY = os.environ.get("FIREWALL_TOPOLOGY", "flat").strip().lower()
MTTD_LOOKBACK = os.environ.get("MTTD_LOOKBACK", "-10m")

BLOCKED_IP_RE = re.compile(r"BLOCKED IP: (\d+\.\d+\.\d+\.\d+)")

PROTOCOLS = ["modbus", "iec104", "dnp3", "opcua"]

if FIREWALL_TOPOLOGY == "inline":
    ACL_RULES = {
        "modbus":  {"allowed": ["172.20.10.20", "172.20.110.10"], "blocked": ["172.20.10.131"], "port": 502},
        "iec104":  {"allowed": ["172.20.30.20", "172.20.130.10"], "blocked": ["172.20.30.131"], "port": 2404},
        "dnp3":    {"allowed": ["172.20.20.20", "172.20.120.10"], "blocked": ["172.20.20.131"], "port": 20000},
        "opcua":   {"allowed": ["172.20.40.20", "172.20.140.10"], "blocked": ["172.20.40.131"], "port": 4840},
    }
else:
    ACL_RULES = {
        "modbus":  {"allowed": ["172.20.10.10", "172.20.10.20"], "blocked": ["172.20.15.100"], "port": 502},
        "iec104":  {"allowed": ["172.20.30.10", "172.20.30.20"], "blocked": ["172.20.35.100"], "port": 2404},
        "dnp3":    {"allowed": ["172.20.20.10", "172.20.20.20"], "blocked": ["172.20.25.100"], "port": 20000},
        "opcua":   {"allowed": ["172.20.40.10", "172.20.40.20"], "blocked": ["172.20.45.100"], "port": 4840},
    }


def read_blacklist_ips():
    """Read unique blocked source IPs from blacklist file."""
    ips = set()
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as handle:
            for line in handle:
                match = BLOCKED_IP_RE.search(line)
                if match:
                    ips.add(match.group(1))
    except FileNotFoundError:
        pass
    return ips


def calculate_false_positive_rate(blocked_ips):
    """FP rate = whitelisted IPs mistakenly present in blacklist / total blacklisted IPs."""
    if not blocked_ips:
        return 0.0, 0, 0

    whitelisted_ips = set()
    for rules in ACL_RULES.values():
        whitelisted_ips.update(rules["allowed"])

    false_positive_count = len(blocked_ips & whitelisted_ips)
    fp_rate = (false_positive_count / len(blocked_ips)) * 100.0
    return fp_rate, false_positive_count, len(blocked_ips)

def connect_influxdb():
    """Connect to InfluxDB with retry"""
    for attempt in range(30):
        try:
            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
            client.ping()
            print(f"[MONITOR] Connected to InfluxDB at {INFLUXDB_URL}")
            return client
        except Exception as e:
            print(f"[MONITOR] Waiting for InfluxDB... ({attempt+1}/30) {e}")
            time.sleep(5)
    raise Exception("Cannot connect to InfluxDB")

def query_attacker_metrics(query_api):
    """Query attacker metrics from InfluxDB to calculate firewall stats"""
    results = {}
    for protocol in PROTOCOLS:
        container = f"{protocol}-attacker"
        try:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
                |> range(start: -10m)
                |> filter(fn: (r) => r._measurement == "secure_attack")
                |> filter(fn: (r) => r.container == "{container}")
                |> filter(fn: (r) => r._field == "blocked" or r._field == "successful" or r._field == "total_attempts")
                |> last()
            '''
            tables = query_api.query(query)
            data = {}
            for table in tables:
                for record in table.records:
                    data[record.get_field()] = record.get_value()
            results[protocol] = data
        except Exception:
            results[protocol] = {}
    return results


def query_whitelist_pass_metrics(query_api):
    """Count recent legitimate client telemetry points per protocol (whitelist pass proxy)."""
    results = {}
    for protocol in PROTOCOLS:
        client_container = f"{protocol}-client"
        try:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
                |> range(start: -10m)
                |> filter(fn: (r) => r._measurement == "{protocol}")
                |> filter(fn: (r) => r.container == "{client_container}")
                |> count()
                |> sum(column: "_value")
            '''
            tables = query_api.query(query)
            total = 0
            for table in tables:
                for record in table.records:
                    try:
                        total += int(record.get_value())
                    except Exception:
                        pass
            results[protocol] = total
        except Exception:
            results[protocol] = 0
    return results


LAST_MTTD_MS = 0.0


def query_mttd_ms(query_api):
    """Mean time from first attacker telemetry point to first firewall action."""
    global LAST_MTTD_MS
    samples = []

    for protocol in PROTOCOLS:
        try:
            attacker_container = f"{protocol}-attacker"
            attack_query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
                |> range(start: {MTTD_LOOKBACK})
                |> filter(fn: (r) => r._measurement == "{protocol}")
                |> filter(fn: (r) => r.container == "{attacker_container}")
                |> filter(fn: (r) => r._field == "latency")
                |> group()
                |> sort(columns: ["_time"])
                |> limit(n: 1)
            '''
            action_query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
                |> range(start: {MTTD_LOOKBACK})
                |> filter(fn: (r) => r._measurement == "firewall_action")
                |> filter(fn: (r) => r.protocol == "{protocol}")
                |> filter(fn: (r) => r._field == "blocked")
                |> group()
                |> sort(columns: ["_time"])
                |> limit(n: 1)
            '''

            attack_time = None
            for table in query_api.query(attack_query):
                for record in table.records:
                    attack_time = record.get_time()
                    break
                if attack_time:
                    break

            action_time = None
            for table in query_api.query(action_query):
                for record in table.records:
                    action_time = record.get_time()
                    break
                if action_time:
                    break

            if attack_time and action_time and action_time >= attack_time:
                samples.append((action_time - attack_time).total_seconds() * 1000)
        except Exception as exc:
            print(f"[ERROR] query MTTD for {protocol}: {exc}")

    if not samples:
        return LAST_MTTD_MS

    LAST_MTTD_MS = sum(samples) / len(samples)
    return LAST_MTTD_MS


def push_firewall_stats(write_api, query_api, attacker_data, whitelist_pass_data, start_time):
    """Push aggregated firewall stats"""
    total_blocked = 0
    total_allowed = 0
    total_whitelist_pass = 0
    total_attempts = 0

    for protocol in PROTOCOLS:
        data = attacker_data.get(protocol, {})
        blocked = int(data.get("blocked", 0))
        successful = int(data.get("successful", 0))
        attempts = int(data.get("total_attempts", 0))
        whitelist_pass = int(whitelist_pass_data.get(protocol, 0))

        total_blocked += blocked
        total_allowed += successful
        total_whitelist_pass += whitelist_pass
        total_attempts += attempts

        point = Point("firewall") \
            .tag("protocol", protocol) \
            .tag("type", "per_protocol") \
            .field("blocked", blocked) \
            .field("allowed", successful) \
            .field("whitelist_pass_count", whitelist_pass) \
            .field("attempts", attempts)
        try:
            write_api.write(bucket=INFLUXDB_BUCKET, record=point)
        except Exception as e:
            print(f"[ERROR] push per-protocol: {e}")

    block_rate = (total_blocked / total_attempts * 100) if total_attempts > 0 else 0.0
    blacklist_ips = read_blacklist_ips()
    false_positive_rate, false_positive_count, total_blacklisted_ips = calculate_false_positive_rate(blacklist_ips)
    mttd_ms = query_mttd_ms(query_api)
    uptime_s = (datetime.now() - start_time).total_seconds()

    point = Point("firewall_stats") \
        .field("total_blocked", total_blocked) \
        .field("total_allowed", total_allowed) \
        .field("total_whitelist_pass_count", total_whitelist_pass) \
        .field("total_attempts", total_attempts) \
        .field("block_rate", round(block_rate, 2)) \
        .field("false_positive_rate", round(false_positive_rate, 2)) \
        .field("false_positive_count", false_positive_count) \
        .field("total_blacklisted_ips", total_blacklisted_ips) \
        .field("mttd_ms", round(mttd_ms, 2)) \
        .field("uptime_s", round(uptime_s, 2))
    try:
        write_api.write(bucket=INFLUXDB_BUCKET, record=point)
    except Exception as e:
        print(f"[ERROR] push stats: {e}")

    print(f"[FIREWALL] Blocked: {total_blocked} | Allowed(attack success): {total_allowed} | "
          f"WhitelistPass: {total_whitelist_pass} | "
          f"Block Rate: {block_rate:.1f}% | FP Rate: {false_positive_rate:.1f}% "
          f"({false_positive_count}/{total_blacklisted_ips} IPs) | "
          f"Uptime: {uptime_s:.0f}s")

def push_acl_config(write_api):
    """Push ACL configuration as metrics"""
    for protocol, rules in ACL_RULES.items():
        point = Point("firewall_acl") \
            .tag("protocol", protocol) \
            .field("whitelisted_ips", len(rules["allowed"])) \
            .field("blocked_ips", len(rules["blocked"])) \
            .field("port", rules["port"])
        try:
            write_api.write(bucket=INFLUXDB_BUCKET, record=point)
        except Exception:
            pass

def main():
    print("=" * 60)
    print("  Industrial Firewall Monitor")
    print("  ACL Enforcement via VLAN Network Isolation")
    print("=" * 60)
    print()

    for protocol, rules in ACL_RULES.items():
        print(f"  [{protocol.upper()}] Port {rules['port']}")
        print(f"    Whitelisted: {rules['allowed']}")
        print(f"    Blocked:     {rules['blocked']}")
    print()

    client = connect_influxdb()
    write_api = client.write_api(write_options=SYNCHRONOUS)
    query_api = client.query_api()

    start_time = datetime.now()
    push_acl_config(write_api)

    print("[MONITOR] Monitoring firewall metrics every 10s...")
    while True:
        try:
            attacker_data = query_attacker_metrics(query_api)
            whitelist_pass_data = query_whitelist_pass_metrics(query_api)
            push_firewall_stats(write_api, query_api, attacker_data, whitelist_pass_data, start_time)
        except Exception as e:
            print(f"[ERROR] Monitor cycle: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main()
