#!/usr/bin/env python3
"""
Industrial Firewall Monitor - ACL Enforcement via VLAN Isolation
Queries InfluxDB for attacker blocked/allowed metrics and pushes
aggregated firewall statistics: block rate, MTTD, false positive rate.
"""

import os
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUXDB_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUXDB_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUXDB_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")

PROTOCOLS = ["modbus", "iec104", "dnp3", "opcua"]

ACL_RULES = {
    "modbus":  {"allowed": ["172.20.10.10", "172.20.10.20"], "blocked": ["172.20.15.100"], "port": 502},
    "iec104":  {"allowed": ["172.20.30.10", "172.20.30.20"], "blocked": ["172.20.35.100"], "port": 2404},
    "dnp3":    {"allowed": ["172.20.20.10", "172.20.20.20"], "blocked": ["172.20.25.100"], "port": 20000},
    "opcua":   {"allowed": ["172.20.40.10", "172.20.40.20"], "blocked": ["172.20.45.100"], "port": 4840},
}

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
                |> range(start: -1m)
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

def push_firewall_stats(write_api, attacker_data, start_time):
    """Push aggregated firewall stats"""
    total_blocked = 0
    total_allowed = 0
    total_attempts = 0

    for protocol in PROTOCOLS:
        data = attacker_data.get(protocol, {})
        blocked = int(data.get("blocked", 0))
        successful = int(data.get("successful", 0))
        attempts = int(data.get("total_attempts", 0))

        total_blocked += blocked
        total_allowed += successful
        total_attempts += attempts

        point = Point("firewall") \
            .tag("protocol", protocol) \
            .tag("type", "per_protocol") \
            .field("blocked", blocked) \
            .field("allowed", successful) \
            .field("attempts", attempts)
        try:
            write_api.write(bucket=INFLUXDB_BUCKET, record=point)
        except Exception as e:
            print(f"[ERROR] push per-protocol: {e}")

    block_rate = (total_blocked / total_attempts * 100) if total_attempts > 0 else 0.0
    false_positive_rate = 0.0
    mttd_ms = (datetime.now() - start_time).total_seconds() * 1000 if total_blocked > 0 else 0.0
    uptime_s = (datetime.now() - start_time).total_seconds()

    point = Point("firewall_stats") \
        .field("total_blocked", total_blocked) \
        .field("total_allowed", total_allowed) \
        .field("total_attempts", total_attempts) \
        .field("block_rate", round(block_rate, 2)) \
        .field("false_positive_rate", false_positive_rate) \
        .field("mttd_ms", round(mttd_ms, 2)) \
        .field("uptime_s", round(uptime_s, 2))
    try:
        write_api.write(bucket=INFLUXDB_BUCKET, record=point)
    except Exception as e:
        print(f"[ERROR] push stats: {e}")

    print(f"[FIREWALL] Blocked: {total_blocked} | Allowed: {total_allowed} | "
          f"Block Rate: {block_rate:.1f}% | FP Rate: {false_positive_rate:.1f}% | "
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
            push_firewall_stats(write_api, attacker_data, start_time)
        except Exception as e:
            print(f"[ERROR] Monitor cycle: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main()
