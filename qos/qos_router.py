#!/usr/bin/env python3
"""QoS Router/Manager for SCADA Phase 2.

- Applies HTB classes (P1/P2/P3) with tc
- Classifies packets with iptables mangle marks
- Exports QoS latency + drop metrics to InfluxDB
"""

import os
import re
import socket
import statistics
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUXDB_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUXDB_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUXDB_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")

MONITOR_INTERVAL = int(os.environ.get("QOS_MONITOR_INTERVAL", "10"))
TOTAL_RATE = os.environ.get("QOS_TOTAL_RATE", "100mbit")

# Priority classes
CLASS_ROOT = "1:"
CLASS_P1 = "1:10"  # critical control commands
CLASS_P2 = "1:20"  # monitoring traffic
CLASS_P3 = "1:30"  # unknown/background traffic

MARK_P1 = "10"
MARK_P2 = "20"
MARK_P3 = "30"


def run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def list_data_interfaces() -> List[str]:
    interfaces = []
    for name in os.listdir("/sys/class/net"):
        if name == "lo":
            continue
        if name.startswith("eth"):
            interfaces.append(name)
    return sorted(interfaces)


def setup_iptables_marks() -> None:
    # Best-effort cleanup from previous runs
    run(["iptables", "-t", "mangle", "-D", "OUTPUT", "-j", "QOS_CLASSIFY"], check=False)
    run(["iptables", "-t", "mangle", "-D", "FORWARD", "-j", "QOS_CLASSIFY"], check=False)
    run(["iptables", "-t", "mangle", "-F", "QOS_CLASSIFY"], check=False)
    run(["iptables", "-t", "mangle", "-X", "QOS_CLASSIFY"], check=False)

    run(["iptables", "-t", "mangle", "-N", "QOS_CLASSIFY"], check=False)

    # Keep existing connmark for established packets
    run(["iptables", "-t", "mangle", "-A", "QOS_CLASSIFY", "-j", "CONNMARK", "--restore-mark"])

    # Priority 1: Control commands
    # IEC104 C_SC_NA_1 TypeID=45 (0x2d), heuristic payload signature matching.
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "2404",
        "-m", "string", "--algo", "bm", "--hex-string", "|2d|",
        "-j", "MARK", "--set-mark", MARK_P1,
    ])
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--sport", "2404",
        "-j", "MARK", "--set-mark", MARK_P1,
    ])
    # Modbus write FC5/FC6 (heuristic signature).
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "502",
        "-m", "string", "--algo", "bm", "--hex-string", "|05|",
        "-j", "MARK", "--set-mark", MARK_P1,
    ])
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "502",
        "-m", "string", "--algo", "bm", "--hex-string", "|06|",
        "-j", "MARK", "--set-mark", MARK_P1,
    ])

    # Priority 2: Monitoring/polling traffic
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "502",
        "-m", "string", "--algo", "bm", "--hex-string", "|03|",
        "-j", "MARK", "--set-mark", MARK_P2,
    ])
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "502",
        "-m", "string", "--algo", "bm", "--hex-string", "|04|",
        "-j", "MARK", "--set-mark", MARK_P2,
    ])
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--dport", "4840",
        "-j", "MARK", "--set-mark", MARK_P2,
    ])
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-p", "tcp", "--sport", "4840",
        "-j", "MARK", "--set-mark", MARK_P2,
    ])

    # Priority 3: Unknown traffic
    run([
        "iptables", "-t", "mangle", "-A", "QOS_CLASSIFY",
        "-m", "mark", "--mark", "0",
        "-j", "MARK", "--set-mark", MARK_P3,
    ])

    # Save mark to conntrack
    run(["iptables", "-t", "mangle", "-A", "QOS_CLASSIFY", "-j", "CONNMARK", "--save-mark"])

    run(["iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "QOS_CLASSIFY"])
    run(["iptables", "-t", "mangle", "-A", "FORWARD", "-j", "QOS_CLASSIFY"])


def setup_tc_for_interface(interface: str) -> None:
    run(["tc", "qdisc", "del", "dev", interface, "root"], check=False)

    run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"])
    run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:1", "htb", "rate", TOTAL_RATE, "ceil", TOTAL_RATE])

    # Use conservative per-class bandwidth in this lab so congestion/drop is visible in dashboards.
    run(["tc", "class", "add", "dev", interface, "parent", "1:1", "classid", CLASS_P1, "htb", "rate", "5mbit", "ceil", "20mbit", "prio", "0"])
    run(["tc", "class", "add", "dev", interface, "parent", "1:1", "classid", CLASS_P2, "htb", "rate", "2mbit", "ceil", "10mbit", "prio", "1"])
    run(["tc", "class", "add", "dev", interface, "parent", "1:1", "classid", CLASS_P3, "htb", "rate", "256kbit", "ceil", "1mbit", "prio", "2"])

    run(["tc", "qdisc", "add", "dev", interface, "parent", CLASS_P1, "handle", "10:", "sfq", "perturb", "10", "limit", "64"])
    run(["tc", "qdisc", "add", "dev", interface, "parent", CLASS_P2, "handle", "20:", "sfq", "perturb", "10", "limit", "32"])
    run(["tc", "qdisc", "add", "dev", interface, "parent", CLASS_P3, "handle", "30:", "sfq", "perturb", "10", "limit", "16"])

    run(["tc", "filter", "add", "dev", interface, "parent", "1:", "protocol", "ip", "prio", "1", "handle", MARK_P1, "fw", "flowid", CLASS_P1])
    run(["tc", "filter", "add", "dev", interface, "parent", "1:", "protocol", "ip", "prio", "2", "handle", MARK_P2, "fw", "flowid", CLASS_P2])
    run(["tc", "filter", "add", "dev", interface, "parent", "1:", "protocol", "ip", "prio", "3", "handle", MARK_P3, "fw", "flowid", CLASS_P3])


def parse_tc_stats(interface: str) -> Dict[str, Dict[str, float]]:
    result = {
        "1:10": {"packets": 0.0, "dropped": 0.0},
        "1:20": {"packets": 0.0, "dropped": 0.0},
        "1:30": {"packets": 0.0, "dropped": 0.0},
    }

    proc = run(["tc", "-s", "class", "show", "dev", interface], check=False)
    lines = proc.stdout.splitlines()
    current = None
    for line in lines:
        class_match = re.search(r"class htb (1:(10|20|30))", line)
        if class_match:
            current = class_match.group(1)
            continue

        if current and "Sent" in line and "pkt" in line:
            pkt_match = re.search(r"Sent\s+\d+\s+bytes\s+(\d+)\s+pkt", line)
            drop_match = re.search(r"dropped\s+(\d+)", line)
            if pkt_match:
                result[current]["packets"] = float(pkt_match.group(1))
            if drop_match:
                result[current]["dropped"] = float(drop_match.group(1))
            current = None

    return result


def avg_query(query_api, flux: str) -> float:
    try:
        tables = query_api.query(flux)
        values = [float(r.get_value()) for t in tables for r in t.records if r.get_value() is not None]
        if not values:
            return 0.0
        return sum(values) / len(values)
    except Exception:
        return 0.0


def tcp_connect_latency_ms(host: str, port: int, timeout: float = 1.5) -> float:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return elapsed
    except Exception:
        return 0.0


def probe_priority_latency() -> Tuple[float, float]:
    def median_probe(host: str, port: int, samples: int = 5) -> float:
        vals: List[float] = []
        for _ in range(samples):
            v = tcp_connect_latency_ms(host, port)
            # Ignore failed probes and extreme outliers to reduce transient jitter spikes.
            if 0 < v < 200:
                vals.append(v)
        if not vals:
            return 0.0
        return float(statistics.median(vals))

    # Use direct network probes per class so QoS latency doesn't include app processing time.
    # P1: control-path probe (Modbus control plane)
    p1 = median_probe("172.20.10.10", 502)
    # P2: monitoring-path probe (OPC-UA monitoring plane)
    p2 = median_probe("172.20.40.10", 4840)
    return p1, p2


def collect_latency_metrics(query_api) -> Tuple[float, float]:
    p1_probe, p2_probe = probe_priority_latency()
    if p1_probe > 0 or p2_probe > 0:
        return p1_probe, p2_probe

    # Last-resort fallback if probes fail completely.
    p1_modbus = avg_query(
        query_api,
        f'''from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -2m)
            |> filter(fn: (r) => r._measurement == "modbus")
            |> filter(fn: (r) => r.container == "modbus-attacker")
            |> filter(fn: (r) => r.action == "write")
            |> filter(fn: (r) => r._field == "latency")''',
    )
    p2_opcua = avg_query(
        query_api,
        f'''from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: -2m)
            |> filter(fn: (r) => r._measurement == "opcua")
            |> filter(fn: (r) => r.container == "opcua-attacker")
            |> filter(fn: (r) => r.action == "attack_recon")
            |> filter(fn: (r) => r._field == "latency")''',
    )
    return p1_modbus, p2_opcua


def push_qos_metrics(write_api, query_api, interfaces: List[str]) -> None:
    p1_latency_ms, p2_latency_ms = collect_latency_metrics(query_api)

    total = {
        "1:10": {"packets": 0.0, "dropped": 0.0},
        "1:20": {"packets": 0.0, "dropped": 0.0},
        "1:30": {"packets": 0.0, "dropped": 0.0},
    }

    for iface in interfaces:
        stats = parse_tc_stats(iface)
        for cls in total:
            total[cls]["packets"] += stats[cls]["packets"]
            total[cls]["dropped"] += stats[cls]["dropped"]

    def drop_rate(cls: str) -> float:
        sent = total[cls]["packets"]
        dropped = total[cls]["dropped"]
        denom = sent + dropped
        if denom <= 0:
            return 0.0
        return (dropped / denom) * 100.0

    p1_drop = drop_rate("1:10")
    p2_drop = drop_rate("1:20")
    p3_drop = drop_rate("1:30")
    sample_time = datetime.now(timezone.utc)

    # Export priority-level metrics for Grafana
    point = (
        Point("qos_metrics")
        .time(sample_time)
        .field("priority_1_latency_ms", round(p1_latency_ms, 2))
        .field("priority_2_latency_ms", round(p2_latency_ms, 2))
        .field("priority_1_drop_rate", round(p1_drop, 4))
        .field("priority_2_drop_rate", round(p2_drop, 4))
        .field("priority_3_drop_rate", round(p3_drop, 4))
    )
    write_api.write(bucket=INFLUXDB_BUCKET, record=point)

    # Also export per-priority rows for bar chart by tag
    per_prio = [
        ("p1_control", p1_drop),
        ("p2_monitoring", p2_drop),
        ("p3_best_effort", p3_drop),
    ]
    for priority, dr in per_prio:
        row = Point("qos_drop") \
            .tag("priority", priority) \
            .time(sample_time) \
            .field("drop_rate", round(dr, 4))
        write_api.write(bucket=INFLUXDB_BUCKET, record=row)

    print(
        f"[QOS] P1 latency={p1_latency_ms:.2f}ms, P2 latency={p2_latency_ms:.2f}ms | "
        f"Drop rates P1={p1_drop:.3f}% P2={p2_drop:.3f}% P3={p3_drop:.3f}%"
    )


def connect_influx() -> InfluxDBClient:
    for attempt in range(30):
        try:
            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
            client.ping()
            print(f"[QOS] Connected InfluxDB {INFLUXDB_URL}")
            return client
        except Exception as exc:
            print(f"[QOS] Waiting InfluxDB ({attempt + 1}/30): {exc}")
            time.sleep(5)
    raise RuntimeError("Cannot connect to InfluxDB")


def main() -> None:
    interfaces = list_data_interfaces()
    if not interfaces:
        raise RuntimeError("No data interfaces found")

    print(f"[QOS] Interfaces: {interfaces}")

    setup_iptables_marks()
    for iface in interfaces:
        setup_tc_for_interface(iface)

    print("[QOS] HTB + packet marking configured")

    client = connect_influx()
    write_api = client.write_api(write_options=SYNCHRONOUS)
    query_api = client.query_api()

    while True:
        try:
            push_qos_metrics(write_api, query_api, interfaces)
        except Exception as exc:
            print(f"[QOS][ERROR] monitor cycle: {exc}")
        time.sleep(MONITOR_INTERVAL)


if __name__ == "__main__":
    main()
