#!/usr/bin/env python3
"""
IDS Monitor - Parse Zeek notice.log and push alerts to InfluxDB
"""
import os
import json
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUX_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUX_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUX_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")

NOTICE_LOG = "/opt/zeek/logs/current/notice.log"

# Stats
stats = {
    "total_alerts": 0,
    "modbus_alerts": 0,
    "iec104_alerts": 0,
    "dnp3_alerts": 0,
    "opcua_alerts": 0
}

def connect_influx():
    """Connect to InfluxDB"""
    try:
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        write_api = client.write_api(write_options=SYNCHRONOUS)
        print(f"[IDS_MONITOR] Connected to InfluxDB at {INFLUX_URL}")
        return client, write_api
    except Exception as e:
        print(f"[ERROR] InfluxDB connection failed: {e}")
        return None, None

def parse_notice_line(line):
    """Parse a JSON notice log line"""
    try:
        data = json.loads(line)
        return data
    except:
        return None

def categorize_alert(note_type):
    """Categorize alert by protocol"""
    note_lower = note_type.lower()
    if "modbus" in note_lower:
        return "modbus"
    elif "iec104" in note_lower:
        return "iec104"
    elif "dnp3" in note_lower:
        return "dnp3"
    elif "opcua" in note_lower or "opc" in note_lower:
        return "opcua"
    return "unknown"

def push_alert(write_api, alert_data):
    """Push single alert to InfluxDB"""
    try:
        protocol = categorize_alert(alert_data.get("note", ""))
        
        point = (
            Point("ids_alert")
            .tag("protocol", protocol)
            .tag("note_type", alert_data.get("note", "unknown"))
            .tag("src_ip", alert_data.get("src", "unknown"))
            .tag("dst_ip", alert_data.get("dst", "unknown"))
            .field("count", 1)
            .field("msg", alert_data.get("msg", ""))
        )
        write_api.write(bucket=INFLUX_BUCKET, record=point)
        
        # Update stats
        stats["total_alerts"] += 1
        if protocol in stats:
            stats[f"{protocol}_alerts"] += 1
            
        print(f"[ALERT] {protocol.upper()}: {alert_data.get('msg', '')[:80]}")
        return True
    except Exception as e:
        print(f"[ERROR] Push alert failed: {e}")
        return False

def push_stats(write_api):
    """Push aggregated stats to InfluxDB"""
    try:
        point = (
            Point("ids_stats")
            .field("total_alerts", stats["total_alerts"])
            .field("modbus_alerts", stats["modbus_alerts"])
            .field("iec104_alerts", stats["iec104_alerts"])
            .field("dnp3_alerts", stats["dnp3_alerts"])
            .field("opcua_alerts", stats["opcua_alerts"])
        )
        write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"[ERROR] Push stats failed: {e}")

def tail_notice_log(write_api):
    """Tail notice.log and push new alerts"""
    print(f"[IDS_MONITOR] Watching {NOTICE_LOG}...")
    
    # Wait for file to exist
    while not os.path.exists(NOTICE_LOG):
        print(f"[IDS_MONITOR] Waiting for {NOTICE_LOG}...")
        time.sleep(5)
    
    # Start from end of file
    with open(NOTICE_LOG, 'r') as f:
        f.seek(0, 2)  # Go to end
        
        last_stats_push = time.time()
        
        while True:
            line = f.readline()
            if line:
                # Skip header lines
                if line.startswith("#") or not line.strip():
                    continue
                    
                alert = parse_notice_line(line)
                if alert:
                    push_alert(write_api, alert)
            else:
                # No new lines, push stats every 30s
                if time.time() - last_stats_push > 30:
                    push_stats(write_api)
                    print(f"[IDS_STATS] Total: {stats['total_alerts']} | "
                          f"Modbus: {stats['modbus_alerts']} | "
                          f"IEC104: {stats['iec104_alerts']} | "
                          f"DNP3: {stats['dnp3_alerts']} | "
                          f"OPCUA: {stats['opcua_alerts']}")
                    last_stats_push = time.time()
                time.sleep(1)

def main():
    print("=" * 50)
    print("  Zeek IDS Monitor - SCADA Lab")
    print("=" * 50)
    
    client, write_api = connect_influx()
    if not write_api:
        print("[ERROR] Cannot start without InfluxDB connection")
        return
    
    try:
        tail_notice_log(write_api)
    except KeyboardInterrupt:
        print("\n[IDS_MONITOR] Shutting down...")
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    main()
