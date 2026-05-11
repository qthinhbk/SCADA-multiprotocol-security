#!/usr/bin/env python3
"""
IDS Monitor - Parse Zeek notice.log and push alerts to InfluxDB
"""
import os
import json
import re
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUX_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUX_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUX_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")

NOTICE_LOG = os.environ.get("NOTICE_LOG", "/opt/zeek/logs/notice.log")
BLACKLIST_FILE = os.environ.get("BLACKLIST_FILE", "blacklist.acl")
WHITELIST_FILE = os.environ.get("WHITELIST_FILE", "whitelist.conf")
READ_EXISTING_NOTICE_LOG = os.environ.get("READ_EXISTING_NOTICE_LOG", "false").strip().lower() in {"1", "true", "yes"}
BLOCKED_IP_RE = re.compile(r"BLOCKED IP: (\d+\.\d+\.\d+\.\d+)")

# Load whitelist IPs at startup
WHITELIST_IPS = set()

# Stats
stats = {
    "total_alerts": 0,
    "modbus_alerts": 0,
    "iec104_alerts": 0,
    "dnp3_alerts": 0,
    "opcua_alerts": 0
}

def connect_influx(retries=30, delay=5):
    """Connect to InfluxDB with startup retry."""
    for attempt in range(retries):
        try:
            client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            client.ping()
            write_api = client.write_api(write_options=SYNCHRONOUS)
            print(f"[IDS_MONITOR] Connected to InfluxDB at {INFLUX_URL}")
            return client, write_api
        except Exception as e:
            print(f"[IDS_MONITOR] Waiting for InfluxDB... ({attempt + 1}/{retries}) {e}")
            time.sleep(delay)

    print("[ERROR] InfluxDB connection failed after retries")
    return None, None

def load_whitelist():
    """Load whitelist IPs from configuration file"""
    global WHITELIST_IPS
    WHITELIST_IPS.clear()
    
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Simple IP validation
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    WHITELIST_IPS.add(line)
        
        if WHITELIST_IPS:
            print(f"[WHITELIST] Loaded {len(WHITELIST_IPS)} whitelisted IPs:")
            for ip in sorted(WHITELIST_IPS):
                print(f"  - {ip}")
        else:
            print(f"[WHITELIST] No IPs found in {WHITELIST_FILE}")
    except FileNotFoundError:
        print(f"[WHITELIST] File not found: {WHITELIST_FILE}, no whitelist protection active")
    except Exception as e:
        print(f"[WHITELIST] Error loading whitelist: {e}")

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


def is_already_blacklisted(src_ip):
    """Return True if src_ip is already present in blacklist file."""
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                match = BLOCKED_IP_RE.search(line)
                if match and match.group(1) == src_ip:
                    return True
    except FileNotFoundError:
        return False
    return False

def trigger_firewall_block(write_api, src_ip, protocol, threat_type):
    """Active Response: Automatically quarantine attacker IP"""
    
    # ===== WHITELIST PROTECTION =====
    if src_ip in WHITELIST_IPS:
        print(f"[WHITELIST-PROTECTED] IP {src_ip} is whitelisted, skipping blacklist for threat: {threat_type}")
        return
    
    critical_threats = [
        "modbus_shutdown_attack", 
        "iec104_c_sc_na_1_attack", 
        "dnp3_direct_operate_attack", 
        "dnp3_cold_restart_attack",
        "dnp3_unauthorized_write",
        "opcua_setpoint_manipulation_attack",
        "opcua_unauthorized_write",
        "opcua_flood_attack"
    ]
    
    # Rút gọn chuỗi note để check (loại bỏ phần namespace nếu có, vd: ModbusAuth::Modbus_Shutdown_Attack)
    threat_lower = threat_type.lower().split("::")[-1]
    
    # Debug logging to see what threat_type we're receiving
    print(f"[DEBUG] Checking threat: '{threat_type}' -> normalized: '{threat_lower}'")
    
    if threat_lower in critical_threats:
        if is_already_blacklisted(src_ip):
            print(f"[FIREWALL-IPS] IP {src_ip} already blacklisted, skip duplicate entry")
            return

        print(f"\n[FIREWALL-IPS] Auto-quarantined IP {src_ip} due to {threat_type}!")

        # Ghi vào file blacklist giả lập Firewall v2
        with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - BLOCKED IP: {src_ip} - PROTOCOL: {protocol.upper()} - REASON: {threat_type}\n")

        # PUSH action lên InfluxDB để Grafana vẽ chart Firewall Actions
        try:
            point = (
                Point("firewall_action")
                .tag("protocol", protocol)
                .tag("ip", src_ip)
                .field("blocked", 1)
            )
            write_api.write(bucket=INFLUX_BUCKET, record=point)
        except Exception as e:
            print(f"[ERROR] Failed to push firewall metric: {e}")

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
        if f"{protocol}_alerts" in stats:
            stats[f"{protocol}_alerts"] += 1
            
        print(f"[ALERT] {protocol.upper()}: {alert_data.get('msg', '')[:80]}")
        
        # ===== KÍCH HOẠT IDS-FIREWALL FEEDBACK LOOP =====
        note_type = alert_data.get('note', 'unknown')
        src_ip = alert_data.get('src', 'unknown')
        if note_type != 'unknown' and src_ip != 'unknown':
            trigger_firewall_block(write_api, src_ip, protocol, note_type)
            
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
    """Tail notice.log and push new alerts - handles file rotation"""
    print(f"[IDS_MONITOR] Watching {NOTICE_LOG}...")
    
    # Wait for file to exist
    while not os.path.exists(NOTICE_LOG):
        print(f"[IDS_MONITOR] Waiting for {NOTICE_LOG}...")
        time.sleep(5)
    
    last_stats_push = time.time()
    last_inode = os.stat(NOTICE_LOG).st_ino if hasattr(os.stat(NOTICE_LOG), 'st_ino') else 0
    f = open(NOTICE_LOG, "r", encoding="utf-8")
    if not READ_EXISTING_NOTICE_LOG:
        f.seek(0, os.SEEK_END)
        print("[IDS_MONITOR] Starting at end of existing notice.log; only new alerts will be processed.")
    
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
            # Check if file was rotated/recreated (Zeek restart)
            try:
                current_inode = os.stat(NOTICE_LOG).st_ino if hasattr(os.stat(NOTICE_LOG), 'st_ino') else 0
                current_size = os.path.getsize(NOTICE_LOG)
                current_pos = f.tell()
                
                if current_inode != last_inode or current_size < current_pos:
                    print(f"[IDS_MONITOR] Detected notice.log rotation, re-opening...")
                    f.close()
                    f = open(NOTICE_LOG, "r", encoding="utf-8")
                    last_inode = current_inode
                    continue
            except (OSError, FileNotFoundError):
                pass
            
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
    
    # Load whitelist configuration
    load_whitelist()
    
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
