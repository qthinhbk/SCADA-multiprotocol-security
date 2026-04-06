import asyncio
import math
import time
from asyncua import Server, ua
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUX_URL = "http://influxdb:8086"
INFLUX_TOKEN = "scada-token-123"
INFLUX_ORG = "scada-lab"
INFLUX_BUCKET = "scada-metrics"

_influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_write_api = _influx.write_api(write_options=SYNCHRONOUS)


def push_metric(action, value):
    try:
        point = (
            Point("opcua")
            .tag("container", "opcua-server")
            .tag("action", action)
            .field("node_value", float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


async def run_opcua_server():
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
    server.set_security_policy([
        ua.SecurityPolicyType.NoSecurity,
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
    ])

    uri = "http://scada.hcmut.edu.vn"
    idx = await server.register_namespace(uri)
    objects = server.nodes.objects
    turbine_obj = await objects.add_object(idx, "Turbine")

    status_var = await turbine_obj.add_variable(idx, "Status", "Running")
    wind_speed_var = await turbine_obj.add_variable(idx, "WindSpeed", 12.5)
    power_output_var = await turbine_obj.add_variable(idx, "PowerOutput", 1500.0)

    control_obj = await turbine_obj.add_object(idx, "Control")
    setpoint_var = await control_obj.add_variable(idx, "SetPoint", 1500.0)
    await setpoint_var.set_writable()

    print("Đang khởi động OPC-UA Server tại Port 4840...")
    async with server:
        t = 0
        while True:
            new_wind = round(12.5 + 7.5 * math.sin(t * 0.1), 2)
            current_wind = await wind_speed_var.read_value()
            push_metric("read", current_wind)
            await wind_speed_var.write_value(new_wind)
            push_metric("write", new_wind)
            t += 1
            await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(run_opcua_server())