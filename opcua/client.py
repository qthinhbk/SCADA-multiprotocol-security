import asyncio
from asyncua import Client
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
        field_name = "wind_speed" if action == "read" else "setpoint"
        point = (
            Point("opcua")
            .tag("container", "opcua-client")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


# xử lý dữ liệu khi có sự kiện thay đổi
class SubHandler:
    def datachange_notification(self, node, val, data):
        print(f"Dữ liệu thay đổi tự động từ Node {node} -> giá trị mới: {val}")
        push_metric("read", val)


async def run_opcua_client():
    url = "opc.tcp://opcua-server:4840/freeopcua/server/"

    async with Client(url=url) as client:
        print("Kết nối thành công đến OPC-UA Turbine Server!")

        uri = "http://scada.hcmut.edu.vn"
        idx = await client.get_namespace_index(uri)

        wind_speed_node = await client.nodes.root.get_child(
            ["0:Objects", f"{idx}:Turbine", f"{idx}:WindSpeed"]
        )
        setpoint_node = await client.nodes.root.get_child(
            ["0:Objects", f"{idx}:Turbine", f"{idx}:Control", f"{idx}:SetPoint"]
        )

        print("Đang đăng ký nhận thông báo thay đổi...")
        handler = SubHandler()
        sub = await client.create_subscription(500, handler)
        await sub.subscribe_data_change(wind_speed_node)

        cycle = 0
        while True:
            await asyncio.sleep(10)
            cycle += 1
            new_setpoint = 1500.0 + (cycle % 10) * 100.0
            print(f"\n SCADA Master gửi lệnh SetPoint mới: {new_setpoint} kW")
            await setpoint_node.write_value(new_setpoint)
            push_metric("write", new_setpoint)


if __name__ == "__main__":
    asyncio.run(run_opcua_client())