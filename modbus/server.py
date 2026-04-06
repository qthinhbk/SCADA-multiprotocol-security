import asyncio
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusDeviceContext, ModbusServerContext
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
            Point("modbus")
            .tag("container", "modbus-server")
            .tag("action", action)
            .field("register_value", int(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


class TrackedDataBlock(ModbusSequentialDataBlock):
    def setValues(self, address, values):
        super().setValues(address, values)
        vals = values if hasattr(values, "__iter__") else [values]
        for v in vals:
            push_metric("write", v)

    def getValues(self, address, count=1):
        values = super().getValues(address, count)
        for v in values:
            push_metric("read", v)
        return values

async def run_modbus_server():
    store = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=TrackedDataBlock(0, [0] * 100),
        ir=ModbusSequentialDataBlock(0, [0] * 100)
    )
    context = ModbusServerContext(devices=store, single=True)

    print("Đang khởi động Modbus TCP Server (PLC giả lập) tại Port 502...")
    await StartAsyncTcpServer(context=context, address=("0.0.0.0", 502))

if __name__ == "__main__":
    asyncio.run(run_modbus_server())