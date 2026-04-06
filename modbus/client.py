import time
from pymodbus.client import ModbusTcpClient
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
            .tag("container", "modbus-client")
            .tag("action", action)
            .field("register_value", int(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


def run_modbus_client():
    client = ModbusTcpClient('modbus-server', port=502)

    if not client.connect():
        print("Kết nối thất bại.")
        return

    print("Kết nối thành công đến Modbus Server!")
    cycle = 0
    while True:
        result = client.read_holding_registers(0, count=1, device_id=1)
        if not result.isError():
            print(f"[READ] Register 0 = {result.registers[0]}")
            push_metric("read", result.registers[0])

        state = cycle % 3
        if state == 0:
            value = 0
            label = "NORMAL"
        elif state == 1:
            value = 1
            label = "WARNING"
        else:
            value = 99
            label = "SHUTDOWN"

        print(f"[WRITE] Ghi trạng thái {label} ({value}) vào Register 0")
        client.write_register(0, value, device_id=1)
        push_metric("write", value)

        cycle += 1
        time.sleep(10)

if __name__ == "__main__":
    run_modbus_client()