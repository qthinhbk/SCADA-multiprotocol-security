import os
import time

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from pymodbus.client import ModbusTcpClient

INFLUX_URL = os.environ.get("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.environ.get("INFLUXDB_TOKEN", "scada-token-123")
INFLUX_ORG = os.environ.get("INFLUXDB_ORG", "scada-lab")
INFLUX_BUCKET = os.environ.get("INFLUXDB_BUCKET", "scada-metrics")

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


def connect_with_retry(target_host):
    while True:
        client = ModbusTcpClient(target_host, port=502)
        if client.connect():
            print("Ket noi thanh cong den Modbus Server!")
            return client

        print(f"[WAIT] Dang cho Modbus server tai {target_host}:502 ...")
        client.close()
        time.sleep(5)


def run_modbus_client():
    target_host = os.environ.get("TARGET_HOST", "modbus-server")
    client = connect_with_retry(target_host)

    cycle = 0
    while True:
        try:
            result = client.read_holding_registers(0, count=1, device_id=1)
            if not result.isError():
                print(f"[READ] Register 0 = {result.registers[0]}")
                push_metric("read", result.registers[0])

            state = cycle % 2
            if state == 0:
                value = 0
                label = "NORMAL"
            else:
                value = 1
                label = "WARNING"

            print(f"[WRITE] Ghi trang thai {label} ({value}) vao Register 0")
            client.write_register(0, value, device_id=1)
            push_metric("write", value)

            cycle += 1
            time.sleep(10)
        except Exception as exc:
            print(f"[WARN] Modbus client error: {exc}; reconnecting...")
            client.close()
            client = connect_with_retry(target_host)


if __name__ == "__main__":
    run_modbus_client()
