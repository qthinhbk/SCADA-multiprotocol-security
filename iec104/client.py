import c104
import time
import os
import socket
import threading
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# ── InfluxDB Configuration ──────────────────────────────────────────
INFLUX_URL    = "http://influxdb:8086"
INFLUX_TOKEN  = "scada-token-123"
INFLUX_ORG    = "scada-lab"
INFLUX_BUCKET = "scada-metrics"

_influx    = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
_write_api = _influx.write_api(write_options=SYNCHRONOUS)


def push_metric(action, field_name, value):
    """Push a single metric point to InfluxDB (measurement = iec104)."""
    try:
        pt = (
            Point("iec104")
            .tag("container", "iec104-client")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=pt)
    except Exception as e:
        print(f"[InfluxDB] write error: {e}")


# ── IEC-104 Control Center (Client / HMI) ──────────────────────────
class ControlCenter:
    """SCADA Control Center kết nối tới IED qua IEC 60870-5-104.

    Chế độ tự động (non-interactive) phù hợp chạy trong Docker:
      - Nhận spontaneous updates qua callback
      - Gửi General Interrogation (GI) định kỳ 30 s
      - Tự động luân phiên lệnh CLOSE / OPEN mỗi 15 s
    """

    def __init__(self, host="iec104-server", port=2404):
        # c104 requires IP address, not hostname
        ip = socket.gethostbyname(host)
        self.client     = c104.Client()
        self.connection = self.client.add_connection(
            ip=ip, port=port, init=c104.Init.ALL
        )
        self.station = self.connection.add_station(common_address=1)
        self.running = True

        # ── Monitoring points ───────────────────────────────────────
        self.voltage        = self.station.add_point(io_address=20,  type=c104.Type.M_ME_NC_1)
        self.current        = self.station.add_point(io_address=30,  type=c104.Type.M_ME_NC_1)
        self.breaker_status = self.station.add_point(io_address=10,  type=c104.Type.M_SP_NA_1)

        # ── Control point ───────────────────────────────────────────
        self.breaker_cmd = self.station.add_point(io_address=100, type=c104.Type.C_SC_NA_1)

        # ── Register callbacks ──────────────────────────────────────
        self.breaker_status.on_receive(self._on_point_arrival)
        self.voltage.on_receive(self._on_point_arrival)
        self.current.on_receive(self._on_point_arrival)

    # ── Incoming data callback ──────────────────────────────────────
    def _on_point_arrival(
        self,
        point: c104.Point,
        previous_info: c104.Information,
        message: c104.IncomingMessage,
    ) -> c104.ResponseState:
        if not self.connection.is_connected:
            return c104.ResponseState.FAILURE

        if point.type == c104.Type.M_SP_NA_1:
            state = "CLOSED" if point.value else "OPEN"
            print(f"[SCADA] Breaker Status: {state}  (IOA {point.io_address})")
            push_metric("read", "breaker_state", int(point.value))

        elif point.type == c104.Type.M_ME_NC_1:
            if point.io_address == 20:
                print(f"[SCADA] Voltage: {point.value:.2f} V")
                push_metric("read", "voltage", point.value)
            elif point.io_address == 30:
                print(f"[SCADA] Current: {point.value:.2f} A")
                push_metric("read", "current", point.value)

        return c104.ResponseState.SUCCESS

    # ── Periodic General Interrogation ──────────────────────────────
    def periodic_gi(self):
        while self.running:
            time.sleep(30)
            if self.connection.is_connected:
                ok = self.connection.interrogation(
                    common_address=1,
                    cause=c104.Cot.ACTIVATION,
                    qualifier=c104.Qoi.STATION,
                )
                print(f"[SCADA] General Interrogation: {'OK' if ok else 'FAILED'}")

    # ── Automated control loop ──────────────────────────────────────
    def automated_control(self):
        """Luân phiên gửi lệnh CLOSE / OPEN mỗi 15 s (cho demo & test)."""
        cycle = 0
        while self.running:
            time.sleep(15)
            if not self.connection.is_connected:
                continue

            cmd_value = (cycle % 2 == 0)        # True = CLOSE, False = OPEN
            action    = "CLOSE" if cmd_value else "OPEN"

            self.breaker_cmd.value = cmd_value
            if self.breaker_cmd.transmit(cause=c104.Cot.ACTIVATION):
                print(f"[SCADA] ➜ Sent command: {action} breaker")
                push_metric("write", "breaker_cmd", int(cmd_value))
            else:
                print(f"[SCADA] ✗ Failed to send: {action}")

            cycle += 1

    # ── Main loop ───────────────────────────────────────────────────
    def run(self):
        print("[SCADA] Khởi động IEC-104 Control Center Client ...")
        self.client.start()

        # Wait for connection with timeout
        retries = 0
        while self.connection.state != c104.ConnectionState.OPEN:
            print(f"[SCADA] Đang chờ kết nối tới {self.connection.ip}:{self.connection.port} ...")
            time.sleep(3)
            retries += 1
            if retries > 20:
                print("[SCADA] Connection timeout; retrying.")
                return

        print(f"[SCADA] ✓ Đã kết nối IED tại {self.connection.ip}:{self.connection.port}")

        threading.Thread(target=self.periodic_gi,       daemon=True).start()
        threading.Thread(target=self.automated_control,  daemon=True).start()

        try:
            while True:
                time.sleep(1)
                if not self.connection.is_connected:
                    print("[SCADA] Connection lost; reconnecting.")
                    return
        except KeyboardInterrupt:
            print("\n[SCADA] Shutting down.")
            raise
        finally:
            self.running = False
            try:
                self.client.stop()
            except Exception:
                pass


# ── Entry-point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    target_host = os.environ.get("TARGET_HOST", "iec104-server")
    while True:
        try:
            scada = ControlCenter(host=target_host)
            scada.run()
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"[SCADA] Client error: {exc}; retrying.")
        time.sleep(5)
