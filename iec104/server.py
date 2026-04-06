import c104
import time
import random
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
            .tag("container", "iec104-server")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=pt)
    except Exception as e:
        print(f"[InfluxDB] write error: {e}")


# ── IEC-104 Substation IED ──────────────────────────────────────────
class SubstationIED:
    """Mô phỏng IED trạm biến áp theo IEC 60870-5-104.

    Data model (ASDU types):
      M_SP_NA_1  IOA 10  — Breaker status   (single-point)
      M_ME_NC_1  IOA 20  — Voltage           (measured float)
      M_ME_NC_1  IOA 30  — Current            (measured float)
      C_SC_NA_1  IOA 100 — Breaker command    (single command)
    """

    def __init__(self, ip="0.0.0.0", port=2404, ca=1):
        self.server  = c104.Server(ip=ip, port=port)
        self.station = self.server.add_station(common_address=ca)

        # ── Monitoring points ───────────────────────────────────────
        self.breaker_status = self.station.add_point(
            io_address=10, type=c104.Type.M_SP_NA_1
        )
        self.voltage = self.station.add_point(
            io_address=20, type=c104.Type.M_ME_NC_1
        )
        self.current = self.station.add_point(
            io_address=30, type=c104.Type.M_ME_NC_1
        )

        # ── Control point ───────────────────────────────────────────
        self.breaker_cmd = self.station.add_point(
            io_address=100, type=c104.Type.C_SC_NA_1
        )
        self.breaker_cmd.on_receive(self._handle_command)

        # ── Init report ────────────────────────────────────────────
        print(f"[IED] Station CA = {self.station.common_address}")
        for label, obj in {
            "Breaker Status  (IOA 10)":  self.breaker_status,
            "Voltage          (IOA 20)": self.voltage,
            "Current          (IOA 30)": self.current,
            "Breaker Command (IOA 100)": self.breaker_cmd,
        }.items():
            print(f"  {'✅' if obj else '❌'} {label}")

    # ── Command callback ────────────────────────────────────────────
    def _handle_command(
        self,
        point: c104.Point,
        previous_info: c104.Information,
        message: c104.IncomingMessage,
    ) -> c104.ResponseState:
        new_val = point.value
        action  = "CLOSE" if new_val else "OPEN"
        print(f"[IED] Command received: {action} breaker (IOA {point.io_address})")

        # Update monitoring point and send spontaneous notification
        self.breaker_status.value = new_val
        self.breaker_status.transmit(cause=c104.Cot.SPONTANEOUS)
        push_metric("command", "breaker_state", int(new_val))

        print(f"[IED] Breaker is now {'CLOSED' if new_val else 'OPEN'}")
        return c104.ResponseState.SUCCESS

    # ── Process simulation (background thread) ──────────────────────
    def simulate_grid(self):
        """Mô phỏng điện áp / dòng điện dao động liên tục."""
        while True:
            bp = self.station.get_point(io_address=10)
            if bp and bp.value:
                voltage = 230.0 + random.uniform(-25.0, 25.0)
                current = 10.0  + random.uniform(-6.0, 6.0)

                self.voltage.value = voltage
                self.current.value = current
                self.voltage.transmit(cause=c104.Cot.SPONTANEOUS)
                self.current.transmit(cause=c104.Cot.SPONTANEOUS)

                push_metric("read", "voltage", voltage)
                push_metric("read", "current", current)
                print(f"[IED] Breaker CLOSED | V = {voltage:7.2f} V | I = {current:5.2f} A")
            else:
                print("[IED] Breaker OPEN — no valid readings")

            time.sleep(5)

    # ── Main loop ───────────────────────────────────────────────────
    def run(self):
        print("[IED] Khởi động IEC 60870-5-104 Server tại port 2404 ...")
        self.server.start()
        threading.Thread(target=self.simulate_grid, daemon=True).start()

        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[IED] Shutting down.")


# ── Entry-point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    ied = SubstationIED()
    ied.run()