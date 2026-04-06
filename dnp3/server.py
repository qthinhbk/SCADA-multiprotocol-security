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
    """Push a single metric point to InfluxDB (measurement = dnp3)."""
    try:
        pt = (
            Point("dnp3")
            .tag("container", "dnp3-server")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=pt)
    except Exception as e:
        print(f"[InfluxDB] write error: {e}")


# ── DNP3 Outstation (giả lập bằng c104) ────────────────────────────
class DNP3Outstation:
    """Giả lập DNP3 Outstation bằng thư viện c104 trên port 20000.

    Ánh xạ DNP3 data objects sang IEC-104 ASDU types:
      Binary Input  (BI)   → M_SP_NA_1  IOA 10  — Pump status
      Analog Input  (AI)   → M_ME_NC_1  IOA 20  — Tank level  (%)
      Analog Input  (AI)   → M_ME_NC_1  IOA 30  — Flow rate   (L/min)
      Binary Output (CROB) → C_SC_NA_1  IOA 100 — Pump control command
    """

    def __init__(self, ip="0.0.0.0", port=20000, ca=1):
        self.server  = c104.Server(ip=ip, port=port)
        self.station = self.server.add_station(common_address=ca)

        # ── Binary Input — Pump running status ─────────────────────
        self.pump_status = self.station.add_point(
            io_address=10, type=c104.Type.M_SP_NA_1
        )

        # ── Analog Inputs — Process values ─────────────────────────
        self.tank_level = self.station.add_point(
            io_address=20, type=c104.Type.M_ME_NC_1
        )
        self.flow_rate = self.station.add_point(
            io_address=30, type=c104.Type.M_ME_NC_1
        )

        # ── Binary Output — Pump control (CROB) ───────────────────
        self.pump_cmd = self.station.add_point(
            io_address=100, type=c104.Type.C_SC_NA_1
        )
        self.pump_cmd.on_receive(self._handle_command)

        # ── Init report ────────────────────────────────────────────
        print(f"[DNP3 Outstation] Station CA = {self.station.common_address}")
        for label, obj in {
            "Pump Status   BI   (IOA 10)":  self.pump_status,
            "Tank Level    AI   (IOA 20)":  self.tank_level,
            "Flow Rate     AI   (IOA 30)":  self.flow_rate,
            "Pump Control  CROB (IOA 100)": self.pump_cmd,
        }.items():
            print(f"  {'✅' if obj else '❌'} {label}")

    # ── Command callback (CROB) ─────────────────────────────────────
    def _handle_command(
        self,
        point: c104.Point,
        previous_info: c104.Information,
        message: c104.IncomingMessage,
    ) -> c104.ResponseState:
        new_val = point.value
        action  = "START" if new_val else "STOP"
        print(f"[DNP3] CROB received: {action} pump (IOA {point.io_address})")

        self.pump_status.value = new_val
        self.pump_status.transmit(cause=c104.Cot.SPONTANEOUS)
        push_metric("command", "pump_state", int(new_val))

        print(f"[DNP3] Pump is now {'RUNNING' if new_val else 'STOPPED'}")
        return c104.ResponseState.SUCCESS

    # ── Water-treatment process simulation ──────────────────────────
    def simulate_process(self):
        """Mô phỏng mức bể chứa và lưu lượng nước."""
        while True:
            pump_pt = self.station.get_point(io_address=10)
            pump_on = pump_pt and pump_pt.value

            if pump_on:
                level = min(100.0, 50.0 + random.uniform(-10.0, 15.0))
                flow  = 120.0 + random.uniform(-20.0, 20.0)
            else:
                level = max(0.0, 30.0 + random.uniform(-5.0, 5.0))
                flow  = 0.0

            self.tank_level.value = level
            self.flow_rate.value  = flow
            self.tank_level.transmit(cause=c104.Cot.SPONTANEOUS)
            self.flow_rate.transmit(cause=c104.Cot.SPONTANEOUS)

            push_metric("read", "tank_level", level)
            push_metric("read", "flow_rate",  flow)
            print(
                f"[DNP3] Pump {'ON ' if pump_on else 'OFF'} "
                f"| Level = {level:6.1f} % | Flow = {flow:6.1f} L/min"
            )
            time.sleep(5)

    # ── Main loop ───────────────────────────────────────────────────
    def run(self):
        print("[DNP3 Outstation] Khởi động giả lập DNP3 trên port 20000 ...")
        self.server.start()
        threading.Thread(target=self.simulate_process, daemon=True).start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[DNP3 Outstation] Shutting down.")


# ── Entry-point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    outstation = DNP3Outstation()
    outstation.run()
