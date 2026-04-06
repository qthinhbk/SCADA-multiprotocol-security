import c104
import time
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
    """Push a single metric point to InfluxDB (measurement = dnp3)."""
    try:
        pt = (
            Point("dnp3")
            .tag("container", "dnp3-client")
            .tag("action", action)
            .field(field_name, float(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=pt)
    except Exception as e:
        print(f"[InfluxDB] write error: {e}")


# ── DNP3 Master (giả lập bằng c104) ────────────────────────────────
class DNP3Master:
    """SCADA Master kết nối tới DNP3 Outstation (giả lập qua c104).

    Chế độ tự động (non-interactive) phù hợp Docker:
      - Nhận spontaneous updates (unsolicited responses) qua callback
      - Gửi Integrity Poll (GI) định kỳ 30 s
      - Luân phiên gửi CROB START / STOP mỗi 15 s
    """

    def __init__(self, host="dnp3-server", port=20000):
        # c104 requires IP address, not hostname
        ip = socket.gethostbyname(host)
        self.client     = c104.Client()
        self.connection = self.client.add_connection(
            ip=ip, port=port, init=c104.Init.ALL
        )
        self.station = self.connection.add_station(common_address=1)

        # ── Monitoring points ───────────────────────────────────────
        self.pump_status = self.station.add_point(
            io_address=10, type=c104.Type.M_SP_NA_1
        )
        self.tank_level = self.station.add_point(
            io_address=20, type=c104.Type.M_ME_NC_1
        )
        self.flow_rate = self.station.add_point(
            io_address=30, type=c104.Type.M_ME_NC_1
        )

        # ── Control point (CROB) ───────────────────────────────────
        self.pump_cmd = self.station.add_point(
            io_address=100, type=c104.Type.C_SC_NA_1
        )

        # ── Register callbacks ──────────────────────────────────────
        self.pump_status.on_receive(self._on_point_arrival)
        self.tank_level.on_receive(self._on_point_arrival)
        self.flow_rate.on_receive(self._on_point_arrival)

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
            state = "RUNNING" if point.value else "STOPPED"
            print(f"[MASTER] Pump Status: {state}  (IOA {point.io_address})")
            push_metric("read", "pump_state", int(point.value))

        elif point.type == c104.Type.M_ME_NC_1:
            if point.io_address == 20:
                print(f"[MASTER] Tank Level: {point.value:.1f} %")
                push_metric("read", "tank_level", point.value)
            elif point.io_address == 30:
                print(f"[MASTER] Flow Rate:  {point.value:.1f} L/min")
                push_metric("read", "flow_rate", point.value)

        return c104.ResponseState.SUCCESS

    # ── Periodic Integrity Poll (≈ DNP3 Class 0 poll) ──────────────
    def periodic_poll(self):
        while True:
            time.sleep(30)
            if self.connection.is_connected:
                ok = self.connection.interrogation(
                    common_address=1,
                    cause=c104.Cot.ACTIVATION,
                    qualifier=c104.Qoi.STATION,
                )
                print(f"[MASTER] Integrity Poll: {'OK' if ok else 'FAILED'}")

    # ── Automated control loop ──────────────────────────────────────
    def automated_control(self):
        """Luân phiên gửi CROB START / STOP mỗi 15 s."""
        cycle = 0
        while True:
            time.sleep(15)
            if not self.connection.is_connected:
                continue

            cmd_value = (cycle % 2 == 0)        # True = START, False = STOP
            action    = "START" if cmd_value else "STOP"

            self.pump_cmd.value = cmd_value
            if self.pump_cmd.transmit(cause=c104.Cot.ACTIVATION):
                print(f"[MASTER] ➜ CROB sent: {action} pump")
                push_metric("write", "pump_cmd", int(cmd_value))
            else:
                print(f"[MASTER] ✗ CROB failed: {action}")

            cycle += 1

    # ── Main loop ───────────────────────────────────────────────────
    def run(self):
        print("[MASTER] Khởi động DNP3 Master Client ...")
        self.client.start()

        retries = 0
        while self.connection.state != c104.ConnectionState.OPEN:
            print(f"[MASTER] Đang chờ kết nối tới {self.connection.ip}:{self.connection.port} ...")
            time.sleep(3)
            retries += 1
            if retries > 20:
                print("[MASTER] ✗ Connection timeout — exiting.")
                return

        print(f"[MASTER] ✓ Đã kết nối Outstation tại {self.connection.ip}:{self.connection.port}")

        threading.Thread(target=self.periodic_poll,      daemon=True).start()
        threading.Thread(target=self.automated_control,  daemon=True).start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[MASTER] Shutting down.")


# ── Entry-point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    master = DNP3Master()
    master.run()
