import time
import subprocess
import os

ZEEK_NOTICE_LOG = "/opt/zeek/logs/current/notice.log"
BLOCKED_IPS = set()

def block_ip_iptables(ip):
    if ip not in BLOCKED_IPS:
        print(f"[!] IDS Alert: Phát hiện tấn công SCADA từ IP {ip}. Đang cập nhật Firewall...")
        block_cmd = f"iptables -I DOCKER-USER -s {ip} -j DROP"
        
        try:
            subprocess.run(block_cmd, shell=True, check=True)
            BLOCKED_IPS.add(ip)
            print(f"[+] Thành công: Đã thêm rule chặn {ip} vào Firewall!")
        except subprocess.CalledProcessError as e:
            print(f"[-] Lỗi cập nhật Firewall: {e}")

def monitor_zeek_logs():
    while not os.path.exists(ZEEK_NOTICE_LOG):
        print("Đang đợi Zeek khởi động và tạo notice.log...")
        time.sleep(2)
        
    print(f"[*] Đã kết nối. Bắt đầu giám sát thời gian thực: {ZEEK_NOTICE_LOG}")
    
    with open(ZEEK_NOTICE_LOG, "r") as file:
        file.seek(0, os.SEEK_END)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            if not line.startswith("#"):
                parts = line.strip().split('\t')
                if len(parts) > 10:
                    attacker_ip = parts[2]
                    notice_type = parts[10]
                    critical_threats = [
                        "Modbus::Unauthorized_Write", 
                        "DNP3::Unauthorized_Control",
                        "SCADA::Reconnaissance"
                    ]
                    if any(threat in notice_type for threat in critical_threats):
                        block_ip_iptables(attacker_ip)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Vui lòng chạy script bằng quyền quản trị")
    else:
        monitor_zeek_logs()