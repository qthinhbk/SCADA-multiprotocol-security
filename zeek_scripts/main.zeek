# Bật tính năng log dưới dạng JSON
@load policy/tuning/json-logs.zeek

# Load SCADA IDS scripts
@load ./modbus-unauth-write.zeek
@load ./iec104-attack.zeek
@load ./dnp3-attack.zeek
@load ./opcua-attack.zeek
@load ./influxdb-push.zeek