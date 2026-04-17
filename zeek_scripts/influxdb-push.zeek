@load base/frameworks/notice

module InfluxPush;

export {
    # InfluxDB config
    const influx_host = "influxdb";
    const influx_port = 8086;
}

# Push alerts to InfluxDB via notice.log (will be parsed by ids_monitor.py)
hook Notice::policy(n: Notice::Info)
{
    # Log is already in JSON format, ids_monitor.py will parse and push to InfluxDB
    print fmt("[IDS_ALERT] %s | %s | %s", n$note, n$msg, n$src);
}
