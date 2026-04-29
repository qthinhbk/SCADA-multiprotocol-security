from influxdb_client import InfluxDBClient
client = InfluxDBClient(url='http://localhost:8086', token='scada-token-123', org='scada-lab')
tables = client.query_api().query('from(bucket:"scada-metrics") |> range(start: -30m) |> filter(fn: (r) => r._measurement == "iec104") |> filter(fn: (r) => r.container == "iec104-client")')
for table in tables:
    for record in table.records:
        print(f'{record.get_field()}: {record.get_value()} (action={record.values.get("action")})')
