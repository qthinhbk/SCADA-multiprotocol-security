@load base/frameworks/notice

module OPCUAAttack;

export {
    redef enum Notice::Type += {
        OPCUA_Unauthorized_Write,
        OPCUA_Brute_Force,
        OPCUA_Flood_Attack,
        OPCUA_SetPoint_Manipulation_Attack
    };

    # Whitelist IPs allowed to write OPC-UA (ot_net_vlan40)
    const allowed_clients: set[addr] = { 172.20.40.20, 172.20.40.10, 172.20.40.200 };
    
    # Thresholds
    const flood_threshold = 100;  # requests per minute
    const auth_fail_threshold = 5;  # failed auths before alert
}

# Track request counts and auth failures
global req_counts: table[addr] of count &default=0;
global auth_fails: table[addr] of count &default=0;
global last_reset: time = network_time();

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    # OPC-UA uses port 4840
    if ( c$id$resp_p != 4840/tcp ) return;
    if ( ! is_orig ) return;
    
    local src = c$id$orig_h;
    
    # Reset counters every minute
    if ( network_time() - last_reset > 1min )
    {
        req_counts = table();
        last_reset = network_time();
    }
    
    # Increment command count safely
    if ( src !in req_counts )
        req_counts[src] = 0;
    req_counts[src] += 1;
    
    # Check for flood attack
    if ( req_counts[src] > flood_threshold )
    {
        NOTICE([$note=OPCUA_Flood_Attack,
                $msg=fmt("OPC-UA flood attack from %s - %d requests/min", src, req_counts[src]),
                $conn=c,
                $identifier=cat(src, "flood")]);
    }

    # Bắt hành vi thay đổi thông số "SetPoint" của OPC-UA
    if ( payload == /.*SetPoint.*/ )
    {
        if ( src !in allowed_clients )
        {
            NOTICE([$note=OPCUA_SetPoint_Manipulation_Attack,
                    $msg=fmt("CANH BAO CRITICAL: Phat hien hanh vi ghi vao bien SetPoint (kiem soat tai turbine) tu IP: %s", src),
                    $conn=c,
                    $identifier=cat(src, "setpoint")]);
        }
    }
    else if ( src !in allowed_clients && |payload| > 0 )
    {
        NOTICE([$note=OPCUA_Unauthorized_Write,
                $msg=fmt("Unauthorized OPC-UA access from %s", src),
                $conn=c,
                $identifier=cat(src, c$id$resp_h)]);
    }
}
