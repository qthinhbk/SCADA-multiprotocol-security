@load base/frameworks/notice

module OPCUAAttack;

export {
    redef enum Notice::Type += {
        OPCUA_Unauthorized_Write,
        OPCUA_Brute_Force,
        OPCUA_Flood_Attack
    };

    # Whitelist IPs allowed to write OPC-UA
    const allowed_clients: set[addr] = { 172.20.40.20 };
    
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
    
    req_counts[src] += 1;
    
    # Check for flood attack
    if ( req_counts[src] > flood_threshold )
    {
        NOTICE([$note=OPCUA_Flood_Attack,
                $msg=fmt("OPC-UA flood attack from %s - %d requests/min", src, req_counts[src]),
                $conn=c,
                $identifier=cat(src, "flood")]);
    }
    
    # Check for unauthorized client
    if ( src !in allowed_clients && |payload| > 0 )
    {
        NOTICE([$note=OPCUA_Unauthorized_Write,
                $msg=fmt("Unauthorized OPC-UA access from %s", src),
                $conn=c,
                $identifier=cat(src, c$id$resp_h)]);
    }
}
