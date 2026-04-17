@load base/frameworks/notice

module IEC104Attack;

export {
    redef enum Notice::Type += {
        IEC104_Unauthorized_Command,
        IEC104_Flood_Attack
    };

    # Whitelist IPs allowed to send IEC104 commands
    const allowed_controllers: set[addr] = { 172.20.20.20 };
    
    # Threshold for flood detection (commands per minute)
    const flood_threshold = 50;
}

# Track command counts per source IP
global cmd_counts: table[addr] of count &default=0;
global last_reset: time = network_time();

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    # IEC 60870-5-104 uses port 2404
    if ( c$id$resp_p != 2404/tcp ) return;
    if ( ! is_orig ) return;
    
    local src = c$id$orig_h;
    
    # Reset counters every minute
    if ( network_time() - last_reset > 1min )
    {
        cmd_counts = table();
        last_reset = network_time();
    }
    
    # Increment command count
    cmd_counts[src] += 1;
    
    # Check for flood attack
    if ( cmd_counts[src] > flood_threshold )
    {
        NOTICE([$note=IEC104_Flood_Attack,
                $msg=fmt("IEC104 flood attack detected from %s - %d commands/min", src, cmd_counts[src]),
                $conn=c,
                $identifier=cat(src, "flood")]);
    }
    
    # Check for unauthorized controller
    if ( src !in allowed_controllers && |payload| > 0 )
    {
        NOTICE([$note=IEC104_Unauthorized_Command,
                $msg=fmt("Unauthorized IEC104 command from %s to %s", src, c$id$resp_h),
                $conn=c,
                $identifier=cat(src, c$id$resp_h)]);
    }
}
