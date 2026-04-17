@load base/frameworks/notice

module DNP3Attack;

export {
    redef enum Notice::Type += {
        DNP3_Unauthorized_Write,
        DNP3_Cold_Restart_Attack
    };

    # Whitelist IPs allowed to write DNP3
    const allowed_masters: set[addr] = { 172.20.30.20 };
    
    # DNP3 function codes for write operations
    const write_functions: set[count] = { 2, 3, 4, 5, 6, 7, 8 };
    
    # Cold restart function code
    const cold_restart_fc = 13;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    # DNP3 uses port 20000
    if ( c$id$resp_p != 20000/tcp ) return;
    if ( ! is_orig ) return;
    if ( |payload| < 12 ) return;
    
    local src = c$id$orig_h;
    
    # Parse DNP3 Application Layer (simplified)
    # DNP3 header: 0x0564 (start bytes)
    if ( |payload| >= 2 && payload[0] == "\x05" && payload[1] == "\x64" )
    {
        # Check if source is unauthorized
        if ( src !in allowed_masters )
        {
            NOTICE([$note=DNP3_Unauthorized_Write,
                    $msg=fmt("Unauthorized DNP3 command from %s to %s", src, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(src, c$id$resp_h)]);
        }
    }
}
