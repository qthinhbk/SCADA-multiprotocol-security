@load base/frameworks/notice

module IEC104Attack;

export {
    redef enum Notice::Type += {
        IEC104_Unauthorized_Command,
        IEC104_Flood_Attack,
        IEC104_C_SC_NA_1_Attack,      # Single Command attack
        IEC104_C_DC_NA_1_Attack,      # Double Command attack
        IEC104_C_RC_NA_1_Attack       # Regulating Step Command attack
    };

    # Whitelist IPs allowed to send IEC104 commands
    const allowed_controllers: set[addr] = { 172.20.20.20 };
    
    # Threshold for flood detection (commands per minute)
    const flood_threshold = 50;
    
    # IEC 104 ASDU Type IDs for control commands
    const C_SC_NA_1 = 45;  # Single Command
    const C_DC_NA_1 = 46;  # Double Command  
    const C_RC_NA_1 = 47;  # Regulating Step Command
    const C_SE_NA_1 = 48;  # Set Point Command, Normalized
    const C_SE_NB_1 = 49;  # Set Point Command, Scaled
    const C_SE_NC_1 = 50;  # Set Point Command, Short Floating Point
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
    
    # Parse IEC 104 APDU to detect specific control commands
    # IEC 104 I-frame: starts after APCI (6 bytes), ASDU Type ID is at byte 6
    if ( |payload| >= 10 && src !in allowed_controllers )
    {
        local type_id = bytestring_to_count(payload[6]);
        
        if ( type_id == C_SC_NA_1 )
        {
            NOTICE([$note=IEC104_C_SC_NA_1_Attack,
                    $msg=fmt("Unauthorized C_SC_NA_1 (Single Command) from %s - Type ID: %d", src, type_id),
                    $conn=c,
                    $identifier=cat(src, "C_SC_NA_1")]);
        }
        else if ( type_id == C_DC_NA_1 )
        {
            NOTICE([$note=IEC104_C_DC_NA_1_Attack,
                    $msg=fmt("Unauthorized C_DC_NA_1 (Double Command) from %s - Type ID: %d", src, type_id),
                    $conn=c,
                    $identifier=cat(src, "C_DC_NA_1")]);
        }
        else if ( type_id == C_RC_NA_1 )
        {
            NOTICE([$note=IEC104_C_RC_NA_1_Attack,
                    $msg=fmt("Unauthorized C_RC_NA_1 (Regulating Step) from %s - Type ID: %d", src, type_id),
                    $conn=c,
                    $identifier=cat(src, "C_RC_NA_1")]);
        }
    }
}
