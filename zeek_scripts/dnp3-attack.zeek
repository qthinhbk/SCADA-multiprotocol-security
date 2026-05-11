@load base/frameworks/notice

module DNP3Attack;

export {
    redef enum Notice::Type += {
        DNP3_Unauthorized_Write,
        DNP3_Cold_Restart_Attack,
        DNP3_Direct_Operate_Attack
    };

    # Whitelist IPs allowed to write DNP3/c104-simulated DNP3.
    const allowed_masters: set[addr] = { 172.20.20.20, 172.20.20.10, 172.20.20.200 };

    # Real DNP3 function codes.
    const fc_direct_operate = 5;
    const fc_cold_restart = 13;

    # The lab simulates DNP3 behavior with c104 frames on TCP/20000.
    const C_SC_NA_1 = 45;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    if ( c$id$resp_p != 20000/tcp ) return;
    if ( ! is_orig ) return;
    if ( |payload| < 7 ) return;

    local src = c$id$orig_h;

    # Real DNP3 wire-format path: header 0x0564 and simplified function code.
    if ( |payload| >= 13 && payload[0] == "\x05" && payload[1] == "\x64" )
    {
        local fc = bytestring_to_count(payload[12]);

        if ( src !in allowed_masters )
        {
            if ( fc == fc_direct_operate )
            {
                NOTICE([$note=DNP3_Direct_Operate_Attack,
                        $msg=fmt("CANH BAO CRITICAL: Phat hien lenh DNP3 Direct Operate tu IP: %s", src),
                        $conn=c,
                        $identifier=cat(src, "dnp3_operate")]);
            }
            else if ( fc == fc_cold_restart )
            {
                NOTICE([$note=DNP3_Cold_Restart_Attack,
                        $msg=fmt("CANH BAO CRITICAL: Phat hien lenh DNP3 Cold Restart tu IP: %s", src),
                        $conn=c,
                        $identifier=cat(src, "dnp3_restart")]);
            }
            else
            {
                NOTICE([$note=DNP3_Unauthorized_Write,
                        $msg=fmt("DNP3 Unauthorized Access FC %d from %s to %s", fc, src, c$id$resp_h),
                        $conn=c,
                        $identifier=cat(src, c$id$resp_h)]);
            }
        }
    }

    # Simulation path: IEC-104 I-frame starts with 0x68; ASDU Type ID is byte 6.
    if ( payload[0] == "\x68" && src !in allowed_masters )
    {
        local type_id = bytestring_to_count(payload[6]);

        if ( type_id == C_SC_NA_1 )
        {
            NOTICE([$note=DNP3_Direct_Operate_Attack,
                    $msg=fmt("CANH BAO CRITICAL: Phat hien lenh DNP3/c104 CROB STOP/START tu IP: %s", src),
                    $conn=c,
                    $identifier=cat(src, "dnp3_c104_operate")]);
        }
        else
        {
            NOTICE([$note=DNP3_Unauthorized_Write,
                    $msg=fmt("DNP3/c104 unauthorized traffic Type ID %d from %s to %s", type_id, src, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(src, c$id$resp_h, type_id)]);
        }
    }
}
