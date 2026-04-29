@load base/frameworks/notice

module DNP3Attack;

export {
    redef enum Notice::Type += {
        DNP3_Unauthorized_Write,
        DNP3_Cold_Restart_Attack,
        DNP3_Direct_Operate_Attack
    };

    # Whitelist IPs allowed to write DNP3 (ot_net_vlan20)
    const allowed_masters: set[addr] = { 172.20.20.20, 172.20.20.10, 172.20.20.200 };
    
    # DNP3 function codes
    const fc_direct_operate = 5;
    const fc_cold_restart = 13;
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    # DNP3 uses port 20000
    if ( c$id$resp_p != 20000/tcp ) return;
    if ( ! is_orig ) return;
    if ( |payload| < 13 ) return;
    
    local src = c$id$orig_h;
    
    # Parse DNP3 Application Layer (simplified)
    # DNP3 header: 0x0564 (start bytes)
    if ( payload[0] == "\x05" && payload[1] == "\x64" )
    {
        # Function Code thường nằm ở byte 12 (nếu không có cấu hình phân mảnh CRC phức tạp nén lại)
        local fc = bytestring_to_count(payload[12]);

        # Định tuyến chặn IP lạ
        if ( src !in allowed_masters )
        {
            if ( fc == fc_direct_operate )
            {
                NOTICE([$note=DNP3_Direct_Operate_Attack,
                        $msg=fmt("CANH BAO CRITICAL: Phat hien lenh DNP3 Direct Operate (Yeu cau dung may bom - STOP) tu IP: %s", src),
                        $conn=c,
                        $identifier=cat(src, "dnp3_operate")]);
            }
            else if ( fc == fc_cold_restart )
            {
                NOTICE([$note=DNP3_Cold_Restart_Attack,
                        $msg=fmt("CANH BAO CRITICAL: Phat hien lenh DNP3 Cold Restart nguy hiem tu IP: %s", src),
                        $conn=c,
                        $identifier=cat(src, "dnp3_restart")]);
            }
            else
            {
                NOTICE([$note=DNP3_Unauthorized_Write,
                        $msg=fmt("DNP3 Unauthorized Access (FC: %d) from %s to %s", fc, src, c$id$resp_h),
                        $conn=c,
                        $identifier=cat(src, c$id$resp_h)]);
            }
        }
    }
}
