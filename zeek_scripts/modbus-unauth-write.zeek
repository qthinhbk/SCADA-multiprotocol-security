@load base/protocols/modbus
@load base/frameworks/notice

module ModbusAuth;

export {
    # Định nghĩa loại cảnh báo mới
    redef enum Notice::Type += {
        Unauthorized_Modbus_Write,
        Modbus_Shutdown_Attack    # Thêm cảnh báo tấn công SHUTDOWN
    };

    # Định nghĩa các IP được phép ghi (Whitelist)
    const allowed_writers: set[addr] = { 172.20.10.20 };
}

# 1. Phát hiện ghi Modbus trái phép (Từ IP lạ)
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    if ( ! is_orig ) return;

    local fc = headers$function_code;
    
    if ( fc == 5 || fc == 6 || fc == 15 || fc == 16 )
    {
        if ( c$id$orig_h !in allowed_writers )
        {
            NOTICE([$note=Unauthorized_Modbus_Write,
                    $msg=fmt("Phat hien hanh vi ghi Modbus trai phep (FC: %d) tu IP: %s den %s", fc, c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, fc)]);
        }
    }
}

# 2. Phát hiện kịch bản tấn công gửi lệnh SHUTDOWN (Giá trị 99 vào Register 0)
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count)
{
    # Log debug in ra màn hình để xem Zeek nhận được số mấy:
    print fmt("[DEBUG Modbus] Phat hien lenh ghi - Address: %d, Value: %d tu IP %s", address, value, c$id$orig_h);

    # Nếu có hành vi ghi giá trị SHUTDOWN (99) vào thanh ghi cấu hình (0)
    if ( address == 0 && value == 99 )
    {
        NOTICE([$note=Modbus_Shutdown_Attack,
                $msg=fmt("CANH BAO CRITICAL: Phat hien lenh SHUTDOWN (ghi %d vao register %d) tu IP: %s", value, address, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, address, value)]);
    }
}