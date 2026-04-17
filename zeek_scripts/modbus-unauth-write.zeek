@load base/protocols/modbus
@load base/frameworks/notice

module ModbusAuth;

export {
    # Định nghĩa loại cảnh báo mới
    redef enum Notice::Type += {
        Unauthorized_Modbus_Write
    };

    # Định nghĩa các IP được phép ghi (Whitelist)
    const allowed_writers: set[addr] = { 172.20.10.10 };
}

# Lắng nghe gói tin modbus được gửi đi
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    # is_orig = true nghĩa là gói tin gửi từ Client (người yêu cầu)
    if ( ! is_orig ) return;

    local fc = headers$function_code;
    
    # Kiểm tra xem Function Code có phải là lệnh GHI (5, 6, 15, 16) hay không
    if ( fc == 5 || fc == 6 || fc == 15 || fc == 16 )
    {
        # Nếu IP nguồn không nằm trong whitelist
        if ( c$id$orig_h !in allowed_writers )
        {
            # Kích hoạt cảnh báo
            NOTICE([$note=Unauthorized_Modbus_Write,
                    $msg=fmt("Phat hien hanh vi ghi Modbus trai phep (FC: %d) tu IP: %s den %s", fc, c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, fc)]);
        }
    }
}