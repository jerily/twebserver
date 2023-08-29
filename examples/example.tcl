package require tws

proc process_request {request_dict} {
    return "HTTP/1.1 200 OK\n\ntest message request_dict=$request_dict\n"
}

proc process_conn {conn addr port} {
    if { [catch {
        set request [::tws::read_conn $conn]
        set reply [process_request [::tws::parse_request $request]]
        ::tws::write_conn $conn $reply
    } errmsg] } {
        puts "error: $errmsg"
    }
    ::tws::close_conn $conn
}

set config_dict [dict create]
set server_handle [::tws::create_server $config_dict process_conn]
::tws::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::tws::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::tws::listen_server $server_handle 4433
::tws::destroy_server $server_handle

