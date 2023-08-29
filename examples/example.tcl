package require twebserver

proc process_request {request_dict} {
    return "HTTP/1.1 200 OK\n\ntest message request_dict=$request_dict\n"
}

proc process_conn {conn addr port} {
    if { [catch {
        set request [::twebserver::read_conn $conn]
        set reply [process_request [::twebserver::parse_request $request]]
        ::twebserver::write_conn $conn $reply
    } errmsg] } {
        puts "error: $errmsg"
    }
    ::twebserver::close_conn $conn
}

set config_dict [dict create]
set server_handle [::twebserver::create_server $config_dict process_conn]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
::twebserver::destroy_server $server_handle

