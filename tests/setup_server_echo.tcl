package require twebserver

set server_port 12345

proc process_request {request_dict} {
    return "HTTP/1.1 200 OK\n\ntest message request_dict=$request_dict\n"
}

proc process_conn {conn addr port} {
    #puts "process_conn $conn $addr $port"
    if { [catch {
        set request [::twebserver::read_conn $conn]
        ::twebserver::write_conn $conn $request
    } errmsg] } {
        puts "error: $errmsg"
    }
    ::twebserver::close_conn $conn
}

set dir [file dirname [info script]]
set config_dict [dict create]
set server_handle [::twebserver::create_server $config_dict process_conn]
::twebserver::add_context $server_handle localhost "${dir}/../certs/host1/key.pem" "${dir}/../certs/host1/cert.pem"
#after 100 [list puts "event loop works fine"]
::twebserver::listen_server $server_handle $server_port

vwait forever
#::twebserver::destroy_server $server_handle
