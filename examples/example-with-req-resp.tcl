package require twebserver

proc process_request {request_dict} {
    set headers {}
    if { [dict exists $request_dict headers content-type] } {
        set content_type [dict get $request_dict headers content-type]
        set headers [dict create Content-Type $content_type]
    }
    set is_base64_encoded [dict get $request_dict isBase64Encoded]
    set body [dict get $request_dict body]
    set response [dict create \
        statusCode 200 \
        headers $headers \
        multiValueHeaders {} \
        isBase64Encoded $is_base64_encoded \
        body $body]
    return $response
}

proc process_conn {conn addr port} {
    #puts "connection from $addr:$port on $conn"
    if { [catch {
        if {1} {
            set request_dict [::twebserver::parse_conn $conn]
            #puts request_dict=$request_dict
            set response_dict [process_request $request_dict]
            #puts response_dict=$response_dict
            ::twebserver::return_conn $conn $response_dict
        } else {
            set request [::twebserver::read_conn $conn]
            set request_dict [::twebserver::parse_request $request]
            #puts request_dict=$request_dict
            ::twebserver::write_conn $conn "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World\r\n"
            ::twebserver::close_conn $conn
            #::twebserver::return_conn $conn [dict create statusCode 200 body {hello world}]
        }

    } errmsg] } {
        puts "error: $errmsg"
    }
}

set config_dict [dict create]
set server_handle [::twebserver::create_server $config_dict process_conn]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
vwait forever
::twebserver::destroy_server $server_handle

