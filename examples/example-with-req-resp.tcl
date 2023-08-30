package require twebserver

proc process_request {request_dict} {
    if { [dict exists $request_dict headers content-type] } {
        set content_type [dict get $request_dict headers content-type]
    } else {
        set content_type "text/plain"
    }
    set is_base64_encoded [dict get $request_dict isBase64Encoded]
    set body [dict get $request_dict body]
    set response [dict create \
        statusCode 200 \
        headers [dict create Content-Type $content_type] \
        multiValueHeaders {} \
        isBase64Encoded $is_base64_encoded \
        body $body]
    return $response
}

proc process_conn {conn addr port} {
    if { [catch {
        set request_dict [::twebserver::parse_conn $conn]
        puts request_dict=$request_dict
        set response_dict [process_request $request_dict]
        ::twebserver::return_conn $conn $response_dict
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

