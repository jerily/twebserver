package require twebserver

proc process_request {request_dict} {
    set content_type [dict get $request_dict headers content-type]
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
        set request [::twebserver::read_conn $conn]
        set response [process_request [::twebserver::parse_request $request]]
        ::twebserver::return_conn $conn $response
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

