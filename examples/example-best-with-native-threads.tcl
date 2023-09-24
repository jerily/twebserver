package require twebserver

set init_script {
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
            set request_dict [::twebserver::parse_conn $conn]
            set response_dict [process_request $request_dict]
            ::twebserver::return_conn $conn $response_dict
        } errmsg] } {
            puts "error: $errmsg"
        }
        ::twebserver::close_conn $conn
    }
}

set config_dict [dict create num_threads 10]
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
vwait forever
::twebserver::destroy_server $server_handle

