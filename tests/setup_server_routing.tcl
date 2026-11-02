package require twebserver 2.0.0

set server_port 12345
set http_server_port 1122

set init_script {
    package require twebserver 2.0.0
    package require tpathexp 1.1.0

    set router [::tpathexp::router]
    foreach {method path handler} {
        GET  /someerror              ::get_someerror_handler
        GET  /qwerty/:user_id/sayhi  ::get_qwerty_handler
        GET  /addr                   ::get_addr_handler
        POST /example                ::post_example_handler
        POST /form-example           ::post_form_handler
    } {
        $router add $method $path \
            [list ::twebserver::invoke_handler $handler {} {}] -strict true
    }
    $router add GET /asdf \
        [list ::twebserver::invoke_handler ::get_asdf_handler {} {}] -end false
    $router add {GET POST} {/:path(.*)} \
        [list ::twebserver::invoke_handler ::catchall_handler {} {}]

    interp alias {} process_conn {} ::twebserver::process_conn $router

    proc get_someerror_handler {ctx req} {
        someerror
    }

    proc catchall_handler {ctx req} {
        dict set res statusCode 404
        dict set res headers {Content-Type text/plain}
        dict set res body "not found"
        return $res
    }

    proc post_example_handler {ctx req} {
        dict set res statusCode 200
        dict set res headers {Content-Type text/plain}
        dict set res body "test message POST headers=[dict get $req headers]"
        return $res
    }

    proc post_form_handler {ctx req} {
        #puts req=$req
        set form [::twebserver::get_form $req]
        dict set res statusCode 200
        dict set res headers {Content-Type text/plain}
        dict set res body "test message POST headers=[dict get $req headers] fields=[dict get $form fields] multiValueFields=[dict get $form multiValueFields]"
        return $res
    }

    proc get_asdf_handler {ctx req} {
        dict set res statusCode 200
        dict set res headers {Content-Type text/plain}
        dict set res body "test message GET path=[dict get $req path]"
        return $res
    }

    proc get_qwerty_handler {ctx req} {
        #puts ctx=[dict get $ctx]
        #puts req=[dict get $req]

        set addr [dict get $ctx addr]
        set user_id [dict get $req pathParameters user_id]

        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET path=[dict get $req path] pathParameters=[dict get $req pathParameters]"

        return $res
    }

    proc get_addr_handler {ctx req} {
        dict set res statusCode 200
        dict set res headers {Content-Type text/plain}
        dict set res body "addr=[dict get $ctx addr]"
        return $res
    }

}

set config_dict [dict create \
    read_timeout_millis 5000 \
    gzip on \
    gzip_types [list text/plain application/json] \
    gzip_min_length 20 \
    connect_timeout_millis 5000]

set server_handle [::twebserver::create_server $config_dict process_conn $init_script]

set dir [file dirname [info script]]
set localhost_key [file join $dir "../certs/host1/key.pem"]
set localhost_cert [file join $dir "../certs/host1/cert.pem"]
::twebserver::add_context $server_handle localhost $localhost_key $localhost_cert

# The client selects this context with TLS SNI (`-servername example.com`).
set cafile [file join $dir "../certs/ca/ca.crt"]
set cadir [file join $dir "../certs/ca"]
set example_key [file join $dir "../certs/host2/key.pem"]
set example_cert [file join $dir "../certs/host2/cert.pem"]
::twebserver::add_context -verify_client -cafile $cafile -cadir $cadir $server_handle example.com $example_key $example_cert

::twebserver::listen_server -num_threads 4 $server_handle $server_port
::twebserver::listen_server -http -num_threads 2 $server_handle $http_server_port
::twebserver::wait_signal
::twebserver::destroy_server $server_handle

