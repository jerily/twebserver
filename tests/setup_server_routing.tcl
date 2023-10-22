package require twebserver

set server_port 12345

set init_script {
    package require twebserver

    set router [::twebserver::create_router]

    ::twebserver::add_route -strict $router GET /someerror get_someerror_handler
    ::twebserver::add_route -prefix $router GET /asdf get_asdf_handler
    ::twebserver::add_route -strict $router GET /qwerty/:user_id/sayhi get_qwerty_handler
    ::twebserver::add_route -strict $router POST /example post_example_handler
    ::twebserver::add_route $router GET "*" catchall_handler
    ::twebserver::add_route $router POST "*" catchall_handler

    interp alias {} process_conn {} $router

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
        dict set res body "test message POST [dict get $req headers]"
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

}

set config_dict [dict create \
    num_threads 10 \
    gzip on \
    gzip_types [list text/plain application/json] \
    gzip_min_length 20]
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::listen_server $server_handle $server_port
vwait forever
::twebserver::destroy_server $server_handle

