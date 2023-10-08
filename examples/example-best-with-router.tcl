package require twebserver

set init_script {
    package require twebserver

    set router [::twebserver::create_router]
    ::twebserver::add_route -prefix $router GET /asdf get_asdf_handler
    ::twebserver::add_route -strict $router GET /qwerty/:user_id/sayhi get_qwerty_handler
    ::twebserver::add_route $router GET "*" get_catchall_handler
    interp alias {} process_conn {} $router

    proc get_catchall_handler {reqVar resVar} {
        upvar $reqVar req
        upvar $resVar res

        dict set res statusCode 404
        dict set res headers {content-type text/plain}
        dict set res body "test message GET not found"
    }

    proc get_asdf_handler {reqVar resVar} {
        upvar $reqVar req
        upvar $resVar res

        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET asdf"
    }

    proc get_qwerty_handler {reqVar resVar} {
        #upvar $ctxVar ctx
        upvar $reqVar req
        upvar $resVar res

        set user_id [dict get $req pathParameters user_id]

        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET user_id=$user_id"
    }

}

set config_dict [dict create \
    num_threads 10 \
    gzip on \
    gzip_types [list text/plain application/json] \
    gzip_min_length 20]
set server_handle [::twebserver::create_server $config_dict process_conn $init_script]
::twebserver::add_context $server_handle localhost "../certs/host1/key.pem" "../certs/host1/cert.pem"
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
vwait forever
::twebserver::destroy_server $server_handle

