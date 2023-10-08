package require twebserver

set init_script {
    package require twebserver

    set router [::twebserver::create_router]
    #puts router=$router
    #$router use_middleware log_middleware
    #$router use_middleware session_middleware
    # $router add_route ?-exact|-prefix? httpMethod path procName ?list_of_middleware_procs?

    ::twebserver::add_route -prefix $router GET /asdf get_asdf_handler
    ::twebserver::add_route $router GET /qwerty/:user_id/sayhi get_qwerty_handler

    #$router add_route POST /test post_test_handler
    #$router add_route GET "/static/" get_static_content_handler
    ::twebserver::add_route $router GET "*" get_catchall_handler
    interp alias {} process_conn {} $router

    puts routes=[::twebserver::info_routes $router]

    #puts "done route definitions"

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

        #set conn [dict get $ctx conn]
        #set params [dict get $ctx params]
        set user_id [dict get $req pathParameters user_id]

        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET user_id=$user_id"
        # return 0 to return the response immediately, 1 to continue with the rest of the handlers
        return 1
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

