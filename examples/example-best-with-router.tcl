package require twebserver

set init_script {
    package require twebserver

    namespace eval simple_session_manager {
        variable secret "keyboard cat"
        variable resave false
        variable save_uninitialized false
        variable cookie [dict create maxAge 3600000]

        proc enter {ctx req} {
            dict set req session [dict create id 1234567890]
            return $req
        }
        proc leave {ctx req res} {
            dict set res headers [list Set-Cookie "session_id=[dict get $req session id]; path=/;"]
            return $res
        }
    }

    set router [::twebserver::create_router]

    ::twebserver::add_middleware \
        -enter_proc simple_session_manager::enter \
        -leave_proc simple_session_manager::leave \
        $router

    ::twebserver::add_route -prefix $router GET /asdf get_asdf_handler
    ::twebserver::add_route -strict $router GET /qwerty/:user_id/sayhi get_qwerty_handler
    ::twebserver::add_route -strict $router POST /example post_example_handler
    ::twebserver::add_route $router GET "*" get_catchall_handler

    interp alias {} process_conn {} $router

    proc get_catchall_handler {ctx req} {
        dict set res statusCode 404
        dict set res headers {content-type text/plain}
        dict set res body "not found"
        return $res
    }

    proc post_example_handler {ctx req} {
        set form [::twebserver::get_form $req]
        puts form=$form
        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message POST [dict get $req headers] multipartBoundary=[dict get $req multipartBoundary] fields=[dict get $form fields]"
        return $res
    }

    proc get_asdf_handler {ctx req} {
        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET asdf"
        return $res
    }

    proc get_qwerty_handler {ctx req} {
        #puts ctx=[dict get $ctx]
        #puts req=[dict get $req]

        set addr [dict get $ctx addr]
        set user_id [dict get $req pathParameters user_id]

        dict set res statusCode 200
        dict set res headers {content-type text/plain}
        dict set res body "test message GET user_id=$user_id addr=$addr"

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
::twebserver::add_context $server_handle www.example.com "../certs/host2/key.pem" "../certs/host2/cert.pem"
::twebserver::listen_server $server_handle 4433
vwait forever
::twebserver::destroy_server $server_handle

